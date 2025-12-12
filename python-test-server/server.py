import argparse
import base64
import socket
import threading
import sqlite3
import hashlib
from concurrent.futures import ThreadPoolExecutor

MAX_FILE_SIZE = 10 * 1024 * 1024
FILE_HEADER_PREFIX = "FILE_TRANSFER:"
FILE_END_MARKER = "FILE_END"


def process_message(text):
    if text == "exit":
        return None
    if text == "ping":
        return "pong"
    if text == "pong":
        return "ping"
    return text


clients_lock = threading.Lock()
client_to_username = {}  # uchwyt klienta -> nazwa użytkownika
username_to_client = {}  # nazwa użytkownika -> uchwyt klienta

DB_PATH = "users.sqlite3"
db_lock = threading.Lock()
db_conn = None


def init_db(path=DB_PATH):
    global db_conn
    db_conn = sqlite3.connect(path, check_same_thread=False)
    with db_conn:
        db_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
            """
        )
        db_conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def register_user(username: str, password: str):
    if not username or " " in username:
        return False, "Niepoprawna nazwa użytkownika. Użyj bez spacji."
    if not password:
        return False, "Hasło nie może być puste."

    pw_hash = hash_password(password)
    with db_lock:
        try:
            with db_conn:
                db_conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, pw_hash),
                )
        except sqlite3.IntegrityError:
            return False, f"Nazwa '{username}' jest już zarejestrowana."
    return True, f"Zarejestrowano użytkownika '{username}'."


def verify_user(username: str, password: str) -> bool:
    pw_hash = hash_password(password)
    with db_lock:
        cur = db_conn.cursor()
        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    if not row:
        return False
    return row[0] == pw_hash


def store_message(sender: str, receiver: str, body: str):
    with db_lock:
        with db_conn:
            db_conn.execute(
                "INSERT INTO messages (sender, receiver, body) VALUES (?, ?, ?)",
                (sender, receiver, body),
            )


def get_history(user1: str, user2: str, limit: int = 50):
    with db_lock:
        cur = db_conn.cursor()
        cur.execute(
            """
            SELECT sender, receiver, body, created_at
            FROM messages
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ORDER BY id DESC
            LIMIT ?
            """,
            (user1, user2, user2, user1, limit),
        )
        rows = cur.fetchall()
    return list(reversed(rows))


def get_username_for_client(client):
    with clients_lock:
        return client_to_username.get(client)


def set_username_for_client(client, username):
    with clients_lock:
        if username in username_to_client and username_to_client[username] is not client:
            return False, f"Użytkownik '{username}' jest już zalogowany."
        old = client_to_username.get(client)
        if old and old != username:
            username_to_client.pop(old, None)
        client_to_username[client] = username
        username_to_client[username] = client
    return True, f"Zalogowano jako '{username}'."


def remove_client(client):
    with clients_lock:
        old = client_to_username.pop(client, None)
        if old:
            username_to_client.pop(old, None)


def list_usernames():
    with clients_lock:
        return sorted(username_to_client.keys())


def broadcast_message(sender_name, message, exclude_client=None, send_func=None):
    with clients_lock:
        for username, client in username_to_client.items():
            if client == exclude_client:
                continue
            try:
                text = f"[{sender_name}] {message}"
                if send_func:
                    send_func(client, text)
            except Exception:
                pass


def handle_udp_packet(server_socket, data, client_address):
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return

    print(f"[{client_address}] Otrzymane: {text}")

    if text == "exit":
        remove_client(client_address)
        print(f"[{client_address}] Zamknięcie żądane ('exit')")
        return

    if text.startswith("/register "):
        parts = text.split(" ", 2)
        if len(parts) < 3:
            msg = "Użycie: /register <użytkownik> <hasło>"
        else:
            _, username, password = parts
            username = username.strip()
            password = password.strip()
            ok, reg_msg = register_user(username, password)
            if ok:
                ok_set, set_msg = set_username_for_client(client_address, username)
                if ok_set:
                    msg = f"{reg_msg} {set_msg}"
                else:
                    msg = f"{reg_msg} {set_msg}"
            else:
                msg = reg_msg
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text.startswith("/login "):
        parts = text.split(" ", 2)
        if len(parts) < 3:
            msg = "Użycie: /login <użytkownik> <hasło>"
        else:
            _, username, password = parts
            username = username.strip()
            password = password.strip()
            if verify_user(username, password):
                ok_set, set_msg = set_username_for_client(client_address, username)
                if ok_set:
                    msg = f"Zalogowano jako '{username}'."
                else:
                    msg = set_msg
            else:
                msg = "Błędna nazwa użytkownika lub hasło."
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text == "/logout":
        remove_client(client_address)
        msg = "Wylogowano."
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text == "/whoami":
        username = get_username_for_client(client_address)
        msg = (
            f"Zalogowany jako: '{username}'"
            if username
            else "Niezalogowany. Użyj /login lub /register."
        )
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text == "/list":
        users = list_usernames()
        msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text == "/help":
        msg = """Dostępne komendy:
/register <użytkownik> <hasło> - Rejestracja nowego użytkownika
/login <użytkownik> <hasło> - Logowanie
/logout - Wylogowanie
/whoami - Pokaż swoją nazwę użytkownika
/list - Lista zalogowanych użytkowników
/msg <użytkownik> <wiadomość> - Wyślij prywatną wiadomość
/sendfile <użytkownik> <ścieżka> - Wyślij plik (tylko TCP, max 10MB)
/history <użytkownik> - Historia wiadomości z użytkownikiem
/help - Ta pomoc
(zwykła wiadomość) - Wyślij do wszystkich zalogowanych"""
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: /help")
        return

    if text.startswith("/history"):
        parts = text.split(" ", 1)
        if len(parts) < 2 or not parts[1].strip():
            msg = "Użycie: /history <użytkownik>"
        else:
            target_user = parts[1].strip()
            me = get_username_for_client(client_address)
            if not me:
                msg = "Musisz być zalogowany. Użyj /login lub /register."
            else:
                rows = get_history(me, target_user, limit=50)
                if not rows:
                    msg = f"Brak wiadomości z '{target_user}'."
                else:
                    lines = []
                    for sender, receiver, body, created_at in rows:
                        lines.append(f"{created_at} {sender} -> {receiver}: {body}")
                    msg = "Historia:\n" + "\n".join(lines)
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text.startswith("/sendfile "):
        msg = "Przesyłanie plików nie jest obsługiwane przez UDP. Użyj TCP."
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text.startswith("/msg "):
        parts = text.split(" ", 2)
        if len(parts) < 3:
            msg = "Użycie: /msg <użytkownik> <wiadomość>"
            server_socket.sendto(msg.encode("utf-8"), client_address)
            print(f"[{client_address}] Wysłano: {msg}")
            return
        _, target_user, msg_body = parts[0], parts[1].strip(), parts[2].strip()
        sender_name = get_username_for_client(client_address)
        if not sender_name:
            msg = "Musisz być zalogowany. Użyj /login lub /register."
            server_socket.sendto(msg.encode("utf-8"), client_address)
            print(f"[{client_address}] Wysłano: {msg}")
            return

        with clients_lock:
            target_client = username_to_client.get(target_user)
        if not target_client:
            msg = f"Nie znaleziono użytkownika '{target_user}'."
            server_socket.sendto(msg.encode("utf-8"), client_address)
            print(f"[{client_address}] Wysłano: {msg}")
            return

        delivered_text = f"[od {sender_name}] {msg_body}"
        server_socket.sendto(delivered_text.encode("utf-8"), target_client)
        ack = f"Wysłano do '{target_user}': {msg_body}"
        server_socket.sendto(ack.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {ack}")

        store_message(sender_name, target_user, msg_body)
        return

    sender_name = get_username_for_client(client_address)
    if sender_name:
        def udp_send(client, msg):
            server_socket.sendto(msg.encode("utf-8"), client)
        
        broadcast_message(sender_name, text, exclude_client=client_address, send_func=udp_send)
        print(f"[{client_address}] Rozgłoszono: [{sender_name}] {text}")
        return

    msg = "Musisz być zalogowany aby wysyłać wiadomości. Użyj /login lub /register."
    server_socket.sendto(msg.encode("utf-8"), client_address)
    print(f"[{client_address}] Wysłano: {msg}")


def run_udp_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    server_socket.bind(server_address)
    print(f"UDP serwer nasłuchuje na {server_address}")

    try:
        executor = ThreadPoolExecutor(max_workers=32)
        while True:
            data, client_address = server_socket.recvfrom(4096)
            executor.submit(handle_udp_packet, server_socket, data, client_address)
    except KeyboardInterrupt:
        print("Koniec programu (zamykam serwer)")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        server_socket.close()


def handle_tcp_client(conn, client_address):
    print(f"Połączono z {client_address}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[{client_address}] Klient się rozłączył")
                break

            text = data.decode("utf-8", errors="replace").strip()
            print(f"[{client_address}] Otrzymane: {text}")


            if text == "exit":
                remove_client(conn)
                print(f"[{client_address}] Zamknięcie żądane ('exit')")
                break

            if text.startswith("/register "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    msg = "Użycie: /register <użytkownik> <hasło>"
                else:
                    _, username, password = parts
                    username = username.strip()
                    password = password.strip()
                    ok, reg_msg = register_user(username, password)
                    if ok:
                        ok_set, set_msg = set_username_for_client(conn, username)
                        if ok_set:
                            msg = f"{reg_msg} {set_msg}"
                        else:
                            msg = f"{reg_msg} {set_msg}"
                    else:
                        msg = reg_msg
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {msg}")
                continue

            if text.startswith("/login "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    msg = "Użycie: /login <użytkownik> <hasło>"
                else:
                    _, username, password = parts
                    username = username.strip()
                    password = password.strip()
                    if verify_user(username, password):
                        ok_set, set_msg = set_username_for_client(conn, username)
                        if ok_set:
                            msg = f"Zalogowano jako '{username}'."
                        else:
                            msg = set_msg
                    else:
                        msg = "Błędna nazwa użytkownika lub hasło."
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {msg}")
                continue

            if text == "/logout":
                remove_client(conn)
                msg = "Wylogowano."
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {msg}")
                continue

            if text == "/whoami":
                username = get_username_for_client(conn)
                msg = (
                    f"Zalogowany jako: '{username}'"
                    if username
                    else "Niezalogowany. Użyj /login lub /register."
                )
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {msg}")
                continue

            if text == "/list":
                users = list_usernames()
                msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {msg}")
                continue

            if text == "/help":
                msg = """Dostępne komendy:
/register <użytkownik> <hasło> - Rejestracja nowego użytkownika
/login <użytkownik> <hasło> - Logowanie
/logout - Wylogowanie
/whoami - Pokaż swoją nazwę użytkownika
/list - Lista zalogowanych użytkowników
/msg <użytkownik> <wiadomość> - Wyślij prywatną wiadomość
/sendfile <użytkownik> <ścieżka> - Wyślij plik (max 10MB)
/history <użytkownik> - Historia wiadomości z użytkownikiem
/help - Ta pomoc
(zwykła wiadomość) - Wyślij do wszystkich zalogowanych"""
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: /help")
                continue

            if text.startswith("/history"):
                parts = text.split(" ", 1)
                if len(parts) < 2 or not parts[1].strip():
                    msg = "Użycie: /history <użytkownik>"
                else:
                    target_user = parts[1].strip()
                    me = get_username_for_client(conn)
                    if not me:
                        msg = "Musisz być zalogowany. Użyj /login lub /register."
                    else:
                        rows = get_history(me, target_user, limit=50)
                        if not rows:
                            msg = f"Brak wiadomości z '{target_user}'."
                        else:
                            lines = []
                            for sender, receiver, body, created_at in rows:
                                lines.append(f"{created_at} {sender} -> {receiver}: {body}")
                            msg = "Historia:\n" + "\n".join(lines)
                conn.sendall(msg.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {msg}")
                continue


            if text.startswith("/sendfile "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    msg = "Użycie: /sendfile <użytkownik> <ścieżka>"
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue
                target_user = parts[1].strip()

                sender_name = get_username_for_client(conn)
                if not sender_name:
                    msg = "Musisz być zalogowany. Użyj /login lub /register."
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue

                with clients_lock:
                    target_client = username_to_client.get(target_user)
                if not target_client:
                    msg = f"Nie znaleziono użytkownika '{target_user}'."
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue
                conn.sendall(b"FILE_READY")
                print(f"[{client_address}] Gotowy na plik dla '{target_user}'")
                continue


            if text.startswith(FILE_HEADER_PREFIX):
                try:
                    header_data = text[len(FILE_HEADER_PREFIX):]
                    parts = header_data.split("|")
                    if len(parts) < 3:
                        msg = "Błędny nagłówek pliku."
                        conn.sendall(msg.encode("utf-8"))
                        continue
                    filename = parts[0]
                    file_size = int(parts[1])
                    target_user = parts[2]
                    
                    sender_name = get_username_for_client(conn)
                    if not sender_name:
                        msg = "Musisz być zalogowany."
                        conn.sendall(msg.encode("utf-8"))
                        continue
                    
                    if file_size > MAX_FILE_SIZE:
                        msg = f"Plik za duży. Maksymalny rozmiar: {MAX_FILE_SIZE // (1024*1024)}MB"
                        conn.sendall(msg.encode("utf-8"))
                        continue
                    
                    with clients_lock:
                        target_client = username_to_client.get(target_user)
                    if not target_client:
                        msg = f"Nie znaleziono użytkownika '{target_user}'."
                        conn.sendall(msg.encode("utf-8"))
                        continue
                    
                    conn.sendall(b"FILE_DATA_READY")
                    
                    file_data = b""
                    remaining = file_size
                    while remaining > 0:
                        chunk = conn.recv(min(4096, remaining))
                        if not chunk:
                            break
                        file_data += chunk
                        remaining -= len(chunk)
                    
                    if len(file_data) != file_size:
                        msg = f"Błąd: odebrano {len(file_data)} bajtów, oczekiwano {file_size}"
                        conn.sendall(msg.encode("utf-8"))
                        continue
                    
                    encoded_data = base64.b64encode(file_data).decode("utf-8")
                    
                    file_msg = f"{FILE_HEADER_PREFIX}{filename}|{file_size}|{sender_name}\n{encoded_data}\n{FILE_END_MARKER}"
                    try:
                        target_client.sendall(file_msg.encode("utf-8"))
                        ack = f"Plik '{filename}' wysłany do '{target_user}'."
                        conn.sendall(ack.encode("utf-8"))
                        print(f"[{client_address}] Wysłano plik '{filename}' do '{target_user}' ({file_size} bajtów)")
                    except Exception as e:
                        err = f"Nie udało się wysłać pliku do '{target_user}': {e}"
                        conn.sendall(err.encode("utf-8"))
                        print(f"[{client_address}] Błąd: {err}")
                except Exception as e:
                    msg = f"Błąd przetwarzania pliku: {e}"
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Błąd: {msg}")
                continue

            if text.startswith("/msg "):
                parts = text.split(" ", 2)
                if len(parts) < 3:
                    msg = "Użycie: /msg <użytkownik> <wiadomość>"
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue
                _, target_user, msg_body = parts[0], parts[1].strip(), parts[2].strip()
                sender_name = get_username_for_client(conn)
                if not sender_name:
                    msg = "Musisz być zalogowany. Użyj /login lub /register."
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue

                with clients_lock:
                    target_client = username_to_client.get(target_user)
                if not target_client:
                    msg = f"Nie znaleziono użytkownika '{target_user}'."
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue

                delivered_text = f"[od {sender_name}] {msg_body}"
                try:
                    target_client.sendall(delivered_text.encode("utf-8"))
                except Exception as e:
                    err = f"Nie udało się wysłać do '{target_user}': {e}"
                    conn.sendall(err.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {err}")
                    continue
                ack = f"Wysłano do '{target_user}': {msg_body}"
                conn.sendall(ack.encode("utf-8"))
                print(f"[{client_address}] Wysłano: {ack}")

                store_message(sender_name, target_user, msg_body)
                continue

            sender_name = get_username_for_client(conn)
            if sender_name:
                def tcp_send(client, msg):
                    try:
                        client.sendall(msg.encode("utf-8"))
                    except Exception:
                        pass
                
                broadcast_message(sender_name, text, exclude_client=conn, send_func=tcp_send)
                print(f"[{client_address}] Rozgłoszono: [{sender_name}] {text}")
                continue

            msg = "Musisz być zalogowany aby wysyłać wiadomości. Użyj /login lub /register."
            conn.sendall(msg.encode("utf-8"))
            print(f"[{client_address}] Wysłano: {msg}")
    except Exception as e:
        print(f"[{client_address}] Błąd: {e}")
    finally:
        remove_client(conn)
        conn.close()
        print(f"[{client_address}] Rozłączono")


def run_tcp_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (host, port)
    server_socket.bind(server_address)
    server_socket.listen()
    print(f"TCP serwer nasłuchuje na {server_address}")

    try:
        while True:
            conn, client_address = server_socket.accept()
            t = threading.Thread(target=handle_tcp_client, args=(conn, client_address), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Koniec programu (zamykam serwer)")
    finally:
        server_socket.close()


def main():
    parser = argparse.ArgumentParser(description="Prosty serwer UDP/TCP: ping/pong/echo + logowanie")
    parser.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Wybierz protokół serwera")
    parser.add_argument("--host", default="localhost", help="Adres hosta (domyślnie: localhost)")
    parser.add_argument("--port", type=int, default=5678, help="Port serwera (domyślnie: 5678)")
    args = parser.parse_args()

    init_db()

    if args.proto == "udp":
        run_udp_server(args.host, args.port)
    else:
        run_tcp_server(args.host, args.port)


if __name__ == "__main__":
    main()
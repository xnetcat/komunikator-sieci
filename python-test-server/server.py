import argparse
import socket
import threading
import sqlite3
import hashlib
from concurrent.futures import ThreadPoolExecutor


def process_message(text):
    if text == "exit":
        return None
    if text == "ping":
        return "pong"
    if text == "pong":
        return "ping"
    return text  # echo


clients_lock = threading.Lock()
# Map dowolnego uchwytu klienta (addr UDP lub gniazdo TCP) -> nazwa użytkownika
client_to_username = {}
# Map nazwy użytkownika -> uchwyt klienta
username_to_client = {}

# SQLite user database
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
    # Zwróć w kolejności od najstarszej do najnowszej
    return list(reversed(rows))


def get_username_for_client(client):
    with clients_lock:
        return client_to_username.get(client)


def set_username_for_client(client, username):
    """Internal function to set username after successful login/register."""
    with clients_lock:
        if username in username_to_client and username_to_client[username] is not client:
            return False, f"Użytkownik '{username}' jest już zalogowany."
        # Remove old mapping if any
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
    """Broadcast a message to all connected users except the sender."""
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

    # Commands
    if text == "exit":
        remove_client(client_address)
        print(f"[{client_address}] Zamknięcie żądane ('exit')")
        return

    if text.startswith("/register "):
        # /register <username> <password>
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
        # /login <username> <password>
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

    if text.startswith("/msg "):
        # /msg <username> <wiadomość>
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
        # Lookup destination
        with clients_lock:
            target_client = username_to_client.get(target_user)
        if not target_client:
            msg = f"Nie znaleziono użytkownika '{target_user}'."
            server_socket.sendto(msg.encode("utf-8"), client_address)
            print(f"[{client_address}] Wysłano: {msg}")
            return
        # Deliver to target
        delivered_text = f"[od {sender_name}] {msg_body}"
        server_socket.sendto(delivered_text.encode("utf-8"), target_client)
        ack = f"Wysłano do '{target_user}': {msg_body}"
        server_socket.sendto(ack.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {ack}")
        # Store in history
        store_message(sender_name, target_user, msg_body)
        return

    # Check if user is logged in - broadcast to all users
    sender_name = get_username_for_client(client_address)
    if sender_name:
        # Broadcast message to all connected users
        def udp_send(client, msg):
            server_socket.sendto(msg.encode("utf-8"), client)
        
        broadcast_message(sender_name, text, exclude_client=client_address, send_func=udp_send)
        print(f"[{client_address}] Rozgłoszono: [{sender_name}] {text}")
        return

    # User not logged in - require login
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
            # Handle packet in thread to serve multiple clients concurrently
            executor.submit(handle_udp_packet, server_socket, data, client_address)
    except KeyboardInterrupt:
        print("Koniec programu (zamykam serwer)")
    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)  # type: ignore[arg-type]
        except Exception:
            pass
        try:
            server_socket.close()
        except Exception:
            pass


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

            # Te same komendy co dla UDP, ale na TCP
            if text == "exit":
                remove_client(conn)
                print(f"[{client_address}] Zamknięcie żądane ('exit')")
                break

            if text.startswith("/register "):
                # /register <username> <password>
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
                # /login <username> <password>
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

            if text.startswith("/msg "):
                # /msg <username> <wiadomość>
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
                # Lookup destination
                with clients_lock:
                    target_client = username_to_client.get(target_user)
                if not target_client:
                    msg = f"Nie znaleziono użytkownika '{target_user}'."
                    conn.sendall(msg.encode("utf-8"))
                    print(f"[{client_address}] Wysłano: {msg}")
                    continue
                # Deliver to target
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
                # Store in history
                store_message(sender_name, target_user, msg_body)
                continue

            # Check if user is logged in - broadcast to all users
            sender_name = get_username_for_client(conn)
            if sender_name:
                # Broadcast message to all connected users
                def tcp_send(client, msg):
                    try:
                        client.sendall(msg.encode("utf-8"))
                    except Exception:
                        pass
                
                broadcast_message(sender_name, text, exclude_client=conn, send_func=tcp_send)
                print(f"[{client_address}] Rozgłoszono: [{sender_name}] {text}")
                continue

            # User not logged in - require login
            msg = "Musisz być zalogowany aby wysyłać wiadomości. Użyj /login lub /register."
            conn.sendall(msg.encode("utf-8"))
            print(f"[{client_address}] Wysłano: {msg}")
    except Exception as e:
        print(f"[{client_address}] Błąd: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
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
        try:
            server_socket.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Prosty serwer UDP/TCP: ping/pong/echo + logowanie")
    parser.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Wybierz protokół serwera")
    parser.add_argument("--host", default="localhost", help="Adres hosta (domyślnie: localhost)")
    parser.add_argument("--port", type=int, default=5678, help="Port serwera (domyślnie: 5678)")
    args = parser.parse_args()

    # inicjalizacja bazy użytkowników (SQLite)
    init_db()

    if args.proto == "udp":
        run_udp_server(args.host, args.port)
    else:
        run_tcp_server(args.host, args.port)


if __name__ == "__main__":
    main()
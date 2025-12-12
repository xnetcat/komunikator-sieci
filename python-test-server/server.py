# =============================================================================
# SERWER KOMUNIKATORA SIECIOWEGO
# =============================================================================
# Ten serwer obsługuje dwa protokoły transportowe:
#
# UDP (User Datagram Protocol) - SOCK_DGRAM:
#   - Bezpołączeniowy: każdy pakiet (datagram) jest niezależny
#   - Identyfikacja klienta: krotka (IP, port) np. ('192.168.1.10', 54321)
#   - Wysyłanie: sendto(dane, adres) - należy podać adres docelowy
#   - Odbieranie: recvfrom() - zwraca dane + adres nadawcy
#   - Brak gwarancji dostarczenia ani kolejności
#   - NIE obsługuje przesyłania plików (zbyt zawodny)
#
# TCP (Transmission Control Protocol) - SOCK_STREAM:
#   - Połączeniowy: klient nawiązuje stałe połączenie z serwerem
#   - Identyfikacja klienta: dedykowany obiekt gniazda (socket)
#   - Wysyłanie: sendall(dane) - gwarantuje wysłanie wszystkich bajtów
#   - Odbieranie: recv() - dane mogą przychodzić w częściach (strumień)
#   - Gwarantuje dostarczenie i kolejność (retransmisje)
#   - Obsługuje przesyłanie plików
#
# WZORZEC ŻĄDANIE/ODPOWIEDŹ:
#   Klient NIE przechowuje stanu (np. listy użytkowników).
#   Aby poznać listę użytkowników, klient musi wysłać /list do serwera.
#   Serwer odpowiada aktualną listą - klient nie ma kopii lokalnej.
#
# BROADCAST (rozgłaszanie):
#   Jedyny przypadek gdy serwer AKTYWNIE wysyła dane bez żądania klienta.
#   Gdy użytkownik wysyła wiadomość, serwer iteruje po wszystkich
#   zalogowanych i wysyła do każdego (oprócz nadawcy).
# =============================================================================

import argparse
import base64
import socket
import threading
import sqlite3
import hashlib
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

# Typy dla identyfikatorów klientów
# UDP: krotka (IP, port), TCP: obiekt socket
ClientHandle = socket.socket | tuple[str, int]

# Stałe protokołu przesyłania plików (tylko TCP)
MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB - limit wielkości pliku
FILE_HEADER_PREFIX: str = "FILE_TRANSFER:"  # Prefix nagłówka: FILE_TRANSFER:nazwa|rozmiar|odbiorca
FILE_END_MARKER: str = "FILE_END"  # Znacznik końca danych pliku


def process_message(text: str) -> str | None:
    if text == "exit":
        return None
    if text == "ping":
        return "pong"
    if text == "pong":
        return "ping"
    return text


# =============================================================================
# ZARZĄDZANIE STANEM KLIENTÓW
# =============================================================================
# Te słowniki przechowują JEDYNE źródło prawdy o zalogowanych użytkownikach.
# Klient NIE ma lokalnej kopii tej listy - musi odpytać serwer komendą /list.
#
# client_to_username: uchwyt klienta -> nazwa użytkownika
#   - UDP: krotka (IP, port), np. ('127.0.0.1', 54321) -> 'jan'
#   - TCP: obiekt gniazda, np. <socket.socket ...> -> 'anna'
#
# username_to_client: nazwa użytkownika -> uchwyt klienta
#   - Odwrotne mapowanie do wyszukiwania po nazwie (np. dla /msg)
# =============================================================================
clients_lock: threading.Lock = threading.Lock()  # Blokada do synchronizacji (wiele wątków)
client_to_username: dict[ClientHandle, str] = {}  # uchwyt klienta -> nazwa użytkownika
username_to_client: dict[str, ClientHandle] = {}  # nazwa użytkownika -> uchwyt klienta

# Baza danych SQLite - przechowuje dane użytkowników i historię wiadomości
DB_PATH: str = "users.sqlite3"
db_lock: threading.Lock = threading.Lock()
db_conn: sqlite3.Connection | None = None


def init_db(path: str = DB_PATH) -> None:
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


def register_user(username: str, password: str) -> tuple[bool, str]:
    if not username or " " in username:
        return False, "Niepoprawna nazwa użytkownika. Użyj bez spacji."
    if not password:
        return False, "Hasło nie może być puste."

    pw_hash = hash_password(password)
    with db_lock:
        try:
            with db_conn:  # type: ignore
                db_conn.execute(  # type: ignore
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, pw_hash),
                )
        except sqlite3.IntegrityError:
            return False, f"Nazwa '{username}' jest już zarejestrowana."
    return True, f"Zarejestrowano użytkownika '{username}'."


def verify_user(username: str, password: str) -> bool:
    pw_hash = hash_password(password)
    with db_lock:
        cur = db_conn.cursor()  # type: ignore
        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    if not row:
        return False
    return row[0] == pw_hash


def store_message(sender: str, receiver: str, body: str) -> None:
    with db_lock:
        with db_conn:  # type: ignore
            db_conn.execute(  # type: ignore
                "INSERT INTO messages (sender, receiver, body) VALUES (?, ?, ?)",
                (sender, receiver, body),
            )


def get_history(user1: str, user2: str, limit: int = 50) -> list[tuple[str, str, str, str]]:
    with db_lock:
        cur = db_conn.cursor()  # type: ignore
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


def get_username_for_client(client: ClientHandle) -> str | None:
    with clients_lock:
        return client_to_username.get(client)


def set_username_for_client(client: ClientHandle, username: str) -> tuple[bool, str]:
    with clients_lock:
        if username in username_to_client and username_to_client[username] is not client:
            return False, f"Użytkownik '{username}' jest już zalogowany."
        old = client_to_username.get(client)
        if old and old != username:
            username_to_client.pop(old, None)
        client_to_username[client] = username
        username_to_client[username] = client
    return True, f"Zalogowano jako '{username}'."


def remove_client(client: ClientHandle) -> None:
    with clients_lock:
        old = client_to_username.pop(client, None)
        if old:
            username_to_client.pop(old, None)


def list_usernames() -> list[str]:
    with clients_lock:
        return sorted(username_to_client.keys())


# =============================================================================
# BROADCAST - ROZGŁASZANIE WIADOMOŚCI
# =============================================================================
# Jedyny przypadek gdy serwer AKTYWNIE wysyła dane do klientów bez ich żądania.
# Iteruje przez wszystkich zalogowanych użytkowników i wysyła wiadomość.
# send_func to funkcja protokołowa (inna dla UDP, inna dla TCP).
# =============================================================================
def broadcast_message(
    sender_name: str,
    message: str,
    exclude_client: ClientHandle | None = None,
    send_func: Callable[[ClientHandle, str], None] | None = None
) -> None:
    with clients_lock:
        for username, client in username_to_client.items():
            if client == exclude_client:
                continue  # Pomijamy nadawcę - nie dostaje własnej wiadomości
            try:
                text = f"[{sender_name}] {message}"
                if send_func:
                    send_func(client, text)  # Funkcja zależna od protokołu
            except Exception:
                pass  # Ignorujemy błędy wysyłania (klient mógł się rozłączyć)


# =============================================================================
# OBSŁUGA PAKIETU UDP
# =============================================================================
# Każdy pakiet UDP jest niezależny - nie ma "połączenia".
# Identyfikacja klienta: krotka (IP, port) otrzymana z recvfrom().
# Odpowiedzi wysyłane przez sendto(dane, adres_klienta).
# =============================================================================
def handle_udp_packet(
    server_socket: socket.socket,
    data: bytes,
    client_address: tuple[str, int]
) -> None:
    # Dekodowanie otrzymanych bajtów na tekst
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

    # =========================================================================
    # KOMENDA /list - LISTA UŻYTKOWNIKÓW
    # =========================================================================
    # Klient NIE przechowuje lokalnej kopii listy użytkowników.
    # Musi wysłać żądanie /list do serwera, aby poznać aktualną listę.
    # Serwer odpytuje słownik username_to_client i zwraca wynik.
    # =========================================================================
    if text == "/list":
        users = list_usernames()  # Pobiera aktualne nazwy z username_to_client
        msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
        # sendto() - wysyłanie UDP na konkretny adres klienta
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

    # =========================================================================
    # PRZESYŁANIE PLIKÓW - UDP NIE OBSŁUGUJE
    # =========================================================================
    # UDP nie gwarantuje dostarczenia ani kolejności pakietów.
    # Plik mógłby przyjść uszkodzony lub niekompletny.
    # Przesyłanie plików wymaga TCP.
    # =========================================================================
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

    # =========================================================================
    # BROADCAST - ROZGŁASZANIE WIADOMOŚCI
    # =========================================================================
    # Jeśli użytkownik jest zalogowany i wysłał zwykłą wiadomość,
    # serwer rozsyła ją do WSZYSTKICH zalogowanych (oprócz nadawcy).
    # To jedyny moment gdy serwer aktywnie wysyła bez żądania.
    # =========================================================================
    sender_name = get_username_for_client(client_address)
    if sender_name:
        # Funkcja wysyłająca przez UDP - podajemy adres docelowy
        def udp_send(client: ClientHandle, msg: str) -> None:
            if isinstance(client, tuple):
                server_socket.sendto(msg.encode("utf-8"), client)
        
        broadcast_message(sender_name, text, exclude_client=client_address, send_func=udp_send)
        print(f"[{client_address}] Rozgłoszono: [{sender_name}] {text}")
        return

    msg = "Musisz być zalogowany aby wysyłać wiadomości. Użyj /login lub /register."
    server_socket.sendto(msg.encode("utf-8"), client_address)
    print(f"[{client_address}] Wysłano: {msg}")


# =============================================================================
# SERWER UDP
# =============================================================================
# UDP (SOCK_DGRAM) - protokół bezpołączeniowy.
# recvfrom(4096) - odbiera datagram max 4KB, zwraca (dane, adres_nadawcy).
# Adres nadawcy (krotka IP, port) służy do identyfikacji klienta.
# ThreadPoolExecutor - obsługuje każdy pakiet w osobnym wątku.
# =============================================================================
def run_udp_server(host: str, port: int) -> None:
    # Tworzenie gniazda UDP (SOCK_DGRAM = datagramy)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    server_socket.bind(server_address)  # Przypisanie adresu do gniazda
    print(f"UDP serwer nasłuchuje na {server_address}")

    executor: ThreadPoolExecutor | None = None
    try:
        executor = ThreadPoolExecutor(max_workers=32)  # Pula wątków do obsługi
        while True:
            # recvfrom() - odbiera datagram i adres nadawcy
            data, client_address = server_socket.recvfrom(4096)
            # Przekazanie pakietu do puli wątków
            executor.submit(handle_udp_packet, server_socket, data, client_address)
    except KeyboardInterrupt:
        print("Koniec programu (zamykam serwer)")
    finally:
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)
        server_socket.close()


# =============================================================================
# OBSŁUGA KLIENTA TCP
# =============================================================================
# TCP (SOCK_STREAM) - protokół połączeniowy.
# Każdy klient ma dedykowane gniazdo (conn) - to jego identyfikator.
# recv(4096) - odbiera dane ze strumienia (mogą przychodzić w częściach).
# sendall() - gwarantuje wysłanie wszystkich bajtów.
# Puste dane z recv() oznaczają rozłączenie klienta.
# =============================================================================
def handle_tcp_client(conn: socket.socket, client_address: tuple[str, int]) -> None:
    print(f"Połączono z {client_address}")
    try:
        while True:
            # recv() - odbiera dane ze strumienia TCP
            # Zwraca pusty ciąg gdy klient się rozłączy
            data = conn.recv(4096)
            if not data:
                print(f"[{client_address}] Klient się rozłączył")
                break

            text: str = data.decode("utf-8", errors="replace").strip()
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

            # =================================================================
            # KOMENDA /list - LISTA UŻYTKOWNIKÓW (TCP)
            # =================================================================
            # Identyczny wzorzec jak w UDP - klient pyta, serwer odpowiada.
            # Klient nie ma lokalnej kopii listy.
            # =================================================================
            if text == "/list":
                users = list_usernames()
                msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
                # sendall() - gwarantuje wysłanie wszystkich bajtów przez TCP
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


            # =================================================================
            # PRZESYŁANIE PLIKÓW - KROK 1: Żądanie klienta
            # =================================================================
            # Klient wysyła: /sendfile <użytkownik> <ścieżka>
            # Serwer sprawdza czy odbiorca istnieje i odpowiada: FILE_READY
            # To sygnalizuje klientowi że może przesłać nagłówek pliku.
            # =================================================================
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
                # Sygnał dla klienta - można wysyłać nagłówek pliku
                conn.sendall(b"FILE_READY")
                print(f"[{client_address}] Gotowy na plik dla '{target_user}'")
                continue


            # =================================================================
            # PRZESYŁANIE PLIKÓW - KROK 2: Odbiór danych
            # =================================================================
            # Klient wysyła nagłówek: FILE_TRANSFER:nazwa|rozmiar|odbiorca
            # Serwer odpowiada: FILE_DATA_READY
            # Klient wysyła surowe dane binarne pliku
            # Serwer odbiera dane w kawałkach po 4KB (recv() może zwracać
            # mniej bajtów niż żądano - to normalne w TCP, trzeba pętlę)
            # Po odbiorze serwer koduje Base64 i przekazuje odbiorcy
            # =================================================================
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
                    
                    # Sygnał dla klienta - można wysyłać dane binarne
                    conn.sendall(b"FILE_DATA_READY")
                    
                    # Odbiór danych binarnych w kawałkach (strumień TCP)
                    # recv() może zwrócić mniej bajtów niż żądano!
                    file_data = b""
                    remaining = file_size
                    while remaining > 0:
                        chunk = conn.recv(min(4096, remaining))  # Max 4KB na raz
                        if not chunk:
                            break
                        file_data += chunk
                        remaining -= len(chunk)
                    
                    if len(file_data) != file_size:
                        msg = f"Błąd: odebrano {len(file_data)} bajtów, oczekiwano {file_size}"
                        conn.sendall(msg.encode("utf-8"))
                        continue
                    
                    # Kodowanie Base64 - bezpieczna transmisja tekstowa do odbiorcy
                    encoded_data = base64.b64encode(file_data).decode("utf-8")
                    
                    # Wysyłanie do odbiorcy w formacie tekstowym
                    file_msg = f"{FILE_HEADER_PREFIX}{filename}|{file_size}|{sender_name}\n{encoded_data}\n{FILE_END_MARKER}"
                    try:
                        # sendall() gwarantuje wysłanie wszystkich bajtów
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

            # =================================================================
            # BROADCAST TCP - ROZGŁASZANIE WIADOMOŚCI
            # =================================================================
            # Identycznie jak UDP - jeśli użytkownik jest zalogowany,
            # wiadomość trafia do wszystkich pozostałych zalogowanych.
            # =================================================================
            sender_name = get_username_for_client(conn)
            if sender_name:
                # Funkcja wysyłająca przez TCP - używa dedykowanego gniazda
                def tcp_send(client: ClientHandle, msg: str) -> None:
                    if isinstance(client, socket.socket):
                        try:
                            client.sendall(msg.encode("utf-8"))
                        except Exception:
                            pass  # Ignorujemy błędy (klient mógł się rozłączyć)
                
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


# =============================================================================
# SERWER TCP
# =============================================================================
# TCP (SOCK_STREAM) - protokół połączeniowy.
# listen() - serwer zaczyna nasłuchiwać na połączenia
# accept() - akceptuje połączenie klienta, zwraca (nowe_gniazdo, adres)
# Każdy klient otrzymuje dedykowane gniazdo - to jest jego identyfikator.
# Dla każdego klienta tworzony jest osobny wątek obsługi.
# =============================================================================
def run_tcp_server(host: str, port: int) -> None:
    # Tworzenie gniazda TCP (SOCK_STREAM = strumień)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Pozwala na ponowne użycie portu po zamknięciu serwera
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (host, port)
    server_socket.bind(server_address)
    server_socket.listen()  # Rozpoczyna nasłuchiwanie
    print(f"TCP serwer nasłuchuje na {server_address}")

    try:
        while True:
            # accept() - blokuje do momentu połączenia klienta
            # Zwraca nowe gniazdo (conn) dla komunikacji z tym klientem
            conn, client_address = server_socket.accept()
            # Każdy klient obsługiwany w osobnym wątku
            t = threading.Thread(target=handle_tcp_client, args=(conn, client_address), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Koniec programu (zamykam serwer)")
    finally:
        server_socket.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Prosty serwer UDP/TCP: ping/pong/echo + logowanie")
    _ = parser.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Wybierz protokół serwera")
    _ = parser.add_argument("--host", default="localhost", help="Adres hosta (domyślnie: localhost)")
    _ = parser.add_argument("--port", type=int, default=5678, help="Port serwera (domyślnie: 5678)")
    args = parser.parse_args()

    init_db()

    if args.proto == "udp":
        run_udp_server(args.host, args.port)
    else:
        run_tcp_server(args.host, args.port)


if __name__ == "__main__":
    main()
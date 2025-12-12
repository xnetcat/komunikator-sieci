# Dokumentacja Komunikatora Sieciowego

Szczegółowe wyjaśnienie kodu serwera i klienta z naciskiem na aspekty sieciowe.

---

## Spis Treści

1. [Architektura Sieciowa](#architektura-sieciowa)
2. [Serwer - Analiza Kodu](#serwer---analiza-kodu)
3. [Klient - Analiza Kodu](#klient---analiza-kodu)
4. [Protokół Przesyłania Plików](#protokół-przesyłania-plików)
5. [Wzorzec Żądanie/Odpowiedź](#wzorzec-żądanieodpowiedź)

---

## Architektura Sieciowa

### Różnice między UDP a TCP

| Aspekt                     | UDP (`SOCK_DGRAM`)  | TCP (`SOCK_STREAM`)           |
| -------------------------- | ------------------- | ----------------------------- |
| **Połączenie**             | Bezpołączeniowe     | Połączeniowe                  |
| **Identyfikator klienta**  | Krotka `(IP, port)` | Obiekt gniazda `conn`         |
| **Przesyłanie plików**     | ❌ Nieobsługiwane   | ✅ Obsługiwane                |
| **Wykrywanie rozłączenia** | ❌ Brak             | ✅ `recv()` zwraca pusty ciąg |
| **Gwarancja dostawy**      | ❌ Brak             | ✅ Pełna                      |
| **Kolejność pakietów**     | ❌ Brak gwarancji   | ✅ Zachowana                  |

---

## Serwer - Analiza Kodu

### Importy i Stałe (linie 1-14)

```python
import socket          # Biblioteka do obsługi gniazd sieciowych
import threading       # Wielowątkowość dla obsługi wielu klientów
import sqlite3         # Baza danych użytkowników i wiadomości
from concurrent.futures import ThreadPoolExecutor  # Pula wątków dla UDP

MAX_FILE_SIZE = 10 * 1024 * 1024
FILE_HEADER_PREFIX = "FILE_TRANSFER:"
FILE_END_MARKER = "FILE_END"
```

---

### Zarządzanie Klientami (linie 26-31)

```python
clients_lock = threading.Lock()  # Blokada do synchronizacji dostępu
client_to_username = {}  # Słownik: uchwyt klienta → nazwa użytkownika
username_to_client = {}  # Słownik: nazwa użytkownika → uchwyt klienta
```

> **WAŻNE**: Te słowniki są jedynym miejscem przechowywania listy zalogowanych użytkowników. Klient NIE przechowuje lokalnej kopii - musi odpytać serwer komendą `/list`.

---

### Baza Danych SQLite (linie 32-61)

```python
DB_PATH = "users.sqlite3"
db_lock = threading.Lock()  # Blokada do operacji na bazie

def init_db(path=DB_PATH):
    db_conn = sqlite3.connect(path, check_same_thread=False)
    # Tworzy tabelę użytkowników
    db_conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL  -- Hasło jako hash SHA-256
        )
    """)
    # Tworzy tabelę wiadomości
    db_conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
```

---

### Funkcje Pomocnicze Klientów (linie 124-152)

```python
def get_username_for_client(client):
    """Pobiera nazwę użytkownika dla danego uchwytu klienta."""
    with clients_lock:
        return client_to_username.get(client)

def set_username_for_client(client, username):
    """Ustawia powiązanie klient-użytkownik po zalogowaniu."""
    with clients_lock:
        # Sprawdza czy użytkownik nie jest już zalogowany gdzie indziej
        if username in username_to_client and username_to_client[username] is not client:
            return False, f"Użytkownik '{username}' jest już zalogowany."
        client_to_username[client] = username
        username_to_client[username] = client
    return True, f"Zalogowano jako '{username}'."

def list_usernames():
    """Zwraca posortowaną listę zalogowanych użytkowników."""
    with clients_lock:
        return sorted(username_to_client.keys())
```

> **WAŻNE**: Funkcja `list_usernames()` jest wywoływana tylko gdy klient wysyła `/list`. Serwer NIE wysyła automatycznie aktualizacji listy użytkowników.

---

### Broadcast Wiadomości (linie 155-166)

```python
def broadcast_message(sender_name, message, exclude_client=None, send_func=None):
    """Wysyła wiadomość do wszystkich zalogowanych użytkowników oprócz nadawcy."""
    with clients_lock:
        for username, client in username_to_client.items():
            if client == exclude_client:
                continue  # Pomija nadawcę
            try:
                text = f"[{sender_name}] {message}"
                if send_func:
                    send_func(client, text)
            except Exception:
                pass  # Ignoruje błędy wysyłania
```

> **WAŻNE**: To jedyny przypadek gdy serwer AKTYWNIE wysyła dane do klientów bez ich żądania.

---

### Serwer UDP (linie 346-368)

```python
def run_udp_server(host, port):
    # Tworzenie gniazda UDP (SOCK_DGRAM = datagramy)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    server_socket.bind(server_address)  # Przypisanie adresu

    print(f"UDP serwer nasłuchuje na {server_address}")

    executor = ThreadPoolExecutor(max_workers=32)  # Pula 32 wątków
    while True:
        # Odbiór datagramu (max 4096 bajtów)
        # recvfrom() zwraca dane I adres nadawcy
        data, client_address = server_socket.recvfrom(4096)

        # Przekazanie do puli wątków dla równoległej obsługi
        executor.submit(handle_udp_packet, server_socket, data, client_address)
```

**Kluczowe różnice UDP:**

- `recvfrom(4096)` - odbiera datagram z max 4KB danych
- `client_address` - krotka (IP, port) identyfikuje klienta
- Brak stałego połączenia - każdy pakiet jest niezależny

---

### Obsługa Pakietu UDP (linie 169-343)

```python
def handle_udp_packet(server_socket, data, client_address):
    text = data.decode("utf-8", errors="replace").strip()
    print(f"[{client_address}] Otrzymane: {text}")

    # Obsługa komend - każda komenda to osobny pakiet
    if text == "exit":
        remove_client(client_address)
        return

    if text == "/list":
        users = list_usernames()
        msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
        # Wysyłanie odpowiedzi przez UDP
        server_socket.sendto(msg.encode("utf-8"), client_address)
        return

    # Przesyłanie plików NIE jest obsługiwane przez UDP
    if text.startswith("/sendfile "):
        msg = "Przesyłanie plików nie jest obsługiwane przez UDP. Użyj TCP."
        server_socket.sendto(msg.encode("utf-8"), client_address)
        return
```

**Wysyłanie danych UDP:**

```python
server_socket.sendto(msg.encode("utf-8"), client_address)
```

- `sendto()` - wysyła datagram na konkretny adres
- Brak gwarancji dostarczenia
- Max ~65KB per datagram (praktycznie 4KB w tym kodzie)

---

### Serwer TCP (linie 660-679)

```python
def run_tcp_server(host, port):
    # Tworzenie gniazda TCP (SOCK_STREAM = strumień)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Pozwala na ponowne użycie portu po zamknięciu
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_address = (host, port)
    server_socket.bind(server_address)
    server_socket.listen()  # Rozpoczyna nasłuchiwanie

    print(f"TCP serwer nasłuchuje na {server_address}")

    while True:
        # accept() blokuje do momentu połączenia klienta
        # Zwraca NOWE gniazdo (conn) dla tego klienta
        conn, client_address = server_socket.accept()

        # Każdy klient obsługiwany w osobnym wątku
        t = threading.Thread(target=handle_tcp_client, args=(conn, client_address), daemon=True)
        t.start()
```

**Kluczowe różnice TCP:**

- `listen()` - serwer oczekuje na połączenia
- `accept()` - akceptuje połączenie, zwraca nowe gniazdo
- `conn` - dedykowane gniazdo dla komunikacji z tym klientem

---

### Obsługa Klienta TCP (linie 371-657)

```python
def handle_tcp_client(conn, client_address):
    print(f"Połączono z {client_address}")
    try:
        while True:  # Pętla obsługi klienta
            # recv() odbiera dane ze strumienia
            # Zwraca pusty ciąg gdy klient się rozłącza
            data = conn.recv(4096)
            if not data:
                print(f"[{client_address}] Klient się rozłączył")
                break

            text = data.decode("utf-8", errors="replace").strip()

            # Obsługa komend...
            if text == "/list":
                users = list_usernames()
                msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
                # sendall() gwarantuje wysłanie wszystkich danych
                conn.sendall(msg.encode("utf-8"))
                continue
```

**Wysyłanie danych TCP:**

```python
conn.sendall(msg.encode("utf-8"))
```

- `sendall()` - gwarantuje wysłanie wszystkich bajtów
- Strumień - dane mogą być odbierane w fragmentach
- Niezawodne - TCP retransmituje utracone pakiety

---

### Przesyłanie Plików TCP (linie 524-591)

```python
# Krok 1: Odbiór nagłówka pliku
if text.startswith(FILE_HEADER_PREFIX):
    header_data = text[len(FILE_HEADER_PREFIX):]  # "filename|size|target"
    parts = header_data.split("|")
    filename = parts[0]
    file_size = int(parts[1])
    target_user = parts[2]

    # Sprawdzenie limitu rozmiaru
    if file_size > MAX_FILE_SIZE:
        msg = f"Plik za duży. Maksymalny rozmiar: {MAX_FILE_SIZE // (1024*1024)}MB"
        conn.sendall(msg.encode("utf-8"))
        continue

    # Sygnał gotowości na dane
    conn.sendall(b"FILE_DATA_READY")

    # Krok 2: Odbiór danych binarnych pliku
    file_data = b""
    remaining = file_size
    while remaining > 0:
        chunk = conn.recv(min(4096, remaining))  # Odbiera w kawałkach 4KB
        if not chunk:
            break
        file_data += chunk
        remaining -= len(chunk)

    # Krok 3: Kodowanie Base64 dla bezpiecznej transmisji tekstowej
    encoded_data = base64.b64encode(file_data).decode("utf-8")

    # Krok 4: Wysłanie do odbiorcy
    file_msg = f"{FILE_HEADER_PREFIX}{filename}|{file_size}|{sender_name}\n{encoded_data}\n{FILE_END_MARKER}"
    target_client.sendall(file_msg.encode("utf-8"))
```

---

## Klient - Analiza Kodu

### Stałe i Konfiguracja (linie 1-16)

```python
import socket
import threading
import queue
import readline  # Edycja linii w terminalu

PROMPT = "> "
MAX_FILE_SIZE = 10 * 1024 * 1024  # Musi odpowiadać serwerowi
FILE_HEADER_PREFIX = "FILE_TRANSFER:"
FILE_END_MARKER = "FILE_END"
DOWNLOADS_DIR = "downloads"  # Katalog na pobrane pliki
```

---

### Klient UDP (linie 42-107)

```python
def run_udp_client(host, port):
    # Tworzenie gniazda UDP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    stop_event = threading.Event()  # Sygnał zatrzymania wątków
    msg_queue = queue.Queue()  # Kolejka wiadomości przychodzących

    # Wątek odbierający wiadomości od serwera
    def receiver():
        while not stop_event.is_set():
            try:
                data, _ = client_socket.recvfrom(4096)
            except OSError:
                break
            text = data.decode("utf-8", errors="replace")
            msg_queue.put(text)  # Dodaje do kolejki do wyświetlenia

    # Wątek drukujący wiadomości
    def printer():
        while not stop_event.is_set():
            try:
                text = msg_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            # Czyści linię i drukuje wiadomość
            sys.stdout.write("\r\033[K")
            sys.stdout.write(f"Odebrano: {text}\n")
            sys.stdout.write(PROMPT + readline.get_line_buffer())
            sys.stdout.flush()
```

**Wysyłanie danych UDP (klient):**

```python
client_socket.sendto(message.encode("utf-8"), server_address)
```

> **WAŻNE**: Klient UDP NIE przechowuje żadnego stanu. Każde żądanie (`/list`, `/whoami`) wymaga odpytania serwera.

---

### Klient TCP (linie 110-322)

```python
def run_tcp_client(host, port):
    # Tworzenie gniazda TCP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    client_socket.connect(server_address)  # Nawiązuje połączenie

    # Stan oczekującego transferu pliku
    pending_file_transfer = {"active": False, "target": None, "path": None}
    pending_file_lock = threading.Lock()
```

**Kluczowa różnica:** `connect()` nawiązuje trwałe połączenie z serwerem.

---

### Wątek Odbiorczy TCP (linie 121-177)

```python
def receiver():
    buffer = ""
    while not stop_event.is_set():
        data = client_socket.recv(8192)  # Większy bufor niż UDP
        if not data:
            msg_queue.put(("disconnect", None))
            stop_event.set()
            break
        text = data.decode("utf-8", errors="replace")
        buffer += text  # Buforowanie - TCP to strumień

        # Sprawdzenie sygnałów protokołu plików
        if buffer == "FILE_READY":
            msg_queue.put(("file_ready", None))
            buffer = ""
            continue

        if buffer == "FILE_DATA_READY":
            msg_queue.put(("file_data_ready", None))
            buffer = ""
            continue

        # Sprawdzenie przychodzącego pliku
        if buffer.startswith(FILE_HEADER_PREFIX) and FILE_END_MARKER in buffer:
            # Parsowanie i zapisanie pliku...
            pass
```

> **WAŻNE**: TCP wymaga buforowania ponieważ dane przychodzą strumieniem - jedna wiadomość może być podzielona na wiele wywołań `recv()` lub wiele wiadomości może przyjść w jednym.

---

### Obsługa Przesyłania Pliku (linie 196-222, 276-303)

```python
# Po otrzymaniu FILE_READY od serwera:
if msg_type == "file_ready":
    with pending_file_lock:
        if pending_file_transfer["active"]:
            filepath = pending_file_transfer["path"]
            target = pending_file_transfer["target"]
            filename = os.path.basename(filepath)

            with open(filepath, "rb") as f:
                file_data = f.read()

            file_size = len(file_data)

            # Wysłanie nagłówka
            header = f"{FILE_HEADER_PREFIX}{filename}|{file_size}|{target}"
            client_socket.sendall(header.encode("utf-8"))

# Po otrzymaniu FILE_DATA_READY od serwera:
if msg_type == "file_data_ready":
    with open(filepath, "rb") as f:
        file_data = f.read()
    # Wysłanie surowych danych binarnych
    client_socket.sendall(file_data)
```

---

### Odbieranie Plików (linie 234-250)

```python
if msg_type == "file_incoming":
    filename, file_size, sender, file_data = data
    save_path = os.path.join(DOWNLOADS_DIR, filename)

    # Obsługa duplikatów nazw
    counter = 1
    base, ext = os.path.splitext(filename)
    while os.path.exists(save_path):
        save_path = os.path.join(DOWNLOADS_DIR, f"{base}_{counter}{ext}")
        counter += 1

    with open(save_path, "wb") as f:
        f.write(file_data)
    print(f"📁 Otrzymano plik od '{sender}': {os.path.basename(save_path)}")
```

---

## Protokół Przesyłania Plików

### Diagram Sekwencji

```
Klient A                    Serwer                    Klient B
   |                          |                          |
   |-- /sendfile bob plik.txt |                          |
   |                          |                          |
   |<---- FILE_READY ---------|                          |
   |                          |                          |
   |-- FILE_TRANSFER:         |                          |
   |   plik.txt|1024|bob ---->|                          |
   |                          |                          |
   |<---- FILE_DATA_READY ----|                          |
   |                          |                          |
   |-- [dane binarne 1024B]-->|                          |
   |                          |                          |
   |                          |-- FILE_TRANSFER:         |
   |                          |   plik.txt|1024|alice    |
   |                          |   [base64 dane]          |
   |                          |   FILE_END ------------->|
   |                          |                          |
   |<-- "Plik wysłany" -------|                          |
```

---

## Wzorzec Żądanie/Odpowiedź

### Klient NIE przechowuje stanu

| Informacja          | Gdzie przechowywana           | Kiedy aktualizowana      | Jak klient poznaje     |
| ------------------- | ----------------------------- | ------------------------ | ---------------------- |
| Lista użytkowników  | Serwer (`username_to_client`) | Login/Logout/Rozłączenie | Tylko przez `/list`    |
| Własna nazwa        | Serwer (`client_to_username`) | Login/Register           | Tylko przez `/whoami`  |
| Historia wiadomości | Serwer (SQLite)               | Przy `/msg`              | Tylko przez `/history` |

### Co serwer wysyła automatycznie

1. **Broadcast** - wiadomości od innych użytkowników
2. **Wiadomości prywatne** - `/msg` od innych
3. **Przychodzące pliki** - TCP only

### Co wymaga żądania klienta

- `/list` - lista użytkowników
- `/whoami` - własna nazwa
- `/history <user>` - historia wiadomości
- Wszystkie inne komendy

---

## Porównanie Metod Wysyłania

### UDP

```python
# Wysyłanie (brak gwarancji dostawy)
server_socket.sendto(msg.encode("utf-8"), client_address)

# Odbieranie (zwraca dane + adres nadawcy)
data, client_address = server_socket.recvfrom(4096)
```

### TCP

```python
# Wysyłanie (gwarantuje wysłanie wszystkich bajtów)
conn.sendall(msg.encode("utf-8"))

# Odbieranie (zwraca tylko dane, może być częściowe)
data = conn.recv(4096)
if not data:  # Puste = rozłączenie
    break
```

---

## Podsumowanie

| Cecha           | UDP                 | TCP                      |
| --------------- | ------------------- | ------------------------ |
| **Gniazdo**     | `SOCK_DGRAM`        | `SOCK_STREAM`            |
| **Wysyłanie**   | `sendto()`          | `sendall()`              |
| **Odbieranie**  | `recvfrom()`        | `recv()`                 |
| **ID klienta**  | `(IP, port)` krotka | obiekt gniazda           |
| **Pliki**       | ❌ Brak             | ✅ Protokół wieloetapowy |
| **Rozłączenie** | Niewidoczne         | `recv()` → pusty ciąg    |
| **Stan**        | Bezstanowe          | Połączeniowe             |

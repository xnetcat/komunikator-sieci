# =============================================================================
# KLIENT KOMUNIKATORA SIECIOWEGO
# =============================================================================
# Ten klient obsługuje dwa protokoły transportowe:
#
# UDP (User Datagram Protocol) - SOCK_DGRAM:
#   - Bezpołączeniowy: każdy pakiet (datagram) jest niezależny
#   - Wysyłanie: sendto(dane, adres_serwera)
#   - Odbieranie: recvfrom(4096) - max 4KB per datagram
#   - Brak gwarancji dostarczenia ani kolejności
#   - NIE obsługuje przesyłania plików
#
# TCP (Transmission Control Protocol) - SOCK_STREAM:
#   - Połączeniowy: connect() nawiązuje stałe połączenie
#   - Wysyłanie: sendall(dane) - gwarantuje wysłanie wszystkich bajtów
#   - Odbieranie: recv() - dane mogą przychodzić w częściach (strumień)
#   - Gwarantuje dostarczenie i kolejność
#   - Obsługuje przesyłanie plików
#
# WZORZEC ŻĄDANIE/ODPOWIEDŹ:
#   Klient NIE przechowuje lokalnego stanu (np. listy użytkowników).
#   Aby poznać listę użytkowników, klient wysyła /list do serwera.
#   Serwer odpowiada aktualną listą - klient nie ma kopii lokalnej.
#   Podobnie dla /whoami, /history itp.
#
# BROADCAST (rozgłaszanie):
#   Serwer może wysłać wiadomości bez żądania klienta (np. od innych użytkowników).
#   Wątek odbiorczy (receiver) nasłuchuje i przekazuje do kolejki.
# =============================================================================

import argparse
import base64
import os
import queue
import readline  # włącza edycję linii w input()
import socket
import sys
import threading

PROMPT = "> "

# Stałe protokołu przesyłania plików (muszą być zgodne z serwerem)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB - limit wielkości pliku
FILE_HEADER_PREFIX = "FILE_TRANSFER:"  # Prefix nagłówka pliku
FILE_END_MARKER = "FILE_END"  # Znacznik końca danych pliku
DOWNLOADS_DIR = "downloads"  # Katalog na pobrane pliki

WELCOME_MESSAGE = """
╔════════════════════════════════════════════════════════════╗
║                    KOMUNIKATOR SIECI                       ║
╠════════════════════════════════════════════════════════════╣
║  Dostępne komendy:                                         ║
║                                                            ║
║  /register <użytkownik> <hasło>  - Rejestracja             ║
║  /login <użytkownik> <hasło>     - Logowanie               ║
║  /logout                         - Wylogowanie             ║
║  /whoami                         - Pokaż swoją nazwę       ║
║  /list                           - Lista użytkowników      ║
║  /msg <użytkownik> <wiadomość>   - Prywatna wiadomość      ║
║  /sendfile <użytkownik> <ścieżka> - Wyślij plik (TCP, 10MB) ║
║  /history <użytkownik>           - Historia wiadomości     ║
║  /help                           - Pokaż pomoc             ║
║  exit                            - Zakończ program         ║
║                                                            ║
║  (zwykła wiadomość)              - Wyślij do wszystkich    ║
║                                                            ║
║  Zaloguj się aby korzystać z czatu!                        ║
╚════════════════════════════════════════════════════════════╝
"""


# =============================================================================
# KLIENT UDP
# =============================================================================
# UDP (SOCK_DGRAM) - protokół bezpołączeniowy.
# sendto(dane, adres) - wysyła datagram na konkretny adres
# recvfrom(4096) - odbiera datagram (max 4KB), zwraca (dane, adres)
# Klient NIE przechowuje żadnego stanu - każde żądanie trafia do serwera.
# =============================================================================
def run_udp_client(host, port):
    # Tworzenie gniazda UDP (SOCK_DGRAM = datagramy)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    stop_event = threading.Event()  # Sygnał zatrzymania wątków
    msg_queue = queue.Queue()  # Kolejka wiadomości do wyświetlenia

    # =========================================================================
    # Wątek odbiorczy - nasłuchuje odpowiedzi od serwera
    # =========================================================================
    # Serwer może wysłać dane w dowolnym momencie (np. broadcast od innych
    # użytkowników). Wątek ciągle odbiera i dodaje do kolejki.
    # =========================================================================
    def receiver():
        while not stop_event.is_set():
            try:
                # recvfrom() - odbiera datagram + adres nadawcy
                data, _ = client_socket.recvfrom(4096)
            except OSError:
                break
            except Exception:
                continue
            text = data.decode("utf-8", errors="replace")
            msg_queue.put(text)  # Dodaje do kolejki do wyświetlenia

    def printer():
        while not stop_event.is_set():
            try:
                text = msg_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            sys.stdout.write("\r\033[K")
            sys.stdout.write(f"Odebrano: {text}\n")
            sys.stdout.write(PROMPT + readline.get_line_buffer())
            sys.stdout.flush()

    recv_thread = threading.Thread(target=receiver, daemon=True)
    print_thread = threading.Thread(target=printer, daemon=True)
    recv_thread.start()
    print_thread.start()

    print(WELCOME_MESSAGE)

    try:
        while True:
            try:
                message = input(PROMPT)
                if not message.strip():
                    continue
                if message == "exit":
                    # sendto() - wysyła datagram na podany adres
                    client_socket.sendto(b"exit", server_address)
                    print("Koniec połączenia")
                    stop_event.set()
                    break
                # Wysyłanie komendy/wiadomości do serwera
                client_socket.sendto(message.encode("utf-8"), server_address)
            except KeyboardInterrupt:
                print("\nKoniec programu")
                stop_event.set()
                break
            except Exception as e:
                print(f"Błąd: {e}")
                stop_event.set()
                break
    finally:
        client_socket.close()


# =============================================================================
# KLIENT TCP
# =============================================================================
# TCP (SOCK_STREAM) - protokół połączeniowy.
# connect() nawiązuje stałe połączenie z serwerem.
# sendall() gwarantuje wysłanie wszystkich bajtów.
# recv() odbiera dane strumieniem (mogą przychodzić w częściach).
# Puste dane z recv() oznaczają rozłączenie serwera.
# =============================================================================
def run_tcp_client(host, port):
    # Tworzenie gniazda TCP (SOCK_STREAM = strumień)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    # connect() - nawiązuje połączenie (TCP handshake)
    client_socket.connect(server_address)
    stop_event = threading.Event()
    msg_queue = queue.Queue()
    
    # Stan oczekującego transferu pliku (tylko TCP obsługuje pliki)
    pending_file_transfer = {"active": False, "target": None, "path": None}
    pending_file_lock = threading.Lock()

    # =========================================================================
    # Wątek odbiorczy TCP
    # =========================================================================
    # TCP to strumień - dane mogą przychodzić w częściach.
    # Jedna wiadomość może być podzielona na wiele recv().
    # Wiele wiadomości może przyjść w jednym recv().
    # Dlatego używamy bufora do składania kompletnych wiadomości.
    # =========================================================================
    def receiver():
        buffer = ""  # Bufor do składania wiadomości ze strumienia
        while not stop_event.is_set():
            try:
                # recv() - odbiera dane ze strumienia TCP
                # Może zwrócić mniej bajtów niż żądano!
                data = client_socket.recv(8192)
                if not data:
                    # Puste dane = serwer się rozłączył
                    msg_queue.put(("disconnect", None))
                    stop_event.set()
                    break
                text = data.decode("utf-8", errors="replace")
                buffer += text  # Dodajemy do bufora
                
                # ============================================================
                # Sygnały protokołu przesyłania plików
                # ============================================================
                # FILE_READY - serwer gotowy na nagłówek pliku
                # FILE_DATA_READY - serwer gotowy na dane binarne
                # ============================================================
                if buffer == "FILE_READY":
                    msg_queue.put(("file_ready", None))
                    buffer = ""
                    continue
                
                if buffer == "FILE_DATA_READY":
                    msg_queue.put(("file_data_ready", None))
                    buffer = ""
                    continue
                

                # ============================================================
                # Odbiór pliku od serwera
                # ============================================================
                # Format: FILE_TRANSFER:nazwa|rozmiar|nadawca\n<base64>\nFILE_END
                # Dane są zakodowane Base64 dla bezpiecznej transmisji tekstowej.
                # ============================================================
                if buffer.startswith(FILE_HEADER_PREFIX) and FILE_END_MARKER in buffer:
                    end_idx = buffer.find(FILE_END_MARKER)
                    file_msg = buffer[:end_idx + len(FILE_END_MARKER)]
                    buffer = buffer[end_idx + len(FILE_END_MARKER):]
                    
                    try:
                        lines = file_msg.split("\n")
                        header = lines[0][len(FILE_HEADER_PREFIX):]
                        parts = header.split("|")
                        filename = parts[0]
                        file_size = int(parts[1])
                        sender = parts[2]
                        encoded_data = lines[1]
                        
                        # Dekodowanie Base64 -> dane binarne
                        file_data = base64.b64decode(encoded_data)
                        msg_queue.put(("file_incoming", (filename, file_size, sender, file_data)))
                    except Exception as e:
                        msg_queue.put(("message", f"Błąd odbierania pliku: {e}"))
                    continue
                

                if "\n" in buffer or len(buffer) > 4096:
                    msg_queue.put(("message", buffer))
                    buffer = ""
                elif not buffer.startswith(FILE_HEADER_PREFIX):
                    msg_queue.put(("message", buffer))
                    buffer = ""
                    
            except OSError:
                break
            except Exception:
                continue

    def printer():
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        
        while not stop_event.is_set():
            try:
                msg_type, data = msg_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            
            sys.stdout.write("\r\033[K")
            
            if msg_type == "disconnect":
                sys.stdout.write("Serwer się rozłączył\n")
            # =================================================================
            # Obsługa sygnału FILE_READY od serwera
            # =================================================================
            # Serwer potwierdził że odbiorca istnieje.
            # Teraz wysyłamy nagłówek: FILE_TRANSFER:nazwa|rozmiar|odbiorca
            # =================================================================
            elif msg_type == "file_ready":
                with pending_file_lock:
                    if pending_file_transfer["active"]:
                        try:
                            filepath = pending_file_transfer["path"]
                            target = pending_file_transfer["target"]
                            filename = os.path.basename(filepath)
                            
                            with open(filepath, "rb") as f:
                                file_data = f.read()
                            
                            file_size = len(file_data)
                            
                            if file_size > MAX_FILE_SIZE:
                                sys.stdout.write(f"Plik za duży ({file_size} > {MAX_FILE_SIZE})\n")
                            else:
                                # Wysyłanie nagłówka pliku
                                header = f"{FILE_HEADER_PREFIX}{filename}|{file_size}|{target}"
                                # sendall() - gwarantuje wysłanie wszystkich bajtów
                                client_socket.sendall(header.encode("utf-8"))
                                sys.stdout.write(f"Wysyłam plik '{filename}' ({file_size} bajtów)...\n")
                        except FileNotFoundError:
                            sys.stdout.write(f"Plik nie istnieje: {filepath}\n")
                        except Exception as e:
                            sys.stdout.write(f"Błąd wysyłania pliku: {e}\n")
                        finally:
                            pending_file_transfer["active"] = False
                            pending_file_transfer["target"] = None
                            pending_file_transfer["path"] = None
            # =================================================================
            # Obsługa sygnału FILE_DATA_READY od serwera
            # =================================================================
            # Serwer odebrał nagłówek i jest gotowy na dane binarne.
            # Wysyłamy surowe bajty pliku przez sendall().
            # =================================================================
            elif msg_type == "file_data_ready":
                with pending_file_lock:
                    if pending_file_transfer["path"]:
                        try:
                            filepath = pending_file_transfer["path"]
                            with open(filepath, "rb") as f:
                                file_data = f.read()
                            # sendall() - gwarantuje wysłanie wszystkich bajtów
                            client_socket.sendall(file_data)
                        except Exception as e:
                            sys.stdout.write(f"Błąd wysyłania danych pliku: {e}\n")
            elif msg_type == "file_incoming":
                filename, file_size, sender, file_data = data

                save_path = os.path.join(DOWNLOADS_DIR, filename)

                counter = 1
                base, ext = os.path.splitext(filename)
                while os.path.exists(save_path):
                    save_path = os.path.join(DOWNLOADS_DIR, f"{base}_{counter}{ext}")
                    counter += 1
                
                try:
                    with open(save_path, "wb") as f:
                        f.write(file_data)
                    sys.stdout.write(f"📁 Otrzymano plik od '{sender}': {os.path.basename(save_path)} ({file_size} bajtów)\n")
                except Exception as e:
                    sys.stdout.write(f"Błąd zapisywania pliku: {e}\n")
            elif msg_type == "message":
                sys.stdout.write(f"Odebrano: {data}\n")
            
            sys.stdout.write(PROMPT + readline.get_line_buffer())
            sys.stdout.flush()

    recv_thread = threading.Thread(target=receiver, daemon=True)
    print_thread = threading.Thread(target=printer, daemon=True)
    recv_thread.start()
    print_thread.start()

    print(WELCOME_MESSAGE)

    try:
        while True:
            try:
                message = input(PROMPT)
                if not message.strip():
                    continue
                if message == "exit":
                    client_socket.sendall(b"exit")
                    print("Koniec połączenia")
                    stop_event.set()
                    break
                
                # ============================================================
                # Obsługa komendy /sendfile - przesyłanie plików
                # ============================================================
                # 1. Klient waliduje plik lokalnie (istnieje, rozmiar OK)
                # 2. Klient wysyła komendę /sendfile do serwera
                # 3. Serwer odpowiada FILE_READY (wątek receiver to obsłuży)
                # 4. Klient wysyła nagłówek, czeka na FILE_DATA_READY
                # 5. Klient wysyła dane binarne
                # ============================================================
                if message.startswith("/sendfile "):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        print("Użycie: /sendfile <użytkownik> <ścieżka>")
                        continue
                    target_user = parts[1].strip()
                    filepath = parts[2].strip()
                    

                    if not os.path.isfile(filepath):
                        print(f"Plik nie istnieje: {filepath}")
                        continue
                    
                    file_size = os.path.getsize(filepath)
                    if file_size > MAX_FILE_SIZE:
                        print(f"Plik za duży: {file_size} bajtów (max {MAX_FILE_SIZE // (1024*1024)} MB)")
                        continue
                    

                    with pending_file_lock:
                        pending_file_transfer["active"] = True
                        pending_file_transfer["target"] = target_user
                        pending_file_transfer["path"] = filepath
                    

                    client_socket.sendall(message.encode("utf-8"))
                    continue
                
                client_socket.sendall(message.encode("utf-8"))
            except KeyboardInterrupt:
                print("\nKoniec programu")
                stop_event.set()
                break
            except Exception as e:
                print(f"Błąd: {e}")
                stop_event.set()
                break
    finally:
        client_socket.close()


def main():
    parser = argparse.ArgumentParser(description="Prosty klient UDP/TCP")
    parser.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Wybierz protokół klienta")
    parser.add_argument("--host", default="localhost", help="Host serwera (domyślnie: localhost)")
    parser.add_argument("--port", type=int, default=5678, help="Port serwera (domyślnie: 5678)")
    args = parser.parse_args()

    if args.proto == "udp":
        run_udp_client(args.host, args.port)
    else:
        run_tcp_client(args.host, args.port)


if __name__ == "__main__":
    main()
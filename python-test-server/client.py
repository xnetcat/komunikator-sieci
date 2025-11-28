import argparse
import queue
import readline  # enables line editing in input
import socket
import sys
import threading

PROMPT = "> "

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
║  /history <użytkownik>           - Historia wiadomości     ║
║  /help                           - Pokaż pomoc             ║
║  exit                            - Zakończ program         ║
║                                                            ║
║  (zwykła wiadomość)              - Wyślij do wszystkich    ║
║                                                            ║
║  Zaloguj się aby korzystać z czatu!                        ║
╚════════════════════════════════════════════════════════════╝
"""


def run_udp_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    stop_event = threading.Event()
    msg_queue = queue.Queue()

    def receiver():
        while not stop_event.is_set():
            try:
                data, _ = client_socket.recvfrom(4096)
            except OSError:
                break
            except Exception:
                continue
            text = data.decode("utf-8", errors="replace")
            msg_queue.put(text)

    def printer():
        """Print incoming messages, refreshing the input line."""
        while not stop_event.is_set():
            try:
                text = msg_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            # Save current input, clear line, print message, restore input
            sys.stdout.write("\r\033[K")  # Clear current line
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
                    client_socket.sendto(b"exit", server_address)
                    print("Koniec połączenia")
                    stop_event.set()
                    break
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
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            client_socket.close()
        except Exception:
            pass


def run_tcp_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    client_socket.connect(server_address)
    stop_event = threading.Event()
    msg_queue = queue.Queue()

    def receiver():
        while not stop_event.is_set():
            try:
                data = client_socket.recv(4096)
                if not data:
                    msg_queue.put(None)  # Signal disconnect
                    stop_event.set()
                    break
                text = data.decode("utf-8", errors="replace")
                msg_queue.put(text)
            except OSError:
                break
            except Exception:
                continue

    def printer():
        """Print incoming messages, refreshing the input line."""
        while not stop_event.is_set():
            try:
                text = msg_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            sys.stdout.write("\r\033[K")  # Clear current line
            if text is None:
                sys.stdout.write("Serwer się rozłączył\n")
            else:
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
                    client_socket.sendall(b"exit")
                    print("Koniec połączenia")
                    stop_event.set()
                    break
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
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            client_socket.close()
        except Exception:
            pass


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
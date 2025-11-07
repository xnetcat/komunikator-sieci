import argparse
import socket
import threading


def process_message(text):
    if text == "exit":
        return None
    if text == "ping":
        return "pong"
    if text == "pong":
        return "ping"
    return text  # echo


def run_udp_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    server_socket.bind(server_address)
    print(f"UDP serwer nasłuchuje na {server_address}")

    try:
        while True:
            data, client_address = server_socket.recvfrom(4096)
            text = data.decode("utf-8", errors="replace")
            print(f"[{client_address}] Otrzymane: {text}")

            response = process_message(text)
            if response is None:
                # brak odpowiedzi dla 'exit'
                print(f"[{client_address}] Zamknięcie żądane ('exit')")
                continue

            server_socket.sendto(response.encode("utf-8"), client_address)
            print(f"[{client_address}] Wysłano: {response}")
    except KeyboardInterrupt:
        print("Koniec programu (zamykam serwer)")
    finally:
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

            text = data.decode("utf-8", errors="replace")
            print(f"[{client_address}] Otrzymane: {text}")

            response = process_message(text)
            if response is None:
                print(f"[{client_address}] Zamknięcie żądane ('exit')")
                break

            conn.sendall(response.encode("utf-8"))
            print(f"[{client_address}] Wysłano: {response}")
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
    parser = argparse.ArgumentParser(description="Prosty serwer UDP/TCP: ping/pong/echo")
    parser.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Wybierz protokół serwera")
    parser.add_argument("--host", default="localhost", help="Adres hosta (domyślnie: localhost)")
    parser.add_argument("--port", type=int, default=5678, help="Port serwera (domyślnie: 5678)")
    args = parser.parse_args()

    if args.proto == "udp":
        run_udp_server(args.host, args.port)
    else:
        run_tcp_server(args.host, args.port)


if __name__ == "__main__":
    main()
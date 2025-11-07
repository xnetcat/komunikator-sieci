import argparse
import socket


def run_udp_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (host, port)
    try:
        while True:
            try:
                message = input("Wpisz wiadomość: ")
                if message == "exit":
                    client_socket.sendto(b"exit", server_address)
                    print("Koniec połączenia")
                    break
                client_socket.sendto(message.encode("utf-8"), server_address)
                data, _ = client_socket.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                print(f"Odpowiedź serwera: {text}")
            except KeyboardInterrupt:
                print("Koniec programu")
                break
            except Exception as e:
                print(f"Błąd: {e}")
                break
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def run_tcp_client(host, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    client_socket.connect(server_address)
    try:
        while True:
            try:
                message = input("Wpisz wiadomość: ")
                if message == "exit":
                    client_socket.sendall(b"exit")
                    print("Koniec połączenia")
                    break
                client_socket.sendall(message.encode("utf-8"))
                data = client_socket.recv(4096)
                if not data:
                    print("Serwer się rozłączył")
                    break
                text = data.decode("utf-8", errors="replace")
                print(f"Odpowiedź serwera: {text}")
            except KeyboardInterrupt:
                print("Koniec programu")
                break
            except Exception as e:
                print(f"Błąd: {e}")
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
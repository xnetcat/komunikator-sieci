import argparse
import socket
import threading
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
# Map UDP client address (ip, port) -> username
addr_to_username = {}
# Map username -> UDP client address (ip, port)
username_to_addr = {}


def get_username_for_addr(addr):
    with clients_lock:
        return addr_to_username.get(addr)


def set_username_for_addr(addr, username):
    if not username or " " in username:
        return False, "Niepoprawna nazwa użytkownika. Użyj bez spacji."
    with clients_lock:
        if username in username_to_addr and username_to_addr[username] != addr:
            return False, f"Nazwa '{username}' jest już zajęta."
        # Remove old mapping if any
        old = addr_to_username.get(addr)
        if old and old != username:
            username_to_addr.pop(old, None)
        addr_to_username[addr] = username
        username_to_addr[username] = addr
    return True, f"Ustawiono nazwę użytkownika na '{username}'."


def remove_addr(addr):
    with clients_lock:
        old = addr_to_username.pop(addr, None)
        if old:
            username_to_addr.pop(old, None)


def list_usernames():
    with clients_lock:
        return sorted(username_to_addr.keys())


def handle_udp_packet(server_socket, data, client_address):
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return

    print(f"[{client_address}] Otrzymane: {text}")

    # Commands
    if text == "exit":
        remove_addr(client_address)
        print(f"[{client_address}] Zamknięcie żądane ('exit')")
        return

    if text.startswith("/set "):
        _, _, username = text.partition(" ")
        ok, msg = set_username_for_addr(client_address, username.strip())
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text == "/whoami":
        username = get_username_for_addr(client_address)
        msg = f"Twoja nazwa użytkownika: '{username}'" if username else "Nie ustawiono nazwy użytkownika. Użyj: /set <nazwa>"
        server_socket.sendto(msg.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {msg}")
        return

    if text == "/list":
        users = list_usernames()
        msg = "Użytkownicy: " + (", ".join(users) if users else "(brak)")
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
        sender_name = get_username_for_addr(client_address) or f"{client_address[0]}:{client_address[1]}"
        # Lookup destination
        with clients_lock:
            target_addr = username_to_addr.get(target_user)
        if not target_addr:
            msg = f"Nie znaleziono użytkownika '{target_user}'."
            server_socket.sendto(msg.encode("utf-8"), client_address)
            print(f"[{client_address}] Wysłano: {msg}")
            return
        # Deliver to target
        delivered_text = f"[od {sender_name}] {msg_body}"
        server_socket.sendto(delivered_text.encode("utf-8"), target_addr)
        ack = f"Wysłano do '{target_user}': {msg_body}"
        server_socket.sendto(ack.encode("utf-8"), client_address)
        print(f"[{client_address}] Wysłano: {ack}")
        return

    # Fallback to ping/pong/echo
    response = process_message(text)
    if response is None:
        print(f"[{client_address}] Zamknięcie żądane ('exit')")
        return
    server_socket.sendto(response.encode("utf-8"), client_address)
    print(f"[{client_address}] Wysłano: {response}")


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
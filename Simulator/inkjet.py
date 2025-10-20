# tcp_utf8_server.py
import socket
import threading

HOST = '0.0.0.0'  # 모든 인터페이스
PORT = 9200       # 원하는 포트 번호

clients = []

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            data = conn.recv(1024)  # 최대 1024바이트 수신
            if not data:
                break
            try:
                msg = data.decode('utf-8')  # UTF-8 디코딩
            except UnicodeDecodeError:
                msg = repr(data)
            print(f"[RECV {addr}] {msg}")
    except ConnectionResetError:
        print(f"[DISCONNECTED] {addr} unexpectedly disconnected.")
    finally:
        conn.close()
        clients.remove(conn)
        print(f"[DISCONNECTED] {addr} disconnected.")

def accept_clients(server_socket):
    while True:
        conn, addr = server_socket.accept()
        clients.append(conn)
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def send_messages():
    print("Type messages to send. CR/LF can be written as [CR] and [LF]. Type 'exit' to quit.")
    while True:
        msg = input()

        if msg.lower() == 'exit':
            print("[SERVER] Shutting down sender...")
            break

        # 맨 앞에 ESC 자동 추가
        msg = "\x1B" + msg

        # 콘솔 입력에서 CR/LF 치환
        msg = msg.replace("[CR]", "\r").replace("[LF]", "\n")

        # UTF-8 인코딩 후 송신
        print(msg)
        data = msg.encode('utf-8')
        for client in clients:
            try:
                client.sendall(data)
            except BrokenPipeError:
                print("[ERROR] Failed to send to a client.")



def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[STARTED] TCP Server listening on {HOST}:{PORT}")

    threading.Thread(target=accept_clients, args=(server_socket,), daemon=True).start()
    send_messages()  # cmd line에서 메시지 입력

    server_socket.close()
    print("[STOPPED] Server shutdown.")

if __name__ == "__main__":
    main()

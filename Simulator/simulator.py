import socket
import threading
import time

HOST = '0.0.0.0'       # 모든 인터페이스에서 수신
PORT = 9100            # 잉크젯 클라이언트가 접속할 포트 번호

ESC = b'\x1B'
CR = b'\x0D'
LF = b'\x0A'

print_count = 0  # 인쇄 완료 횟수

def parse_message(msg: bytes) -> str:
    """수신된 메시지를 사람이 읽을 수 있는 형태로 디코딩"""
    decoded = ''
    for b in msg:
        if b == 0x1B:
            decoded += '[ESC]'
        elif b == 0x0D:
            decoded += '[CR]'
        elif b == 0x0A:
            decoded += '[LF]'
        elif 32 <= b <= 126:
            decoded += chr(b)
        else:
            decoded += f'[0x{b:02X}]'
    return decoded

def build_response(protocol: str, success: bool = True) -> bytes:
    """프로토콜명에 따른 응답 메시지 생성"""
    if success:
        return ESC + f'{protocol} OK : 1'.encode() + CR + LF
    else:
        return ESC + f'{protocol} ER : Unknown protocol'.encode() + CR + LF

def send_print_complete_signal(conn: socket.socket):
    """3초 주기로 인쇄 완료 신호를 송신하는 함수"""
    global print_count
    while True:
        time.sleep(3)
        if print_count>100 : print_count= 0;
        print_count += 1
        count_str = f'{print_count:06d}'
        message = ESC + f'CTR OK : ({count_str})'.encode() + CR + LF
        try:
            conn.sendall(message)
            print(f"[SENT - CTR] {parse_message(message)}")
        except Exception as e:
            print(f"[ERROR] 인쇄 완료 메시지 송신 중 오류: {e}")
            break

# TCP 서버 시작
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[SIMULATOR] 잉크젯 설비 시뮬레이터가 {PORT} 포트에서 대기 중...")

    conn, addr = server.accept()
    with conn:
        print(f"[CONNECTED] 클라이언트 접속: {addr}")

        # 인쇄 완료 신호 송신 스레드 시작
        threading.Thread(target=send_print_complete_signal, args=(conn,), daemon=True).start()

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print("[DISCONNECTED] 클라이언트 종료됨")
                    break

                readable = parse_message(data)
                print(f"[RECEIVED] {readable}")

                # 바이트 문자열에서 명령어 추출
                if b'TXC' in data:
                    protocol = 'TXC'
                    response = build_response(protocol, success=True)
                elif b'BSC' in data:
                    protocol = 'BSC'
                    response = build_response(protocol, success=True)
                elif b'CTI' in data:
                    protocol = 'CTI'
                    response = build_response(protocol, success=True)
                else:
                    protocol = 'UNK'
                    response = build_response(protocol, success=False)

                conn.sendall(response)
                print(f"[SENT] {parse_message(response)}")
            except Exception as e:
                print(f"[ERROR] 수신 처리 중 오류: {e}")
                break




# # import socket
# # import threading
# # import time

# # HOST = '0.0.0.0'
# # PORT = 9200

# # ESC = b'\x1B'
# # CR = b'\x0D'
# # LF = b'\x0A'

# # # 인쇄 횟수 (예: 증가시켜보기 위한 전역 변수로도 사용 가능)
# # print_count = 0

# # def send_print_complete_signal(conn):
# #     global print_count
# #     while True:
# #         time.sleep(3)
# #         print_count += 1
# #         count_str = f'{print_count:06d}'  # 6자리로 포맷
# #         msg = ESC + f'CTR OK : ({count_str})'.encode('ascii') + CR + LF
# #         try:
# #             conn.sendall(msg)
# #             print(f'[SEND] {msg}')
# #         except Exception as e:
# #             print(f'[ERROR] Failed to send: {e}')
# #             break

# # def handle_client(conn, addr):
# #     print(f'[CONNECTED] {addr}')
# #     sender_thread = threading.Thread(target=send_print_complete_signal, args=(conn,), daemon=True)
# #     sender_thread.start()

# #     try:
# #         while True:
# #             data = conn.recv(1024)
# #             if not data:
# #                 break
# #             print(f'[RECEIVED from {addr}] {data}')
# #             # 수신 프로토콜 처리
# #     except Exception as e:
# #         print(f'[ERROR] {e}')
# #     finally:
# #         conn.close()
# #         print(f'[DISCONNECTED] {addr}')

# # def start_server():
# #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
# #         s.bind((HOST, PORT))
# #         s.listen()
# #         print(f'[LISTENING] on {HOST}:{PORT}')
# #         while True:
# #             conn, addr = s.accept()
# #             threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# # if __name__ == '__main__':
# #     start_server()


# import socket

# HOST = '0.0.0.0'       # 모든 인터페이스에서 수신
# PORT = 9100            # 잉크젯 클라이언트가 접속할 포트 번호 (프로그램 설정과 일치시켜야 함)

# ESC = b'\x1B'
# CR = b'\x0D'
# LF = b'\x0A'

# def parse_message(msg: bytes) -> str:
#     """수신된 메시지를 사람이 읽을 수 있는 형태로 디코딩"""
#     decoded = ''
#     for b in msg:
#         if b == 0x1B:
#             decoded += '[ESC]'
#         elif b == 0x0D:
#             decoded += '[CR]'
#         elif b == 0x0A:
#             decoded += '[LF]'
#         elif 32 <= b <= 126:
#             decoded += chr(b)
#         else:
#             decoded += f'[0x{b:02X}]'
#     return decoded

# def build_response(protocol: str, success: bool = True) -> bytes:
#     """프로토콜명에 따른 응답 메시지 생성"""
#     if success:
#         return ESC + f'{protocol} OK : 1'.encode() + CR + LF
#     else:
#         return ESC + f'{protocol} ER : Unknown protocol'.encode() + CR + LF


# # TCP 서버 시작
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
#     server.bind((HOST, PORT))
#     server.listen(1)
#     print(f"[SIMULATOR] 잉크젯 설비 시뮬레이터가 {PORT} 포트에서 대기 중...")

#     conn, addr = server.accept()
#     with conn:
#         print(f"[CONNECTED] 클라이언트 접속: {addr}")
#         while True:
#             data = conn.recv(1024)
#             if not data:
#                 print("[DISCONNECTED] 클라이언트 종료됨")
#                 break

#             readable = parse_message(data)
#             print(f"[RECEIVED] {readable}")

#             # 바이트 문자열에서 명령어 추출 (예: b'TXC', b'BSC' 등)
#             if b'TXC' in data:
#                 protocol = 'TXC'
#                 response = build_response(protocol, success=True)
#             elif b'BSC' in data:
#                 protocol = 'BSC'
#                 response = build_response(protocol, success=True)
#             elif b'CTI' in data:
#                 protocol = 'CTI'
#                 response = build_response(protocol, success=True)
#             else:
#                 # 프로토콜 이름을 추정할 수 없으므로 ER만 보냄
#                 protocol = 'AAA'  # 혹은 'UNK'
#                 response = build_response(protocol, success=False)


#             conn.sendall(response)
#             print(f"[SENT] {parse_message(response)}")

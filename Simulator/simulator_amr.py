import socket

HOST = '0.0.0.0'
PORT = 9200

STX = b'\x02'
ETX = b'\x03'
EOT = b'\x04'

def parse_message(msg: bytes) -> str:
    decoded = ''
    for b in msg:
        if b == 0x1B:
            decoded += '[ESC]'
        elif b == 0x0D:
            decoded += '[CR]'
        elif b == 0x0A:
            decoded += '[LF]'
        elif b == 0x02:
            decoded += '[STX]'
        elif b == 0x03:
            decoded += '[ETX]'
        elif b == 0x04:
            decoded += '[EOT]'
        elif 32 <= b <= 126:
            decoded += chr(b)
        else:
            decoded += f'[0x{b:02X}]'
    return decoded

def build_response(mailbox: str, msg_type: str, ack: str = 'A', reason_code: str = '00') -> bytes:
    """
    AMR Response 메시지 생성
    """
    # 본문 구성
    body = msg_type.lower().encode() + ack.encode() + reason_code.encode()
    
    # 메시지 길이 (본문 길이)
    data_len = len(body)
    header = mailbox.ljust(10).encode()                 # Destination (Mailbox name, 10 bytes)
    header += f"{data_len:04}".encode()                 # Length (4 bytes, zero-padded)
    header += EOT                                       # Terminator (1 byte)

    # 전체 메시지 조합
    return header + STX + body + ETX

# ====================== Main TCP Server ======================

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[SIMULATOR] AMR 시뮬레이터가 포트 {PORT}에서 대기 중...")

    conn, addr = server.accept()
    with conn:
        print(f"[CONNECTED] 클라이언트 접속: {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                print("[DISCONNECTED] 클라이언트 종료됨")
                break

            print(f"[RECEIVED] {parse_message(data)}")

            # Mailbox 가정: ECS_ACS ← ECS → AMR
            mailbox = 'ACS_ECS'

            # 메시지 타입 추출
            if b'O' in data:                 # 작업 등록 명령만 수신!! 
                msg_type = 'O'
                ack = 'A'
                reason = '00'
            else:
                msg_type = 'UNK'
                ack = 'N'
                reason = '16'  # Unknown Message Type

            response = build_response(mailbox, msg_type, ack, reason)

            conn.sendall(response)
            print(f"[SENT] {parse_message(response)}")

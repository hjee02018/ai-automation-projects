from flask import Flask, jsonify, Response, request
from db import get_db_connection
import os
import cv2
import time
from model.detection_model import ObjectDetectionModel
from utils.image_processing import process_video
from cctv_service_back.hist_controller import hist_blueprint
import datetime  # 인식 결과의 일시를 기록하기 위해 추가
import sys
from model.hist_model import HistModel  # Import HistModel
from ultralytics import YOLO
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import time

import atexit


app = Flask(__name__)

#CORS 설정
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def home():
    return 'This is Home!'

@app.route('/test-db')
def test_db():
    """ DB 연결을 테스트하는 엔드포인트 """
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT 'Connection successful!' FROM dual")
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        return jsonify({"message": result[0]})
    else:
        return jsonify({"error": "Failed to connect to the database"}), 500
    
@app.route('/socket-test')
def socket_test():
    """ 클라이언트에게 소켓 연결 테스트 요청 전송 """
    socketio.emit('server_message', {'data': 'Hello from server!'})
    return jsonify({"message": "Socket test message sent to client!"})

@app.route('/send-notification', methods=['POST'])
def send_notification():
    data = request.get_json()
    cctv_no = data['cctv_no']
    class_name = data['class_name']
    timestamp = data['time']

    # 클라이언트로 소켓 알림 전송
    socketio.emit('new_detection', {
        'cctv_no': cctv_no,
        'class_name': class_name,
        'time': timestamp
    })

    return jsonify({"message": "Notification sent!"})


# 커스텀 모델 로드
custom_model = YOLO("file/500_100_sample_yolov8l.pt")  # pretrained YOLO11n model

# VER1. 실시간 스트리밍 요청 처리 (웹 소켓 방식)
@socketio.on('stream_video')
def stream_video(cctv_id):
    # 파일 경로
    video_path = f'video/cctv_{cctv_id}.mp4'  # 각 CCTV ID에 맞는 비디오 파일 경로
    cap = cv2.VideoCapture(video_path)

    if not cap.isOpened():
        emit('error', {"error": "Could not open video stream"})
        return

    frame_count = 0
    start_time = time.time()
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        # YOLO 모델로 프레임 처리
        results = custom_model(frame)

        # 탐지 결과를 이미지에 표시
        for result in results:
            for i in range(len(result.boxes.data)):
                class_id = int(result.boxes.data[i][-1].item())  # 클래스 ID
                confidence = float(result.boxes.data[i][-2].item())  # 신뢰도
                x1, y1, x2, y2 = result.boxes.data[i][:4].tolist()  # 바운딩 박스 좌표
                custom_class_name = custom_model.names[int(class_id)]  # 클래스 이름

                # 프레임에 바운딩 박스 그리기
                cv2.rectangle(frame, (int(x1), int(y1)), (int(x2), int(y2)), (0, 255, 0), 2)
                # 클래스 이름과 신뢰도 텍스트 그리기
                label = f'{custom_class_name} ({confidence:.2f})'
                cv2.putText(frame, label, (int(x1), int(y1) - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)

                # 탐지 결과 히스토리에 기록
                detection_data = {
                    'x1': x1, 'y1': y1, 'x2': x2, 'y2': y2,
                    'class_name': custom_class_name, 'confidence': confidence
                }
                # HistModel.insert_detection_to_hist(detection_data)
                HistModel.send_socket_notification(detection_data)


        frame_count += 1

        # 수정된 프레임을 JPEG로 인코딩
        ret, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        # 30프레임마다 FPS 계산
        if frame_count % 30 == 0:
            elapsed_time = time.time() - start_time
            fps = frame_count / elapsed_time
            print(f"FPS: {fps:.2f}")

        # 클라이언트에 프레임 전송
        emit('frame', {'image': frame_bytes}, broadcast=True)

    cap.release()

# VER2. 실시간 스트리밍 요청 처리 (cctv_id 인자로 넘겨 받음 : video id로 치환)
@app.route('/stream_video/<int:cctv_id>', methods=['GET'])
def stream_video_play(cctv_id):
    def generate_frames():
        # 파일 경로
        video_path = f'video/cctv_{cctv_id}.mp4'  # 각 CCTV ID에 맞는 비디오 파일 경로
        output_video_path = f'video/output/result_cctv_{cctv_id}.mp4'  # 저장할 동영상 파일 경로
        
        frame_count = 0
        start_time = time.time()

        # 비디오 캡처 초기화
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            yield jsonify({"error": "Could not open video stream"}), 400

        # 비디오 정보 가져오기
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = int(cap.get(cv2.CAP_PROP_FPS))

        # 비디오 저장용 VideoWriter 초기화 (코덱은 mp4v 사용)
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_video_path, fourcc, fps, (frame_width, frame_height))

        def release_resources():
            # 비디오 캡처 및 VideoWriter 해제
            if cap.isOpened():
                cap.release()
            if out.isOpened():
                out.release()
            print("Video writer released and saved successfully.")
        
        # 서버 종료 시 자원 해제 및 파일 저장 보장을 위해 atexit에 등록
        atexit.register(release_resources)

        try:
            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break  # 비디오가 종료되면 내부 루프를 나감

                # YOLO 모델로 프레임 처리
                results = custom_model(frame)

                # 탐지 결과를 이미지에 표시
                for result in results:
                    # 바운딩 박스와 클래스 라벨을 프레임에 표시
                    for i in range(len(result.boxes.data)):
                        class_id = int(result.boxes.data[i][-1].item())  # 클래스 ID
                        confidence = float(result.boxes.data[i][-2].item())  # 신뢰도
                        x1, y1, x2, y2 = result.boxes.data[i][:4].tolist()  # 바운딩 박스 좌표
                        custom_class_name = custom_model.names[int(class_id)]  # 클래스 이름

                        # 박스 색상 결정 (UA/UC- : 빨간색)
                        if custom_class_name.startswith("UA") or custom_class_name.startswith("UC"):
                            box_color = (0, 0, 255)  # 빨간색 (BGR 형식)
                        else:
                            box_color = (0, 255, 0)  # 초록색 (BGR 형식)

                        # 프레임에 바운딩 박스 그리기
                        cv2.rectangle(frame, (int(x1), int(y1)), (int(x2), int(y2)), box_color, 2)
                        # 클래스 이름과 신뢰도 텍스트 그리기
                        label = f'{custom_class_name} ({confidence:.2f})'
                        cv2.putText(frame, label, (int(x1), int(y1) - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, box_color, 2)

                        # 탐지 결과 히스토리에 기록
                        detection_data = {
                            'x1': x1, 'y1': y1, 'x2': x2, 'y2': y2,
                            'class_name': custom_class_name, 'confidence': confidence
                        }
                        # HistModel.insert_detection_to_hist(detection_data)
                        HistModel.send_socket_notification(detection_data)

                # 수정된 프레임을 저장
                out.write(frame)  # 비디오 파일에 매 프레임을 저장

                frame_count += 1

                # 수정된 프레임을 JPEG로 인코딩
                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()

                # 30프레임마다 FPS 계산
                if frame_count % 30 == 0:
                    elapsed_time = time.time() - start_time
                    fps = frame_count / elapsed_time
                    print(f"FPS: {fps:.2f}")

                # 클라이언트에 프레임 전송
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

        except GeneratorExit:
            print("Client disconnected.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            release_resources()  # 강제 종료가 아닌 경우도 자원 해제 및 저장

    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')


app.register_blueprint(hist_blueprint)

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)

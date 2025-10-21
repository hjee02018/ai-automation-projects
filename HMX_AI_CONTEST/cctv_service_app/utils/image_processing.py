# 프레임 단위 영상 처리 및 탐지 결과 시각화 (ROI박스)
import cv2
import os
from datetime import datetime  
from model.detection_model import ObjectDetectionModel
import time  # FPS 계산에 필요

def process_video(video_path, model):
    # 처리 후 영상을 저장할 경로 설정
    processed_video_path = video_path
#    processed_video_path = os.path.splitext(video_path)[0] + "_processed.avi"

    # 비디오 파일 열기
    cap = cv2.VideoCapture(video_path)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(processed_video_path, fourcc, 20.0, (640, 480))

    detections = []  # 탐지 결과 저장
    frame_count = 0  # 프레임 수 카운트
    start_time = time.time()  # 시작 시간

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        
        # 프레임에 대해 객체 탐지 수행
        predictions = model.predict(frame)

        # 예측 결과 시각화 (바운딩 박스 그리기)
        for pred in predictions:
            if pred.boxes is not None and len(pred.boxes) > 0:
                for box in pred.boxes:
                    x, y, w, h = map(int, box.xywh[0])
                    confidence = box.conf[0].item()
                    class_id = int(box.cls[0].item())
                    class_name = ObjectDetectionModel.get_class_names(model, class_id)

                    # 탐지 시각 출력
                    detection_time = datetime.now()
                    reg_date = detection_time.strftime("%Y-%m-%d")  # REG_DATE (날짜)
                    reg_time = detection_time.strftime("%H:%M:%S")  # REG_TIME (시간)

                    # 프레임마다 인식 결과 출력
                    print(f"인식 일시: {detection_time}, 신뢰도: {confidence:.2f}, ROI 좌표: x={x}, y={y}, w={w}, h={h}, class_ID: {class_id}, class_name: {class_name}")

                    # 바운딩 박스와 레이블 추가
                    cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 2)  # 빨간색 박스
                    cv2.putText(frame, f"{class_name} ({confidence:.2f})", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 255), 2)

                    # 탐지 결과 저장
                    detections.append({
                        "area": 1,
                        "label": class_name,
                        "confidence": confidence,
                        "bbox": [x, y, w, h],
                        "REG_DATE": reg_date,
                        "REG_TIME": reg_time
                    })

        # 처리된 프레임 저장
        out.write(frame)

        # 프레임 수 증가
        frame_count += 1

        # FPS 계산 및 출력
        if frame_count % 20 == 0:  # 20 프레임마다 FPS 출력 (대략 1초 기준)
            elapsed_time = time.time() - start_time
            fps = frame_count / elapsed_time
            print(f"현재 FPS: {fps:.2f}")
        
    cap.release()
    out.release()

    return processed_video_path, detections

# video_processing.py
import cv2
import time
from flask import Response
from model.hist_model import HistModel  # Import HistModel

def generate_frames(video_path, custom_model):
    cap = cv2.VideoCapture(video_path)

    if not cap.isOpened():
        raise ValueError("Could not open video stream")

    frame_count = 0
    start_time = time.time()

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        results = custom_model(frame)

        for result in results:
            for i in range(len(result.boxes.data)):
                class_id = int(result.boxes.data[i][-1].item())
                confidence = float(result.boxes.data[i][-2].item())
                x1, y1, x2, y2 = result.boxes.data[i][:4].tolist()
                custom_class_name = custom_model.names[int(class_id)]

                # Log detection information
                print(f"Class ID: {class_id}, Class Name: {custom_class_name}, Confidence: {confidence:.4f}, BBox: ({x1:.2f}, {y1:.2f}, {x2:.2f}, {y2:.2f})")
                
                # Store detection data
                detection_data = {
                    'x1': x1,
                    'y1': y1,
                    'x2': x2,
                    'y2': y2,
                    'class_name': class_id,
                    'confidence': confidence
                }
                HistModel.insert_detection_to_hist(detection_data)

        frame_count += 1
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()

        if frame_count % 30 == 0:
            elapsed_time = time.time() - start_time
            fps = frame_count / elapsed_time
            print(f"FPS: {fps:.2f}")

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()

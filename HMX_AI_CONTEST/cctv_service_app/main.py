# 파일 업로드 및 객체 탐지 처리
from flask import Flask, request, jsonify
import os
import cv2
from werkzeug.utils import secure_filename
from model.detection_model import ObjectDetectionModel
from utils.image_processing import process_video

app = Flask(__name__)

# 업로드된 파일을 저장할 경로
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 허용할 파일 확장자
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov'}

# 객체 탐지 모델 로드
model = ObjectDetectionModel('file/500_100_sample_yolov8l.pt')

# 허용된 파일 확장자 확인 함수
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 영상 업로드 및 처리 라우트
@app.route('/upload', methods=['POST'])
def upload_video():
    # 파일이 요청에 포함되었는지 확인
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']

    # 파일 이름이 없는지 확인
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # 허용된 파일 형식인지 확인
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 업로드된 파일에 대해 객체 탐지 처리
        processed_video_path, detections = process_video(filepath, model)

        return jsonify({
            "message": "Video processed successfully",
            "processed_video": processed_video_path,
            "detections": detections
        }), 200

    return jsonify({"error": "Invalid file format"}), 400

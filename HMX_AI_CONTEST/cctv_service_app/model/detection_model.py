import torch
import cv2
import numpy as np
from ultralytics import YOLO  # YOLOv8 모델 로드

class ObjectDetectionModel:
    def __init__(self, model_path):
        # 모델 가중치 로드
        self.model = YOLO(model_path)  # YOLOv8 모델 로드

    def predict(self, image):
        # 이미지 전처리 (YOLO 모델에 맞는 크기 및 포맷으로 변환)
        input_image = cv2.resize(image, (640, 640))  # YOLOv8의 입력 크기에 맞게 조정
        input_image = input_image / 255.0  # 픽셀 값 정규화
        input_image = np.transpose(input_image, (2, 0, 1))  # HWC -> CHW 변환
        input_image = torch.tensor(input_image, dtype=torch.float32)  # 텐서로 변환
        input_image = input_image.unsqueeze(0)  # 배치 차원 추가

        # 모델 예측
        predictions = self.model(input_image)
        return predictions

    def get_class_names(self, class_index):
        class_names = self.model.names
        return class_names[int(class_index)]
    
    def detect(self, frame):
        # BGR에서 RGB로 변환 (OpenCV는 BGR 포맷 사용)
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        # 이미지 전처리: 텐서 변환 및 차원 확장
        results = self.model(rgb_frame)  # YOLOv8 모델에 입력

        detections = []
        for *box, conf, cls in results.xyxy[0]:  # xyxy 형식으로 결과 가져오기
            x1, y1, x2, y2 = map(int, box)  # 좌표를 정수형으로 변환
            class_name = self.model.names[int(cls)]  # 클래스 이름 가져오기
            detections.append((x1, y1, x2, y2, class_name, conf.item()))  # 탐지 결과를 튜플로 추가

        return detections



# # PyTorch로 객체 탐지 모델 정의 (파이토치 ver 로 수정)
# import torch
# import cv2
# import numpy as np

# class ObjectDetectionModel:
#     def __init__(self, model_path):
#         # PyTorch 모델 로드
#         #!!!! 임시 추가 CUDA가 사용 가능하지 않으면 모델을 CPU로 로드
#         self.model = torch.load(model_path, map_location=torch.device('cpu'))
#         # self.model = torch.load(model_path)
#         self.model.eval()  # 모델을 평가 모드로 설정 (추론 시 필요 -> 추후 변경 가능)

#     def predict(self, image):
#         # 이미지 전처리 (PyTorch 텐서로 변환)
#         input_image = cv2.resize(image, (224, 224))  # 필요한 입력 크기로 이미지 리사이즈
#         input_image = input_image / 255.0  # 픽셀 값을 0-1 사이로 정규화
#         input_image = np.transpose(input_image, (2, 0, 1))  # 채널 순서를 맞추기 (HWC -> CHW)
#         input_image = torch.tensor(input_image, dtype=torch.float32)  # NumPy 배열을 PyTorch 텐서로 변환
#         input_image = input_image.unsqueeze(0)  # 배치 차원을 추가 (1, C, H, W)

#         # 예측
#         with torch.no_grad():  # 추론 시에는 그라디언트를 계산하지 않음
#             predictions = self.model(input_image)
        
#         return predictions


# # 객체 탐지 모델 정의 (추후 어진M 모델 경로로 수정)
# import tensorflow as tf
# import cv2
# import numpy as np

# class ObjectDetectionModel:
#     def __init__(self, model_path):
#         # 모델 로드
#         self.model = tf.keras.models.load_model(model_path)

#     def predict(self, image):
#         # 이미지 전처리 후 모델에 입력
#         input_image = cv2.resize(image, (224, 224))
#         input_image = input_image / 255.0
#         input_image = np.expand_dims(input_image, axis=0)

#         # 예측
#         predictions = self.model.predict(input_image)
#         return predictions

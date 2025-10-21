import matplotlib.pyplot as plt
import numpy as np
import cv2
import os
import glob

#아래 draw_annotations 함수는 JSON 라벨링을 가지고 이미지를 Fig.show() 하는 함수임.
def draw_annotations(image_path, bbox_annotation_file, seg_annotation_file):
    # Load the image
    img = cv2.imread(image_path)
    height, width, _ = img.shape

    # Read the bounding box annotation file
    with open(bbox_annotation_file, 'r') as f:
        bbox_annotations = f.readlines()

    # Read the segmentation annotation file
    with open(seg_annotation_file, 'r') as f:
        seg_annotations = f.readlines()

    # Draw bounding boxes
    for ann in bbox_annotations:
        values = ann.strip().split()
        class_id = values[0]
        x_center, y_center, bbox_width, bbox_height = map(float, values[1:])
        x_center *= width
        y_center *= height
        bbox_width *= width
        bbox_height *= height

        # Calculate top-left and bottom-right corners of the bounding box
        x_min = int(x_center - bbox_width / 2)
        y_min = int(y_center - bbox_height / 2)
        x_max = int(x_center + bbox_width / 2)
        y_max = int(y_center + bbox_height / 2)

        # Draw the bounding box
        cv2.rectangle(img, (x_min, y_min), (x_max, y_max), (0, 255, 0), 2)
        cv2.putText(img, f"{class_id}", (x_min, y_min - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)

    # Draw polygons (segmentation)
    for ann in seg_annotations:
        values = ann.strip().split()
        class_id = values[0]
        points = [(float(values[i]) * width, float(values[i + 1]) * height) for i in range(1, len(values), 2)]
        points = [(int(x), int(y)) for x, y in points]

        # Draw the polygon
        points = np.array(points, np.int32)
        points = points.reshape((-1, 1, 2))
        cv2.polylines(img, [points], isClosed=True, color=(0, 0, 255), thickness=2)
        cv2.putText(img, f"{class_id}", (points[0][0][0], points[0][0][1] - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.6,
                    (0, 0, 255), 2)

    # Display the image with bounding boxes and polygons
    plt.figure(figsize=(10, 10))
    plt.imshow(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    plt.axis('off')
    plt.show()


# Example usage
image_path = 'SampleFile/L-210916_G03_D_WS-09_001_0001.jpg'  # Replace with the actual image file path
bbox_annotation_file = 'bounding_box_annotations/L-210916_G03_D_WS-09_001_0001.txt'  # Bounding box .txt file path
seg_annotation_file = 'segmentation_annotations/L-210916_G03_D_WS-09_001_0001.txt'  # Segmentation .txt file path

# draw_annotations(image_path, bbox_annotation_file, seg_annotation_file)


def visualize_yolo_labels(image_dir, label_dir, output_dir):
    # 출력 디렉토리가 없으면 생성합니다.
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 이미지 파일 목록을 가져옵니다.
    image_paths = []
    for ext in ('*.jpg', '*.jpeg', '*.png', '*.bmp'):
        image_paths.extend(glob.glob(os.path.join(image_dir, ext)))

    for image_path in image_paths:
        # 이미지를 읽습니다.
        image = cv2.imread(image_path)
        if image is None:
            print(f"이미지를 읽을 수 없습니다: {image_path}")
            continue
        height, width, _ = image.shape

        # 이미지의 파일명에서 확장자를 제거합니다.
        base_name = os.path.splitext(os.path.basename(image_path))[0]

        # 해당 이미지의 라벨 파일 경로를 생성합니다.
        label_path = os.path.join(label_dir, base_name + '.txt')

        if not os.path.exists(label_path):
            print(f"라벨 파일이 없습니다: {label_path}")
            continue

        # 라벨 파일을 읽습니다.
        with open(label_path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            # 각 라인은 'class_id center_x center_y width height' 형식입니다.
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 5:
                print(f"잘못된 라벨 형식입니다 ({label_path}): {line}")
                continue

            class_id, x_center, y_center, w, h = parts

            # 문자열을 숫자로 변환합니다.
            class_id = int(class_id)
            x_center = float(x_center)
            y_center = float(y_center)
            w = float(w)
            h = float(h)

            # 좌표를 이미지 크기에 맞게 변환합니다.
            x_center *= width
            y_center *= height
            w *= width
            h *= height

            # 바운딩 박스의 좌상단 좌표와 우하단 좌표를 계산합니다.
            x1 = int(x_center - w / 2)
            y1 = int(y_center - h / 2)
            x2 = int(x_center + w / 2)
            y2 = int(y_center + h / 2)

            # 바운딩 박스를 그립니다.
            color = (0, 255, 0)  # 녹색
            cv2.rectangle(image, (x1, y1), (x2, y2), color, 2)

            # 클래스 ID를 표시합니다.
            cv2.putText(image, str(class_id), (x1, y1 - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.9, color, 2)

        # 결과 이미지를 저장합니다.
        output_path = os.path.join(output_dir, base_name + '_labeled.jpg')
        cv2.imwrite(output_path, image)
        print(f"라벨이 적용된 이미지를 저장했습니다: {output_path}")

# 사용 예시:
visualize_yolo_labels('./SampleFile', './SampleFile', './SampleFile')

import json
import os
from typing import Dict, List, Tuple


def load_json(file_path: str) -> Dict:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def convert_bbox_to_yolo(bbox: List[float], img_width: int, img_height: int) -> List[float]:
    x, y, w, h = bbox
    return [
        (x + w / 2) / img_width,  # center x
        (y + h / 2) / img_height,  # center y
        w / img_width,  # width
        h / img_height  # height
    ]


def convert_polygon_to_yolo(polygon: List[float], img_width: int, img_height: int) -> List[float]:
    # For simplicity, we'll use the bounding box of the polygon
    x_coords = polygon[::2]
    y_coords = polygon[1::2]
    x_min, x_max = min(x_coords), max(x_coords)
    y_min, y_max = min(y_coords), max(y_coords)
    w, h = x_max - x_min, y_max - y_min
    return convert_bbox_to_yolo([x_min, y_min, w, h], img_width, img_height)


def create_yolo_txt(json_data: Dict, output_path: str):
    img_width, img_height = json_data['resolution']
    annotations = json_data.get('annotation', [])

    with open(output_path, 'w') as f:
        for anno in annotations:
            class_id = anno['class_ID']
            if anno['type'] == 'box':
                yolo_format = convert_bbox_to_yolo(anno['Bbox'], img_width, img_height)
            elif anno['type'] == 'polygon':
                yolo_format = convert_polygon_to_yolo(anno['polygon'], img_width, img_height)
            else:
                continue
            f.write(f"{class_id} {' '.join(map(str, yolo_format))}\n")


def create_yolact_label(json_data: Dict, output_path: str):
    annotations = json_data.get('annotation', [])

    with open(output_path, 'w') as f:
        json.dump({
            'num_classes': len(set(anno['class_ID'] for anno in annotations)),
            'classes': list(set(anno['class_ID'] for anno in annotations)),
            'annotations': [
                {
                    'bbox': anno['Bbox'] if anno['type'] == 'box' else None,
                    'polygon': anno['polygon'] if anno['type'] == 'polygon' else None,
                    'category_id': anno['class_ID']
                }
                for anno in annotations
            ]
        }, f, indent=2)


def process_json_file(json_file: str, output_dir: str):
    json_data = load_json(json_file)
    base_name = os.path.splitext(os.path.basename(json_file))[0]

    # Create YOLO txt file
    yolo_output = os.path.join(output_dir, f"{base_name}_yolo.txt")
    create_yolo_txt(json_data, yolo_output)

    # Create Yolact label file
    yolact_output = os.path.join(output_dir, f"{base_name}_yolact.json")
    create_yolact_label(json_data, yolact_output)


def main():
    input_dir = 'path/to/json/files'  # JSON 파일들이 있는 디렉토리 경로
    output_dir = 'path/to/output'  # 출력 파일들을 저장할 디렉토리 경로

    os.makedirs(output_dir, exist_ok=True)

    for filename in os.listdir(input_dir):
        if filename.endswith('.json'):
            json_file = os.path.join(input_dir, filename)
            process_json_file(json_file, output_dir)


if __name__ == "__main__":
    main()
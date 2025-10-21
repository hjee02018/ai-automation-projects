import pandas as pd
import os
import json
import shutil
from tqdm import tqdm

"""클래스를 매핑합니다.*
클래스 ID 0에서 27까지는 WO와 SO로 나누어 매핑하고, ID 28에서 40까지는 UA로 매핑하며, UC 클래스는 ID 41에서 55까지 매핑하고 총 56개 클래스를 포함하고 있습니다."""



# ORIGINAL_DATASET_PATH = r'F:\Warehouse_Total_Dataset\01.Data\1.Training\원천데이터'
# ORIGINAL_DATASET_LABEL_PATH = r'F:\Warehouse_Total_Dataset\01.Data\1.Training\라벨링데이터'
ORIGINAL_DATASET_PATH = r'F:\Warehouse_Total_Dataset\01.Data\2.Validation\원천데이터'
ORIGINAL_DATASET_LABEL_PATH = r'F:\Warehouse_Total_Dataset\01.Data\2.Validation\라벨링데이터'

# TRAIN_DATASET_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\train'
# TRAIN_DATASET_IMAGE_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\train\images'
# TRAIN_DATASET_LABEL_BBOX_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\train\labels'
# TRAIN_DATASET_LABEL_POLYGON_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\train\labels_polygon'
TRAIN_DATASET_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\val'
TRAIN_DATASET_IMAGE_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\val\images'
TRAIN_DATASET_LABEL_BBOX_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\val\labels'
TRAIN_DATASET_LABEL_POLYGON_PATH = r'C:\Users\dldjw\OneDrive\바탕 화면\HMX AI Contest\Train Dataset(min 500 instances per class)\val\labels_polygon'


EXTRACTION_LIST_PATH = r'.\sampled_dataset_val_100.xlsx'  # 복사해서 Train Dataset으로 옮길 Sampling 진행된 데이터 List. 파일 명과 상대경로 열이 작성되어 있음.




def CopyTrainImagesToTrainDatasetFolder():
    # 데이터 로드
    data = pd.read_excel(EXTRACTION_LIST_PATH)

    # 로그 변수 초기화
    total_files = len(data)
    copied_files = 0
    missing_files = 0
    missing_files_list = []

    # 대상 디렉토리가 없으면 생성
    os.makedirs(TRAIN_DATASET_IMAGE_PATH, exist_ok=True)

    # tqdm 적용하여 진행 상황 표시
    for index, row in tqdm(data.iterrows(), total=total_files, desc='Copying files'):
        name = row['Name']
        directory = row['Directory']

        # 'TL_'를 'TS_'로 변경하여 이미지 경로 수정
        # corrected_directory = directory.replace('TL_', 'TS_')
        corrected_directory = directory.replace('VL_', 'VS_')


        # 소스 파일 경로 생성
        source_path = os.path.join(ORIGINAL_DATASET_PATH, corrected_directory, name)

        # 대상 파일 경로 생성 (디렉토리 구조 없이 파일만 복사)
        destination_path = os.path.join(TRAIN_DATASET_IMAGE_PATH, name)

        # 파일 복사
        try:
            if os.path.exists(source_path):
                shutil.copy2(source_path, destination_path)
                copied_files += 1
            else:
                missing_files += 1
                missing_files_list.append(source_path)
        except Exception as e:
            missing_files += 1
            missing_files_list.append(source_path)
            print(f'Failed to copy {source_path}: {e}')

    # 로그 출력
    print(f'\nTotal files to copy: {total_files}')
    print(f'Successfully copied files: {copied_files}')
    print(f'Missing files: {missing_files}')
    if missing_files > 0:
        print('\nList of missing files:')
        for file in missing_files_list:
            print(file)
        print("Missing file list end, total : {}".format(len(missing_files_list)))

CopyTrainImagesToTrainDatasetFolder()

#240925 : sampled_dataset_500.xlsx 파일로 실행한 결과 Missing file list end, total : 1053
#이 List 는 TRAIN_DATASET_PATH 폴더에 CopyLog.txt로 기록해둠.

# Define the classes in the specified order
WO_classes = sorted([
    'WO-01', 'WO-02', 'WO-03', 'WO-04', 'WO-05', 'WO-06', 'WO-07', 'WO-08'
])
SO_classes = sorted([
    'SO-01', 'SO-02', 'SO-03', 'SO-06', 'SO-07', 'SO-08', 'SO-09', 'SO-10', 'SO-11', 'SO-12',
    'SO-13', 'SO-14', 'SO-15', 'SO-16', 'SO-17', 'SO-18', 'SO-19', 'SO-21', 'SO-22', 'SO-23'
])
UA_classes = sorted([
    'UA-01', 'UA-02', 'UA-03', 'UA-04', 'UA-05', 'UA-06', 'UA-10', 'UA-12', 'UA-13', 'UA-14',
    'UA-16', 'UA-17', 'UA-20'
])
UC_classes = sorted([
    'UC-02', 'UC-06', 'UC-08', 'UC-09', 'UC-10', 'UC-13', 'UC-14', 'UC-15', 'UC-16', 'UC-17',
    'UC-18', 'UC-19', 'UC-20', 'UC-21', 'UC-22'
])

# Combine all classes in the specified order
classes = WO_classes + SO_classes + UA_classes + UC_classes

# Create a mapping from class names to integer IDs
class_name_to_id = {class_name: idx for idx, class_name in enumerate(classes)}


def CopyTrainLabelsToTrainDatasetFolder():
    # Load the data
    data = pd.read_excel(EXTRACTION_LIST_PATH)

    # Initialize log variables
    total_files = len(data)
    processed_files = 0
    missing_files = 0
    missing_files_list = []

    # Create target directories if they don't exist
    os.makedirs(TRAIN_DATASET_LABEL_BBOX_PATH, exist_ok=True)
    os.makedirs(TRAIN_DATASET_LABEL_POLYGON_PATH, exist_ok=True)

    # Process each file
    for index, row in tqdm(data.iterrows(), total=total_files, desc='Processing label files'):
        name = row['Name']
        directory = row['Directory']

        # Change the extension to .json to get the label file name
        label_name = os.path.splitext(name)[0] + '.json'

        # # Replace 'TS_' with 'TL_' to correct the label directory path
        # corrected_directory = directory.replace('TS_', 'TL_')

        # Construct the source label file path
        source_label_path = os.path.join(ORIGINAL_DATASET_LABEL_PATH, directory, label_name)

        # Check if the label file exists
        if not os.path.exists(source_label_path):
            missing_files += 1
            missing_files_list.append(source_label_path)
            continue  # Skip to the next file

        try:
            # Convert JSON label file to YOLO format and save
            convert_json_to_yolo(
                json_file=source_label_path,
                output_dir_bbox=TRAIN_DATASET_LABEL_BBOX_PATH,
                output_dir_polygon=TRAIN_DATASET_LABEL_POLYGON_PATH,
                image_name=os.path.splitext(name)[0]  # Pass the image name
            )
            processed_files += 1
        except Exception as e:
            missing_files += 1
            missing_files_list.append(source_label_path)
            print(f'Failed to process {source_label_path}: {e}')

    # Print the log
    print(f'\nTotal label files to process: {total_files}')
    print(f'Successfully processed label files: {processed_files}')
    print(f'Missing or failed label files: {missing_files}')
    if missing_files > 0:
        print('\nList of missing or failed label files:')
        # for file in missing_files_list:
        #     print(file)
        print("Missing file list end, total : {}".format(len(missing_files_list)))

# Function to convert JSON label files to YOLO format
def convert_json_to_yolo(json_file, output_dir_bbox, output_dir_polygon, image_name):
    # Load the JSON data
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Extract image resolution
    img_width, img_height = data["Raw data Info."]["resolution"]

    # Get the list of annotations
    annotations = data["Learning data info."]["annotation"]

    # Output files for bounding boxes and polygons
    bbox_output_file = os.path.join(output_dir_bbox, f"{image_name}.txt")
    polygon_output_file = os.path.join(output_dir_polygon, f"{image_name}.txt")

    with open(bbox_output_file, 'w', encoding='utf-8') as bbox_file, \
            open(polygon_output_file, 'w', encoding='utf-8') as polygon_file:
        for ann in annotations:
            # Get the class name and map it to the integer ID
            class_name = ann['class_id']  # Assuming 'class_name' is available in the JSON
            if class_name not in class_name_to_id:
                print(f"Class name '{class_name}' not found in class mapping.")
                continue  # Skip annotations with unknown classes
            class_id = class_name_to_id[class_name]

            # Process bounding boxes
            if ann['type'] == 'box':
                bbox = ann['coord']
                x_center, y_center, width, height = convert_bbox_to_yolo_format(bbox, img_width, img_height)
                bbox_file.write(f"{class_id} {x_center} {y_center} {width} {height}\n")

            # Process polygons
            elif ann['type'] == 'polygon':
                polygon = ann['coord']
                normalized_polygon = convert_polygon_to_yolo_format(polygon, img_width, img_height)
                polygon_file.write(f"{class_id} {normalized_polygon}\n")


# Utility function to convert bounding box coordinates into YOLO format
def convert_bbox_to_yolo_format(bbox, img_width, img_height):
    x_min, y_min, bbox_width, bbox_height = bbox
    x_center = (x_min + bbox_width / 2) / img_width
    y_center = (y_min + bbox_height / 2) / img_height
    norm_width = bbox_width / img_width
    norm_height = bbox_height / img_height
    return x_center, y_center, norm_width, norm_height


# Utility function to convert polygon coordinates into normalized YOLO format
def convert_polygon_to_yolo_format(polygon, img_width, img_height):
    normalized_polygon = []
    for point in polygon:
        x, y = point
        normalized_x = x / img_width
        normalized_y = y / img_height
        normalized_polygon.append(f"{normalized_x} {normalized_y}")
    return " ".join(normalized_polygon)


# Generate the YAML file for YOLOv8
def generate_yaml_file(yaml_path):
    yaml_content = {
        'path': TRAIN_DATASET_PATH,
        'train': 'images',
        'val': 'images',  # Update if you have a separate validation set
        'test': 'images',  # Update if you have a separate test set
        'names': classes
    }
    import yaml
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_content, f, allow_unicode=True)
    print(f"YAML file generated at: {yaml_path}")


# Run the functions
CopyTrainLabelsToTrainDatasetFolder()
generate_yaml_file(os.path.join(TRAIN_DATASET_PATH, 'data_val.yaml'))
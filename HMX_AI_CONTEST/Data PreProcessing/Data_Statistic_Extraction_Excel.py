import os
import json
import pandas as pd
from tqdm import tqdm
from collections import defaultdict
import random

# 데이터셋 경로 설정
DATASET_DIR = r'F:\Warehouse_Total_Dataset\01.Data\2.Validation\라벨링데이터'

# JSON 파일이 저장된 경로를 리스트로 저장
json_file_paths = []

for root, dirs, files in os.walk(DATASET_DIR):
    for file in files:
        if file.lower().endswith('.json'):
            json_file_paths.append(os.path.join(root, file))

print(f"총 {len(json_file_paths)}개의 JSON 파일을 발견했습니다.")

# 통계 정보를 저장할 변수들 초기화
image_stats = []
class_counts = defaultdict(int)
video_stats = defaultdict(lambda: {'이미지 수': 0, '객체 수': 0, '바운딩 박스 수': 0, '세그멘테이션 수': 0})
class_video_counts = defaultdict(lambda: defaultdict(int))  # 영상별 클래스 객체 수


# 영상 식별자를 추출하기 위한 함수
def get_video_id(filename):
    # 파일 확장자 제거
    filename = os.path.splitext(filename)[0]
    # 마지막 언더바 이전까지 추출
    parts = filename.rsplit('_', 1)
    if len(parts) == 2:
        video_id = parts[0]
    else:
        video_id = filename
    return video_id


# JSON 파일들을 순회하며 데이터 수집
for json_file in tqdm(json_file_paths, desc='Processing JSON files'):
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except UnicodeDecodeError:
        # 다른 인코딩 시도
        with open(json_file, 'r', encoding='cp949') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {json_file}: {e}")
        continue

    # 이미지 파일명 추출
    source_data_info = data.get('Source data Info.', {})
    image_filename = source_data_info.get('source_data_ID', '') + '.' + source_data_info.get('file_extension', '')

    if not image_filename:
        continue  # 이미지 파일명이 없으면 건너뜁니다.

    # 영상 식별자 추출
    video_id = get_video_id(image_filename)

    # 어노테이션 정보 추출
    learning_data_info = data.get('Learning data info.', {})
    annotations = learning_data_info.get('annotation', [])

    num_objects = len(annotations)
    num_bboxes = 0
    num_segmentations = 0

    for ann in annotations:
        class_id = ann.get('class_id', '')
        if class_id:
            class_counts[class_id] += 1
            class_video_counts[video_id][class_id] += 1  # 클래스별 영상 내 객체 수 증가

        ann_type = ann.get('type', '')
        if ann_type == 'box':
            num_bboxes += 1
        elif ann_type == 'polygon':
            num_segmentations += 1

    # 이미지별 통계 저장
    image_stats.append({
        '영상 식별자': video_id,
        '이미지 파일명': image_filename,
        '총 객체 수': num_objects,
        '바운딩 박스 수': num_bboxes,
        '세그멘테이션 수': num_segmentations,
    })

    # 영상별 통계 업데이트
    video_stats[video_id]['이미지 수'] += 1
    video_stats[video_id]['객체 수'] += num_objects
    video_stats[video_id]['바운딩 박스 수'] += num_bboxes
    video_stats[video_id]['세그멘테이션 수'] += num_segmentations

# 클래스 ID가 없는 경우 제거
class_counts = {k: v for k, v in class_counts.items() if k}

# 영상별 통계를 DataFrame으로 변환
video_stats_list = []
class_ids = sorted(class_counts.keys())  # 클래스 ID 정렬

for video_id, stats in video_stats.items():
    row = {
        '영상 식별자': video_id,
        '이미지 수': stats['이미지 수'],
        '객체 수': stats['객체 수'],
        '바운딩 박스 수': stats['바운딩 박스 수'],
        '세그멘테이션 수': stats['세그멘테이션 수'],
    }
    # 각 클래스별 객체 수를 열에 추가
    for class_id in class_ids:
        row[class_id] = class_video_counts[video_id].get(class_id, 0)

    video_stats_list.append(row)

# 최종 DataFrame 생성
video_stats_df = pd.DataFrame(video_stats_list)

# 결과를 Excel 파일로 저장
with pd.ExcelWriter('Statistic(데이터 통계 분석)/validation_dataset_statistics_with_classes.xlsx') as writer:
    # 영상별 통계 저장
    video_stats_df.to_excel(writer, sheet_name='영상별 통계', index=False)

print('클래스별 통계를 포함한 영상별 통계가 dataset_statistics_with_classes.xlsx 파일에 저장되었습니다.')

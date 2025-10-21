import os
import json
import pandas as pd
import numpy as np
from collections import defaultdict
from tqdm import tqdm
import logging
from datetime import datetime

# 로깅 설정
logging.basicConfig(filename='LogData/sampling_log_val_100.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 필요한 파일들을 읽어옵니다.
chunk_data = pd.read_excel('Chunk별_이미지수와_각_Class개수_Validation.xlsx', index_col='영상 식별자 (Chunk)')

# '전체_데이터셋의_Class개수합.xlsx' 파일을 읽어옵니다.
total_class_counts = pd.read_excel('전체_데이터셋의_Class개수합_Validation.xlsx', index_col='Class')

# 'Count' 열의 데이터를 숫자로 변환합니다.
total_class_counts['Count'] = pd.to_numeric(total_class_counts['Count'], errors='coerce')

# 변환 중 발생한 NaN 값을 제거합니다.
total_class_counts = total_class_counts.dropna()

# Class 우선순위를 결정합니다. SO-05는 제외합니다.
class_priority = total_class_counts[total_class_counts.index != 'SO-05'].sort_values('Count').index.tolist()


def get_chunk_id(filename):
    """파일 이름에서 Chunk ID를 추출합니다."""
    parts = filename.split('_')
    return '_'.join(parts[:-1])


def get_chunk_priority(chunk_id, class_name):
    """특정 클래스에 대한 Chunk의 우선순위를 반환합니다."""
    if chunk_id not in chunk_data.index or class_name not in chunk_data.columns:
        return float('inf')  # 정보가 없는 경우 가장 낮은 우선순위
    return chunk_data.loc[chunk_id, class_name]


# 샘플링 함수를 정의합니다.
def sample_images(directory, target_samples=100):
    sampled_images = defaultdict(int)
    sampled_data = []

    # JSON 파일 경로를 모두 찾아 Chunk별로 정리합니다.
    chunk_files = defaultdict(list)
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.json'):
                chunk_id = get_chunk_id(file)
                chunk_files[chunk_id].append(os.path.join(root, file))

    total_files = sum(len(files) for files in chunk_files.values())
    logging.info(f"총 {total_files}개의 JSON 파일을 발견했습니다.")
    print(f"총 {total_files}개의 JSON 파일을 발견했습니다.")

    # 클래스 우선순위에 따라 처리
    for class_name in tqdm(class_priority, desc="Processing classes"):
        if sampled_images[class_name] >= target_samples:
            logging.info(f"{class_name}: 이미 목표 샘플 수에 도달했습니다. 다음 클래스로 넘어갑니다.")
            continue

        logging.info(f"{class_name} 클래스 처리 시작")
        print(f"\n{class_name} 클래스 처리 중...")

        # Chunk 우선순위 결정
        chunk_priority = sorted(chunk_files.keys(), key=lambda x: get_chunk_priority(x, class_name))

        for chunk_id in tqdm(chunk_priority, desc=f"Processing chunks for {class_name}", leave=False):
            if sampled_images[class_name] >= target_samples:
                logging.info(f"{class_name}: 목표 샘플 수에 도달했습니다. 다음 클래스로 넘어갑니다.")
                break

            logging.info(f"Chunk {chunk_id} 처리 시작")
            for json_file in tqdm(chunk_files[chunk_id], desc=f"Processing files in chunk {chunk_id}", leave=False):
                try:
                    # UTF-8로 먼저 시도하고, 실패하면 cp949로 시도합니다.
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                    except UnicodeDecodeError:
                        with open(json_file, 'r', encoding='cp949') as f:
                            data = json.load(f)

                    # JSON 구조 확인
                    if 'Learning data info.' not in data or 'annotation' not in data['Learning data info.']:
                        continue

                    annotations = data['Learning data info.']['annotation']
                    image_classes = set(ann['class_id'] for ann in annotations if 'class_id' in ann)

                    if class_name in image_classes and sampled_images[class_name] < target_samples:
                        jpg_file = data['Source data Info.']['source_data_ID'] + '.' + data['Source data Info.'][
                            'file_extension']
                        class_counts = {cls: sum(1 for ann in annotations if ann.get('class_id') == cls) for cls in
                                        class_priority}

                        # 상대 경로 계산
                        rel_path = os.path.relpath(os.path.dirname(json_file), directory)

                        row = [jpg_file] + [class_counts.get(cls, 0) for cls in class_priority] + [rel_path]
                        sampled_data.append(row)

                        # 모든 클래스에 대해 누적 집계
                        for cls in class_priority:
                            sampled_images[cls] += class_counts.get(cls, 0)

                        logging.info(f"Sampled image for {class_name}: {jpg_file}, Path: {rel_path}")

                        if sampled_images[class_name] >= target_samples:
                            logging.info(f"{class_name}: 목표 샘플 수에 도달했습니다.")
                            break

                except Exception as e:
                    logging.error(f"Error processing file {json_file}: {str(e)}")

            logging.info(f"Chunk {chunk_id} 처리 완료")

        logging.info(f"{class_name} 클래스 처리 완료. 현재 샘플 수: {sampled_images[class_name]}")
        print(f"{class_name} 클래스 처리 완료. 현재 샘플 수: {sampled_images[class_name]}")

    logging.info("샘플링된 이미지 수:")
    print("\n샘플링된 이미지 수:")
    for cls in class_priority:
        logging.info(f"{cls}: {sampled_images[cls]}")
        print(f"{cls}: {sampled_images[cls]}")

    return pd.DataFrame(sampled_data, columns=['파일명.jpg'] + class_priority + ['디렉토리 경로'])


# 메인 실행 코드
if __name__ == "__main__":
    directory = r"F:\Warehouse_Total_Dataset\01.Data\2.Validation\라벨링데이터"  # JSON 파일들이 있는 디렉토리 경로를 지정하세요
    start_time = datetime.now()
    logging.info(f"샘플링 작업 시작: {start_time}")

    result_df = sample_images(directory)

    end_time = datetime.now()
    logging.info(f"샘플링 작업 종료: {end_time}")
    logging.info(f"총 소요 시간: {end_time - start_time}")

    # 결과를 CSV 파일로 저장합니다.
    result_df.to_csv(r'sampled_dataset_100.csv', index=False)

    # 결과를 Excel 파일로 저장합니다.
    result_df.to_excel('sampled_dataset_100.xlsx', index=False)

    logging.info("샘플링이 완료되었습니다. 결과는 'sampled_dataset_100.csv'와 'sampled_dataset_1000.xlsx' 파일에 저장되었습니다.")
    logging.info(f"총 {len(result_df)} 개의 이미지가 샘플링되었습니다.")

    print("샘플링이 완료되었습니다. 결과는 'sampled_dataset_100.csv'와 'sampled_dataset_500.xlsx' 파일에 저장되었습니다.")
    print(f"총 {len(result_df)} 개의 이미지가 샘플링되었습니다.")
    print(f"총 소요 시간: {end_time - start_time}")
    print("자세한 로그는 'sampling_log.txt' 파일을 확인하세요.")
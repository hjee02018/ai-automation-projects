# Chunk 단위로 Analysis 하여 고르게 분포되었는지 확인하는 프로그램.
# Chunk 단위로 묶어, X축은 Class 명 / Y 축은 Chunk 명으로 Heatmap 을 Plot 시에 랜덤하게 분포되어 있다면 성공한 것임.
# 그렇지 않고 유독 한 Chunk 에 색깔이 밝고 나머지는 전부 0에 가깝다면 실패한것임.
# 이를 어느정도 시각적으로 확인하기 위해 만드는 프로그램
# 나중에 Total Dataset(532GB) JSON으로 그대로 슥 긁어 쓰는거 해서 (이건 Claude 대화 초기에 있음) 기존 대비 얼마나 좋아졌는지 비교하면 좋을듯?

import pandas as pd

# Load the data from the Excel file
file_path = '../Validation Sampled Dataset 200 for Statistic (Chunk).xlsx'  # 엑셀 파일 경로를 여기에 입력하세요.
data = pd.read_excel(file_path, index_col=0)  # 첫 번째 열을 인덱스(Chunk)로 사용

# Grouping by 'Chunk' and summing the attributes
chunk_sums = data.groupby(data.index).sum()

# Saving the summed data to a new Excel file
chunk_sums.to_excel('validation_chunk_sums.xlsx')

print("The summed data has been saved to 'validation_chunk_sums.xlsx'.")
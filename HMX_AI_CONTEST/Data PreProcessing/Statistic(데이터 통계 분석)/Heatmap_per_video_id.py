import pandas as pd
import plotly.express as px

# 엑셀 파일 읽기
df = pd.read_excel('chunk_sums.xlsx')

# '영상 식별자'를 인덱스로 설정
df.set_index('Chunk', inplace=True)

# 결측값을 0으로 채우기
df.fillna(0, inplace=True)

# 히트맵 생성
fig = px.imshow(
    df,
    labels=dict(x="Class ID", y="Chunk", color="값"),
    x=df.columns,
    y=df.index,
    color_continuous_scale='Viridis',
    aspect='auto'
)

# 레이아웃 업데이트 (화면 크기에 맞게 조정)
fig.update_layout(
    title='데이터 히트맵 - Sampled Data Chunk Sum / Class instances minimum Threshold : 500',
    width=1920,
    height=1080,
    xaxis_nticks=len(df.columns)
)

# X축 레이블 설정 (모든 항목이 보이도록)
fig.update_xaxes(
    tickangle=45,  # 레이블을 45도 기울여서 겹치지 않도록 함
    tickfont=dict(size=12),  # 글자 크기 조정
    automargin=True  # 레이블이 잘리지 않도록 여백 자동 조정
)

# Y축 레이블 설정 (필요에 따라 축소)
fig.update_yaxes(
    tickfont=dict(size=10),
    automargin=True
)

# 히트맵 표시
fig.show()

import pandas as pd
import numpy as np

# 데이터 로드
data = pd.read_excel('chunk_sums.xlsx', index_col=0)  # 첫 번째 열을 인덱스로 사용, Chunk 이름을 인덱스로 가정

# Chunk의 총 수 계산
num_chunks = len(data.index.unique())

# 각 Class ID에 대한 총 인스턴스 수 (최소 500개)
total_instances = 500

# 실제 각 Chunk에 분배될 인스턴스 수 계산
instances_per_chunk = total_instances / num_chunks

# 이상적인 엔트로피 값 계산
ideal_entropy = -num_chunks * (instances_per_chunk / total_instances) * np.log(instances_per_chunk / total_instances)

# 엔트로피 계산 함수 정의
def calculate_entropy(column):
    probabilities = column / column.sum()
    entropy = -np.sum(probabilities * np.log(probabilities + 1e-9))
    return entropy

# 각 Class_ID별로 엔트로피 계산
entropy_scores = data.apply(calculate_entropy)

# 결과 출력
print(f"Ideal Entropy: {ideal_entropy}")
print("Calculated Entropy Scores:")
print(entropy_scores)

# 각 Class_ID별로 지니 계수 계산
def calculate_gini(series):
    # 데이터를 1차원 배열로 변환
    array = series.values
    if np.amin(array) < 0:
        array = array - np.amin(array)  # 모든 값이 양수가 되도록 조정
    array = array + 0.0000001  # 0 값 방지를 위해 작은 수를 추가
    array_sorted = np.sort(array)  # 값들을 오름차순으로 정렬
    n = array_sorted.size
    index = np.arange(1, n + 1)  # 1부터 n까지의 인덱스 배열 생성
    # 지니 계수 계산
    return ((np.sum((2 * index - n - 1) * array_sorted)) / (n * np.sum(array_sorted)))

# 각 Class_ID별로 지니 계수 계산
gini_scores = data.apply(calculate_gini)

# 결과 출력
print("Calculated Gini Coefficients:")
print(gini_scores)

""" 실행 결과는 아래와 같음 """


"""C:\ProgramData\miniconda3\envs\py38\python.exe "C:\Users\EJ-LEE\PycharmProjects\HMX_AI_CONTEST\Data PreProcessing\Statistic(데이터 통계 분석)\Heatmap_per_video_id.py" 
Ideal Entropy: 5.5333894887275195
Calculated Entropy Scores:
SO-09    1.892691
SO-12    2.276680
UA-06    2.159177
UA-02    1.133226
UC-20    1.888530
UC-13    1.899389
UA-14    1.389870
UC-19    2.304300
UA-17    1.251126
UA-12    1.999326
UA-13    1.603964
UA-05    2.097008
UA-03    1.072249
UA-20    2.525582
SO-11    2.013520
SO-23    1.598153
UC-14    2.062242
UC-17    1.589592
WO-08    2.524480
SO-10    1.783993
UC-18    1.904793
UA-16    0.699893
UA-04    0.684933
SO-22    1.239134
SO-16    2.319970
UA-10    2.050220
UC-09    1.364507
UA-01    2.497765
UC-02    1.657448
UC-16    0.676859
UC-06    2.018422
UC-21    1.868574
UC-10    1.939010
UC-08    1.038112
UC-22    2.259929
UC-15    1.672760
SO-17    2.985680
SO-08    1.437634
SO-14    1.958864
SO-19    1.959855
WO-02    2.953677
WO-05    1.434062
SO-13    2.449574
WO-06    1.668829
WO-07    3.373947
SO-18    1.959032
SO-15    3.529156
SO-21    1.886924
WO-03    3.441949
SO-01    2.986484
SO-06    3.170962
WO-04    4.363529
SO-03    3.674189
SO-07    3.176475
WO-01    5.085604
SO-02    4.529657
dtype: float64
Calculated Gini Coefficients:
SO-09    0.977034
SO-12    0.965707
UA-06    0.971772
UA-02    0.988770
UC-20    0.977328
UC-13    0.976854
UA-14    0.986752
UC-19    0.966466
UA-17    0.987779
UA-12    0.975431
UA-13    0.981344
UA-05    0.972799
UA-03    0.989502
UA-20    0.956348
SO-11    0.975262
SO-23    0.982862
UC-14    0.972710
UC-17    0.982292
WO-08    0.956738
SO-10    0.978451
UC-18    0.976632
UA-16    0.992513
UA-04    0.992601
SO-22    0.988665
SO-16    0.966340
UA-10    0.975204
UC-09    0.985660
UA-01    0.961312
UC-02    0.982292
UC-16    0.992806
UC-06    0.974636
UC-21    0.979665
UC-10    0.976585
UC-08    0.989992
UC-22    0.969834
UC-15    0.981892
SO-17    0.934631
SO-08    0.987054
SO-14    0.976124
SO-19    0.976083
WO-02    0.940048
WO-05    0.987235
SO-13    0.963350
WO-06    0.983519
WO-07    0.907400
SO-18    0.976117
SO-15    0.896826
SO-21    0.980063
WO-03    0.902407
SO-01    0.939621
SO-06    0.925939
WO-04    0.763089
SO-03    0.880127
SO-07    0.927370
WO-01    0.499588
SO-02    0.718888
dtype: float64

종료 코드 0(으)로 완료된 프로세스
"""
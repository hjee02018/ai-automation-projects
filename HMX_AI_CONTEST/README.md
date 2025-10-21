# HMX_AI_CONTEST
라스베가스 갈 사람들의 Repo

프로젝트 설명 : 대형화 되는 물류센터, 창고 등 물류 관련 공간 내에서 발생하는 작업자들의 안전 사고 방지를 위한 서비스 개발  

○ 필요성
- 작업 현장의 높은 재해율 경감을 위해서는 그동안 전통적인 방법에서 탈피하여, IT를 활용한 근본적인 취약성 및 원인분
석 방법을 통한 개선이 필요함 - 작업 현장의 유해요인 및 작업자 행동 위험요인으로부터 근로자를 보호하기 위해서는 설비 등의 환경과 근로자 보호구
및 행동 패턴 등의 분석이 필요함 - 이러한 문제점 개선을 위해서는 사고예측, 시나리오, 위치정보, 위험설비 등 요소를 통한 시스템 구축이며, 최우선 개선
을 위해서 작업 현장의 데이터 정보화가 필요함

○ 추진목적
- 물류창고 내 사고 및 위험 발생 가능성을 사전 파악할 수 있도록 작업환경 안의 각 객체에 대한 정보를 기반으로 하
는 AI 학습용 데이터 구축
- 대형화 및 고밀도화되는 분야로서 현장 작업자들의 안전과 효율적인 작업을 책임질 수 있는 AI 서비스 제공
  
○ 기대효과
- 산업재해보상보험법에 가입된 창고 관련 사업장수 증가로 인해 각 물류창고 내 작업에 대한 안전과 산업재해로 인한
경제적 직간접 손실액 감소 추구
- 작업자의 행동과 위험 상황에 관한 분석의 자동화를 통해 사전 위험 요소 및 사고 예방
- 물류창고 내 각 객체에 대한 정보를 활용한 AI 응용서비스로 안전한 작업현장 형성과 작업 효율 증대 


[백엔드]
language : python  
framework :  Flask  
api : ...ing (restful api)  
서버 : nginx or apache  
형상관리 : git  
ide : VSCODE  

  
[AI 모델]  
커스템 데이터셋 : https://www.aihub.or.kr/aihubdata/data/view.do?currMenu=115&topMenu=100&dataSetSn=510  
모델 아키텍처 : YOLOv8m or YOLOv8l  
  
모델 상세(ultralytics git 발췌) :  
scales: # model compound scaling constants, i.e. 'model=yolov8n.yaml' will call yolov8.yaml with scale 'n'
  
[depth, width, max_channels]  
m: [0.67, 0.75, 768] # YOLOv8m summary: 295 layers, 25902640 parameters, 25902624 gradients,  79.3 GFLOPs  
l: [1.00, 1.00, 512] # YOLOv8l summary: 365 layers, 43691520 parameters, 43691504 gradients, 165.7 GFLOPs

[DB]  
DATABASE : ORACLE  
SCHEMA   : HMX_AI  
TABLE    : T_HIST  
COLUMN   : [  
      "ID_T_HIST", "X1", "Y1", "X2", "Y2", "CONFIDENCE", "CLASS_LABEL",   
      "TRACKING_ID", "CENTER_X", "CENTER_Y", "WIDTH", "HEIGHT", "X1_NORM",   
      "Y1_NORM", "X2_NORM", "Y2_NORM", "WIDTH_NORM", "HEIGHT_NORM",   
      "REG_DATE", "REG_TIME", "REG_ID", "CHG_DATE", "CHG_TIME", "CHG_ID"  
     ]  


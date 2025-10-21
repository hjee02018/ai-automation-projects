import cx_Oracle
from db import get_db_connection
import base64
import requests
from datetime import datetime, timedelta
from flask_socketio import SocketIO
from ultralytics import YOLO

# Flask SocketIO 초기화
socketio = SocketIO(cors_allowed_origins="*")
custom_model = YOLO("file/500_100_sample_yolov8l.pt") 

class SkipInsertException(Exception):
    """데이터 삽입을 건너뛰기 위한 예외."""
    pass

class HistModel:
    # 모든 HIST 가져오기
    @staticmethod
    def get_all_hists():
        connection = get_db_connection()
        cursor = connection.cursor()

        query = "SELECT * FROM HMX_AI.T_HIST T ORDER BY TO_DATE(T.REG_DATE || ' ' || T.REG_TIME, 'YYYY-MM-DD HH24:MI:SS') DESC"
        cursor.execute(query)

        result = cursor.fetchall()
        columns = [col[0] for col in cursor.description]  # 컬럼 이름 추출

        connection.close()

        formatted_result = []
        for row in result:
            row_dict = dict(zip(columns, row))
            # 각 row에서 bytes 타입을 처리
            for key, value in row_dict.items():
                if isinstance(value, bytes):
                    try:
                        # bytes를 utf-8로 디코딩
                        row_dict[key] = value.decode('utf-8')
                    except UnicodeDecodeError:
                        # 만약 utf-8로 디코딩할 수 없다면 Base64로 인코딩
                        row_dict[key] = base64.b64encode(value).decode('utf-8')
            formatted_result.append(row_dict)

        return formatted_result
    
    # 최신 10개의 HIST 가져오기
    @staticmethod
    def get_latest_hists(limit):
        connection = get_db_connection()
        cursor = connection.cursor()

        query = f"SELECT T.CCTV_NO, T.CLASS_LABEL, T.REG_DATE, T.REG_TIME FROM HMX_AI.T_HIST T ORDER BY TO_DATE(T.REG_DATE || ' ' || T.REG_TIME, 'YYYY-MM-DD HH24:MI:SS') DESC FETCH FIRST {limit} ROWS ONLY"
        cursor.execute(query)

        result = cursor.fetchall()
        columns = [col[0] for col in cursor.description]  # 컬럼 이름 추출

        connection.close()

        formatted_result = []
        for row in result:
            row_dict = dict(zip(columns, row))
            
            for key, value in row_dict.items():
                if isinstance(value, bytes):
                    try:
                        
                        row_dict[key] = value.decode('utf-8')
                    except UnicodeDecodeError:
                        
                        row_dict[key] = base64.b64encode(value).decode('utf-8')
            formatted_result.append(row_dict)

        return formatted_result

    # CLASS_LABEL 그룹화하여 COUNT 값 가져오기
    @staticmethod
    def get_class_counts():
        connection = get_db_connection()
        cursor = connection.cursor()

        query = """
        SELECT CLASS_LABEL, COUNT(*) AS COUNT
        FROM HMX_AI.T_HIST
        GROUP BY CLASS_LABEL
        ORDER BY COUNT DESC
        """
        cursor.execute(query)

        result = cursor.fetchall()
        columns = [col[0] for col in cursor.description]  # 컬럼 이름 추출

        connection.close()

        formatted_result = []
        for row in result:
            row_dict = dict(zip(columns, row))
            formatted_result.append(row_dict)

        return formatted_result
    
    @staticmethod
    def insert_detection_to_hist(detection):
        connection = None  # Initialize connection
        cursor = None  #
        try:
             # UA 또는 UC로 시작하는지 확인
            custom_class_name = detection['class_name']
            
            if not (custom_class_name.startswith('UA') or custom_class_name.startswith('UC') or custom_class_name.startswith('SO') or custom_class_name.startswith('WO')):
                raise ValueError(f"Invalid class_name: {custom_class_name}")  # 예외 발생
            
            # if custom_class_name.startswith('SO') or custom_class_name.startswith('WO'):
            #     raise SkipInsertException(f"Skipping insert for class_name: {custom_class_name}")


            detection_time = datetime.now()
            reg_date = detection_time.strftime("%Y-%m-%d")  # REG_DATE (날짜)
            reg_time = detection_time.strftime("%H:%M:%S")  # REG_TIME (시간)

            connection = get_db_connection()
            cursor = connection.cursor()

             # class_name으로 최근 데이터 조회
            select_query = """
            SELECT REG_DATE, REG_TIME 
            FROM HMX_AI.T_HIST 
            WHERE CLASS_LABEL = :class_name
            ORDER BY REG_DATE DESC, REG_TIME DESC
            """
            cursor.execute(select_query, {'class_name': custom_class_name})
            recent_row = cursor.fetchone()

            if recent_row:
                last_reg_date = recent_row[0]  # REG_DATE
                last_reg_time = recent_row[1]  # REG_TIME
                last_detection_time = datetime.strptime(f"{last_reg_date} {last_reg_time}", "%Y-%m-%d %H:%M:%S")
                
                if (detection_time - last_detection_time).total_seconds() < 10:
                    raise ValueError(f"Data for class_name '{custom_class_name}' was inserted within the last 5 minutes.")

            insert_query = """
            INSERT INTO HMX_AI.T_HIST 
            (CCTV_NO, X1, Y1, X2, Y2, CLASS_LABEL, CONFIDENCE, REG_DATE, REG_TIME) 
            VALUES (:cctv_no, :x1, :y1, :x2, :y2, :class_name, :confidence, :reg_date, :reg_time)
            """

            # 데이터 삽입 실행
            cursor.execute(insert_query, {
                'x1': detection['x1'],
                'y1': detection['y1'],
                'x2': detection['x2'],
                'y2': detection['y2'],
                'cctv_no': 1,
                'class_name': custom_class_name,
                'confidence': detection['confidence'],
                'reg_date': reg_date,
                'reg_time': reg_time
            })

            detection_timestamp = f"{reg_date} {reg_time}"

            connection.commit()

            # 데이터가 삽입된 후 클라이언트에 알림
            requests.post('http://127.0.0.1:5000/send-notification', json={
                'cctv_no': 1, 
                'class_name': custom_class_name, 
                'time': detection_timestamp
            })
            
        except SkipInsertException:
            # SO 또는 WO로 시작하는 클래스에 대해 삽입 건너뛰기
            pass
        except ValueError as ve:
            # 시간 차이가 5분 이내이거나 class_name이 유효하지 않은 경우
            print(f"Error: {ve}")
        
        except Exception as e:
            # 기타 예외 처리
            print(f"Error inserting detections: {e}")
        finally:
            if cursor is not None:
                cursor.close()
            if connection is not None:
                connection.close()

    @staticmethod
    def send_socket_notification(detection):
        try:
            custom_class_name = detection['class_name']
            
            # class_name이 UA, UC, SO, WO로 시작하는지 확인
            if not (custom_class_name.startswith('UA') or custom_class_name.startswith('UC') or 
                    custom_class_name.startswith('SO') or custom_class_name.startswith('WO')):
                raise ValueError(f"Invalid class_name: {custom_class_name}")
            
            if custom_class_name.startswith('SO') or custom_class_name.startswith('WO'):
                raise SkipInsertException(f"Skipping insert for class_name: {custom_class_name}")
            
            # 알림을 위한 타임스탬프 생성
            detection_time = datetime.now()
            reg_date = detection_time.strftime("%Y-%m-%d")
            reg_time = detection_time.strftime("%H:%M:%S")
            detection_timestamp = f"{reg_date} {reg_time}"

            # 소켓 알림 전송
            requests.post('http://127.0.0.1:5000/send-notification', json={
                'cctv_no': detection.get('cctv_no', 1),  # CCTV 번호 (기본값 1)
                'class_name': custom_class_name,
                'time': detection_timestamp
            })

        except ValueError as ve:
            # 유효하지 않은 class_name 예외 처리
            print(f"Error: {ve}")
        except Exception as e:
            # 기타 예외 처리
            print(f"Error sending socket notification: {e}")


    
    @staticmethod
    def get_filtered_hist_counts(selected_cctv, selected_start_date, selected_end_date, selected_event_name):
        connection = get_db_connection()
        cursor = connection.cursor()

        # Base query for getting the count grouped by CLASS_LABEL
        query = """
        SELECT CCTV_NO, CLASS_LABEL, COUNT(*) AS COUNT
        FROM HMX_AI.T_HIST
        WHERE 1 = 1
        """

        # Add filters based on the provided parameters
        params_dict = {}
        
        if selected_cctv is not None:
            query += " AND CCTV_NO = :cctv_id"
            params_dict['cctv_id'] = selected_cctv

        if selected_start_date and selected_end_date:
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = selected_start_date
            params_dict['end_date'] = selected_end_date
        elif selected_start_date and not selected_end_date:
            # If start date is present but no end date, set end date to 1 week after start date
            end_date = (datetime.strptime(selected_start_date, "%Y-%m-%d") + timedelta(days=7)).strftime("%Y-%m-%d")
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = selected_start_date
            params_dict['end_date'] = end_date
        elif not selected_start_date and selected_end_date:
            # If end date is present but no start date, set start date to 1 week before end date
            start_date = (datetime.strptime(selected_end_date, "%Y-%m-%d") - timedelta(days=7)).strftime("%Y-%m-%d")
            query += " AND TO REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = start_date
            params_dict['end_date'] = selected_end_date
        else:
            # If no dates provided, use the current date and 1 week before
            end_date = datetime.now().strftime("%Y-%m-%d")
            start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = start_date
            params_dict['end_date'] = end_date
        # Handle event name selection, or group by event if null
        if selected_event_name is not None:
            query += " AND CLASS_LABEL = :class_label"
            params_dict['class_label'] = selected_event_name

        # Add GROUP BY and ORDER BY clauses
        query += " GROUP BY CCTV_NO, CLASS_LABEL ORDER BY COUNT DESC FETCH FIRST 5 ROWS ONLY"

        # Execute query with parameters
        cursor.execute(query, params_dict)
        result = cursor.fetchall()

        class_query = """
        SELECT SUBSTR(CLASS_LABEL, 1, 2) AS CLASS, COUNT(*) AS COUNT
        FROM HMX_AI.T_HIST
        WHERE 1 = 1
        """
        if selected_cctv is not None:
            class_query += " AND CCTV_NO = :cctv_id"

        class_query += " AND REG_DATE BETWEEN :start_date AND :end_date"
        class_query += " GROUP BY SUBSTR(CLASS_LABEL, 1, 2)"

        cursor.execute(class_query, params_dict)
        class_result = cursor.fetchall()

        connection.close()

        # Format the label results
        formatted_label_result = [{"LABEL": row[1], "COUNT": row[2]} for row in result]
        
        # Format the class results
        formatted_class_result = [{"CLASS": row[0], "COUNT": row[1]} for row in class_result]

        return {
            "label": formatted_label_result,
            "class": formatted_class_result
        }
    

    @staticmethod
    def get_records_log(selected_cctv, selected_start_date, selected_end_date, selected_event_name, page, page_size):
        connection = get_db_connection()
        cursor = connection.cursor()

        # Base query for getting the count grouped by CLASS_LABEL
        query = """
        SELECT RAWTOHEX(ID_T_HIST) AS ID, CCTV_NO, CLASS_LABEL, REG_DATE, REG_TIME 
        FROM HMX_AI.T_HIST
        WHERE 1 = 1
        """

        # Add filters based on the provided parameters
        params_dict = {}
        
        if selected_cctv is not None:
            query += " AND CCTV_NO = :cctv_id"
            params_dict['cctv_id'] = selected_cctv

        # Handle date filtering logic
        if selected_start_date and selected_end_date:
            # If both start and end dates are provided, fetch between the two dates
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = selected_start_date
            params_dict['end_date'] = selected_end_date
        elif selected_start_date and not selected_end_date:
            # If only start date is provided, fetch from start date to today
            end_date = datetime.now().strftime("%Y-%m-%d")
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = selected_start_date
            params_dict['end_date'] = end_date
        elif not selected_start_date and selected_end_date:
            # If only end date is provided, fetch from 30 days before the end date to the end date
            start_date = (datetime.strptime(selected_end_date, "%Y-%m-%d") - timedelta(days=30)).strftime("%Y-%m-%d")
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = start_date
            params_dict['end_date'] = selected_end_date
        else:
            # If neither start nor end date is provided, fetch from today to 30 days prior
            end_date = datetime.now().strftime("%Y-%m-%d")
            start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
            query += " AND REG_DATE BETWEEN :start_date AND :end_date"
            params_dict['start_date'] = start_date
            params_dict['end_date'] = end_date

        # Handle event name selection
        if selected_event_name is not None:
            query += " AND CLASS_LABEL = :class_label"
            params_dict['class_label'] = selected_event_name

        offset = (page - 1) * page_size
        query += " ORDER BY REG_DATE DESC, REG_TIME DESC OFFSET :offset ROWS FETCH NEXT :page_size ROWS ONLY"
        params_dict['offset'] = offset
        params_dict['page_size'] = page_size

        # Execute query with parameters
        cursor.execute(query, params_dict)
        result = cursor.fetchall()
        columns = [col[0] for col in cursor.description]  # Get column names
        connection.close()

        # Format the results into a list of dictionaries
        formatted_result = []
        for row in result:
            row_dict = dict(zip(columns, row))
            formatted_result.append(row_dict)

        return formatted_result
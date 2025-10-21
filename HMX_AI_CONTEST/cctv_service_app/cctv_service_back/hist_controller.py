from flask import Blueprint, jsonify, request, send_file, abort, Response, send_from_directory
from model.hist_model import HistModel
from utils.response import format_response, handle_error
import os
from flask_cors import CORS

hist_blueprint = Blueprint('hist_blueprint', __name__)
CORS(hist_blueprint)  # CORS 적용

@hist_blueprint.route('/hist/all', methods = ['GET'])
def get_all_hist():
    try:
        data = HistModel.get_all_hists()
        if data:
            return jsonify(format_response(data)), 200
        else:
            return jsonify(handle_error("No data found")), 404
    except Exception as e:
        return jsonify(handle_error(str(e))), 500
    

@hist_blueprint.route('/hist/latest', methods=['GET'])
def get_latest_hist():
    try:
        data = HistModel.get_latest_hists(10)  # 최신 10개 데이터를 요청
        if data:
            return jsonify(format_response(data)), 200
        else:
            return jsonify(handle_error("No data found")), 404
    except Exception as e:
        return jsonify(handle_error(str(e))), 500
    

@hist_blueprint.route('/hist/class_counts', methods=['GET'])
def get_class_counts():
    try:
        data = HistModel.get_class_counts()
        if data:
            return jsonify(format_response(data)), 200
        else:
            return jsonify(handle_error("No data found")), 404
    except Exception as e:
        return jsonify(handle_error(str(e))), 500
    
@hist_blueprint.route('/hist/statistics', methods=['POST'])
def get_filtered_hist_counts():
    try:
        data = request.get_json()
        selected_cctv = data.get('selectdCctv')  # CCTV 선택
        selected_start_date = data.get('selectdStartDate')  # 시작 날짜
        selected_end_date = data.get('selectdEndDate')  # 종료 날짜
        selected_event_name = data.get('selectdEventName')  # 이벤트 이름
        response_data  = HistModel.get_filtered_hist_counts(selected_cctv, selected_start_date, selected_end_date, selected_event_name)
        if response_data:
            # Create the response object without nested structure
            response = {
                "data": response_data,  # 데이터 배열
                "section": "all" if selected_cctv is None else selected_cctv,  # CCTV 번호
                "status": "success"
            }
            return jsonify(response), 200
        else:
            return jsonify(handle_error("No data found")), 404
    except Exception as e:
        return jsonify(handle_error(str(e))), 500
    
@hist_blueprint.route('/hist/records', methods=['POST'])
def get_records_log():
    try:
        data = request.get_json()
        selected_cctv = data.get('selectdCctv')  # CCTV 선택
        selected_start_date = data.get('selectdStartDate')  # 시작 날짜
        selected_end_date = data.get('selectdEndDate')  # 종료 날짜
        selected_event_name = data.get('selectdEventName')  # 이벤트 이름
        page = data.get('page', 1)  # 페이지 번호, 기본값 1
        page_size = data.get('pageSize', 10)
        data = HistModel.get_records_log(selected_cctv, selected_start_date, selected_end_date, selected_event_name, page, page_size)
        if data:
            return jsonify(format_response(data)), 200
        else:
            return jsonify(handle_error("No data found")), 404
    except Exception as e:
        return jsonify(handle_error(str(e))), 500
    
VIDEO_DIR = 'C:/Project/github/cctv_service_app/public/video'

# 정적 파일을 제공하는 라우트
@hist_blueprint.route('/public/video/<filename>', methods=['GET'])
def serve_video(filename):
    try:
        return send_from_directory(VIDEO_DIR, filename)
    except Exception as e:
        print(f"Error serving video: {e}")
        return abort(404, description="File not found")
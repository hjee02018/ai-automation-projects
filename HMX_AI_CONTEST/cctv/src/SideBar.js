// Sidebar.js
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import videoList from './common/videoList'; 
import { io } from 'socket.io-client';
import './SideBar.css'

const socket = io('http://127.0.0.1:5000'); // Flask 서버의 주소

const Sidebar = ({ selectedVideo, setSelectedVideo }) => {
  const [logList, setLogList] = useState([]);
  const [blinkVideo, setBlinkVideo] = useState(null);

  const handleVideoClick = (video) => {
    setSelectedVideo(video);
    setBlinkVideo(null);
  };

  const getSocketAlarm = (data) => {
    const detectedCCTV = videoList.find(video => video.id === data.cctv_no);
    if (detectedCCTV) {
      if (!selectedVideo) {
        setBlinkVideo(detectedCCTV.id);
      }
      setBlinkVideo(detectedCCTV.id);
    }
    setTimeout(() => {
      setBlinkVideo(null);
    }, 5000);

    fetchLatestData();
  };

  const fetchLatestData = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:5000/hist/latest');
      setLogList(response.data.data);
    } catch (error) {
      console.error('Error fetching logs:', error);
    }
  };

  useEffect(() => {
    fetchLatestData();
    socket.on('new_detection', getSocketAlarm);

    return () => {
      socket.off('new_detection', getSocketAlarm);
    };
  }, []);

  return (
    <aside className="video-list">  

        <div className="cctv-list">
          <h2 className="cctv-title">CCTV 목록</h2> {/* 클래스 이름을 적용하여 스타일 설정 */}
          <ul>   
            {videoList.map((video, index) => (
              <li key={index} onDoubleClick={() => handleVideoClick(video)}>
                {video.name}
              </li>
            ))}
          </ul>
        </div>
    
        <div className="log-list">
          <h3 className="log-title">이벤트 현황</h3> {/* 글자 색상과 크기 설정 */}
          <ul>
            {logList.length > 0 ? (
              logList.map((log, index) => (
                <li key={index} className="log-item"> {/* 로그 항목에도 스타일 적용 */}
                  {`${log.REG_DATE} ${log.REG_TIME}에 CCTV ${log.CCTV_NO}번에서 ${log.CLASS_LABEL} 이벤트 발생`}
                </li>
              ))
            ) : (
              <li className="log-item">로그가 없습니다.</li>
            )}
          </ul>
        </div>
      </aside>
  );
};

export default Sidebar;

import React, { useState , useEffect} from 'react';
import axios from 'axios';
import videoList from './common/videoList'; 
import { io } from 'socket.io-client';
import eventList from './common/eventList';   // 이벤트 class-id <> name 매핑용

const socket = io('http://127.0.0.1:5000'); // Flask 서버의 주소


const eventOptions = Object.keys(eventList).map(key => ({
  value: key,
  label: eventList[key],
}));

function HomePage ({selectedVideo, setSelectedVideo}) {

  const fakeLogData = [
    { REG_DATE: '2024-10-20', REG_TIME: '12:34:56', CCTV_NO: 1, CLASS_LABEL: 'UA-01' },
    { REG_DATE: '2024-10-20', REG_TIME: '13:12:34', CCTV_NO: 2, CLASS_LABEL: 'UA-02' },
    { REG_DATE: '2024-10-21', REG_TIME: '09:45:22', CCTV_NO: 3, CLASS_LABEL: 'UA-03' },
  ];


    //로그 기록용 상태
    // const [logList, setLogList] = useState([]);
    const [logList, setLogList] = useState(fakeLogData);
    const [blinkVideo, setBlinkVideo] = useState(null);

    const handleVideoClick = (video) => {
      setSelectedVideo(video);
      setBlinkVideo(null);
    };

    const getSocketAlarm = (data) => {
      const detectedCCTV = videoList.find(video => video.id === data.cctv_no);
      if (detectedCCTV) 
        {
          // 선택되지 않았을 때는 자동 이동 방지
          if (!selectedVideo) 
            setBlinkVideo(detectedCCTV.id);
          setBlinkVideo(detectedCCTV.id); // 깜빡이기 위한 CCTV ID 설정
      }
      setTimeout(() => {
          setBlinkVideo(null); // 5초 후에 깜빡이기 종료
      }, 5000);

      // 새로운 감지 이벤트가 발생하면 /hist/latest 에서 최신 데이터를 가져와서 업데이트
      // fetchLatestData();
      setLogList((prevLogs) => [
        {
            REG_DATE: new Date(data.time).toISOString().split('T')[0], // 날짜 포맷
            REG_TIME: new Date(data.time).toLocaleTimeString(), // 시간 포맷
            CCTV_NO: data.cctv_no,
            CLASS_LABEL: data.class_name,
        },
        ...prevLogs, // 이전 로그를 뒤에 추가
      ]);
  };

  
  // 서버로부터 최신 데이터를 가져오는 함수
  // const fetchLatestData = async () => {
  //     try {
  //         const response = await axios.get('http://127.0.0.1:5000/hist/latest');
  //         setLogList(response.data.data);
  //     } catch (error) {
  //         console.error('데이터를 가져오는 중 오류 발생:', error);
  //     }
  // };

    useEffect(() => {
        // 초기 데이터 로드
        // fetchLatestData();

        // 소켓 이벤트 등록
        socket.on('new_detection', getSocketAlarm);

        // 컴포넌트가 unmount 될 때 소켓 이벤트 제거
        return () => {
            socket.off('new_detection', getSocketAlarm);
        };
    }, [selectedVideo]);

    return (
      <div className="content">
      {/* 좌측 비디오 목록 */}
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
                  { `${log.REG_DATE} ${log.REG_TIME}  CCTV ${log.CCTV_NO} | ${eventList[log.CLASS_LABEL] || log.CLASS_LABEL} 이벤트 발생`}
                  {/* {`${log.REG_DATE} ${log.REG_TIME}에 CCTV ${log.CCTV_NO}번에서 ${eventOptions.find(option => option.value === log.CLASS_LABEL)?.label || log.CLASS_LABEL} 이벤트 발생`} */}
                  {/* {`${log.REG_DATE} ${log.REG_TIME}에 CCTV ${log.CCTV_NO}번에서 ${log.CLASS_LABEL} 이벤트 발생`} */}
                </li>
              ))
            ) : (
              <li className="log-item">로그가 없습니다.</li>
            )}
          </ul>
        </div>
      </aside>
    
      {/* 우측 CCTV 화면 */}
      <main className="video-display">
        {selectedVideo ? (
          <div className={`selected-video`}>
          <h2>{selectedVideo.name}</h2>
          <div className={`video-container ${blinkVideo === selectedVideo.id ? 'blink' : ''}`}>
            <img src={selectedVideo.src} alt={selectedVideo.name} />
          </div>
        </div>
        
          // <div className={`selected-video ${blinkVideo === selectedVideo.id ? '' : 'blink'}`}>
          // {/* <div className={`selected-video ${blinkVideo === selectedVideo.id ? 'blink' : ''}`}> */}
          //   <h2>{selectedVideo.name}</h2>
          //   <img src={selectedVideo.src} alt={selectedVideo.name} />
          // </div>
        ) : (
          <div className="grid-view">
            {videoList.slice(0, 9).map((video, index) => (
              <div
                key={index}
                className={`grid-item ${blinkVideo === video.id ? '' : 'blink'}`} // 각 CCTV 화면에 대해 깜빡이기 적용
                // className={`grid-item ${blinkVideo === video.id ? 'blink' : ''}`} // 각 CCTV 화면에 대해 깜빡이기 적용
              >
                <img src={video.src} alt={video.name} />
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
    
    );
}

export default HomePage;
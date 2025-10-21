import React, {useState, useEffect} from 'react';
import axios from 'axios';
import './StatisticsPage.css';
import Sidebar from './SideBar';
import videoList from './common/videoList';
import eventList from './common/eventList';
import { Bar, Pie } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement } from 'chart.js';


/* 통계 페이지 */

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement);

function StatisticsPage() {
    // 체크박스 
    const [cctvChecked, setCctvChecked] = useState(false);
    const [dateChecked, setDateChecked] = useState(false);
    const [eventChecked, setEventChecked] = useState(false);

    // 선택된 검색조건 
    const [selectedCctv, setSelectedCctv] = useState('');
    const [selectedCctvId, setSelectedCctvId] = useState('');
    const [selectedStartDate, setSelectedStartDate] = useState('');
    const [selectedEndDate, setSelectedEndDate] = useState('');
    const [selectedEventName, setSelectedEventName] = useState('');
    const [selectedEventKey, setSelectedEventKey] = useState('');

    // 받은 데이터를 저장한 상태
    const [labelData, setLabelData] = useState([]);
    const [classData, setClassData] = useState([]);


    //계산한 비율 데이터
    //const [percentages, setPercentages] = useState([]);

    //class구분 매핑
    const className = {
        UA : "위험 행동",
        UC : "위험 상태",
        WO : "동적 위험 요소",
        SO : "정적 위험 요소"
    };
    
    // 조건에 따라 서버에 검색요청보내는 함수
    const handleSearch = async () => {

        const searchParams = {
            selectdCctv: cctvChecked ? selectedCctvId : null,
            selectdStartDate: dateChecked ? selectedStartDate : null,
            selectdEndDate: dateChecked ? selectedEndDate : null,
            selectdEventName: eventChecked ? selectedEventKey : null,
        };

        //console.log(searchParams);
        try {
            //const response = await axios.post('http://127.0.0.1:5000/hist/statistics', searchParams);
    
            const response = {
                "data": {
                  "label": [
                    {
                      "LABEL": "UA-05",
                      "COUNT": 3
                    },
                    {
                      "LABEL": "UC-02",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "UC-15",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "UC-16",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "UA-02",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "UA-02",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "UA-02",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "UA-02",
                      "COUNT": 2
                    },
                    {
                      "LABEL": "WO-02",
                      "COUNT": 2
                    }
                  ],
                  "class": [
                    {
                      "CLASS": "UA",
                      "COUNT": 3
                    },
                    {
                      "CLASS": "UC",
                      "COUNT": 2
                    },
                    {
                      "CLASS": "WO",
                      "COUNT": 2
                    },
                    {
                      "CLASS": "SO",
                      "COUNT": 2
                    }
                  ]
                },
                "section": "1",
                "status": "success"
              }
            setLabelData(response.data?.label || []);
            setClassData(response.data?.class || []);
    
            console.log(classData);
            console.log(labelData);
    
            // 퍼센트 계산용 -- 사용안함
            // const classDataArray = response.data?.class || [];
            // if (classDataArray.length > 0) {
            //     const total = classDataArray.reduce((acc, item) => acc + item.COUNT, 0);
            //     const calculatedPercentages = classDataArray.map(item => ({
            //         class: item.CLASS,
            //         percentage: ((item.COUNT / total) * 100).toFixed(2),
            //     }));
            //     setPercentages(calculatedPercentages);
            // } 
            // else {
            //     setPercentages([]); // Reset percentages if no class data
            // }
        } catch (error) {
            console.error('데이터 조회 오류:', error);
        }
    };

    useEffect(() => {
        handleSearch();
    }, []);


    // LabelData -> 막대그래프용 데이터로 나누기
    const labels = labelData ? labelData.map(item => eventList[item.LABEL]) : [];
    const labelCount = labelData ? labelData.map(item => item.COUNT) : [];

    // ClassData -> 그래프용 데이터로 나누기
    const classes = classData ? classData.map(item => className[item.CLASS]) : [];
    const classCount = classData ? classData.map(item => item.COUNT) : [];

    // 최다 발생 라벨 두개 저장
    const topTwo = labelCount
        .map((count, index) => ({ labelName: labels[index], count }))  // 라벨명과 개수 추출
        .sort((a, b) => b.count - a.count)  
        .slice(0, 2); 

    // 막대그래프 그리기
    const barChartData = {
        maintainAspectRatio: false,
        labels: labels,
        datasets: [{
            label: '최근 발생한 위험상황 종류',
            data: labelCount,
            backgroundColor:['#FF9A00', '#FF3D00', '#D5006D', '#6200EA', '#00BFFF'], 
        }]
    };

    //막대그래프 옵션
    const barChartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false, // 범례 표시 비활성화
            },
            title: {
                display: true, 
                text: '위험이벤트 발생 빈도',
                color: '#f9f4f4', 
                font: {
                    size: 18, 
                },
                position: 'bottom'
            },
        },
        scales: {
            x: {
                ticks: {
                    color: '#f9f4f4', 
                    font: {
                        size: 10 // 라벨 텍스트 크기를 줄임
                      },
                    maxRotation: 30, 
                },
                title: {
                    display: false, 
                },
            },
            y: {
                ticks: {
                    color: '#f9f4f4', 
                },
                title: {
                    display: false, 
                },
            },
        },
        aspectRatio: 0.9, 
    };

    // 원형그래프 그리기
    const pieChartData = {
        labels: classes,
        datasets: [{
            data: classCount,
            backgroundColor:['#FF9A00', '#FF3D00', '#D5006D', '#6200EA', '#00BFFF'], 
            //['#4E79A7', '#F28E2C', '#E15759', '#76B7B2', '#59A14F'], 
            //['#9C27B0', '#2196F3', '#FFEB3B', '#FF5722', '#00E676'],
            //['#FF9A00', '#FF3D00', '#D5006D', '#6200EA', '#00BFFF'], 
            //['#4A90E2', '#50E3C2', '#B8E986', '#F5A623', '#D0021B'], 
        }]
    };

    // 파이차트 옵션
    const pieChartOptions = {
        plugins: {
            tooltip: {
                callbacks: {
                    label: function(tooltipItem) {
                        let total = tooltipItem.dataset.data.reduce((a, b) => a + b, 0);
                        let value = tooltipItem.raw;
                        let percentage = ((value / total) * 100).toFixed(2);
                        return `${tooltipItem.label}: ${percentage}%`;
                    }
                }
            },
            datalabels: {
                formatter: (value, ctx) => {
                    let sum = ctx.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                    let percentage = (value * 100 / sum).toFixed(2) + "%";
                    return percentage;
                },
                color: '#fff',  
            },
            legend: {
                position: 'right', 
                labels: {
                    color: '#f9f4f4', 
                    font: {
                        size: 10,
                    },
                }
            },
            title: {
                display: true, 
                text: '위험이벤트 분류별 비율', 
                color: '#f9f4f4', 
                font: {
                    size: 18, 
                    weight: 'bold' 
                },
                padding: {
                    //top: 30, 
                    bottom: 10 
                },
                position: 'bottom'
            },
        },
        elements: {
            arc: {
                borderWidth: 1, 
                color: '#000000',
            }
        },
    };

    return (
        <div className="statistics-page-container">
            {/* Left Sidebar */}
            <Sidebar selectedVideo={selectedCctv} setSelectedVideo={setSelectedCctv} />
            <div className="statistics-page-content">
                <h2>Statistics</h2>
                <div className="search-filters">
                        <input type="checkbox" checked={cctvChecked} onChange={() => setCctvChecked(!cctvChecked)} />
                        <label> CCTV </label>
                        <select value={selectedCctvId}
                            onChange={(e) => {
                                setSelectedCctvId(e.target.value);
                                setSelectedCctv(videoList.find(video => video.id === parseInt(selectedCctvId)));
                                }}>
                        <option value="">구역 선택</option>
                            {videoList.map((video, index) => (
                                <option key={index} value={video.id}>
                                    {video.name}
                                </option>
                                ))}
                        </select>
                        <input type="checkbox" checked={dateChecked} onChange={() => setDateChecked(!dateChecked)} />
                        <label>Date</label>
                            <input type="date" value={selectedStartDate} onChange={(e) => setSelectedStartDate(e.target.value)} />
                            <input type="date" value={selectedEndDate} onChange={(e) => setSelectedEndDate(e.target.value)} />
                
                        <input type="checkbox" checked={eventChecked} onChange={() => setEventChecked(!eventChecked)} />
                        <label>Event Name</label>
                        <select value={selectedEventKey}
                                onChange={(e) => {
                                    setSelectedEventKey(e.target.value);
                                    setSelectedEventName(eventList[e.target.value]);
                                }}>
                        <option value="">이벤트 선택</option>
                                {Object.entries(eventList).map(([key,value]) => (
                                    <option key={key} value={key}>
                                        {value}
                                    </option>
                                ))}
                        </select>
                        <button onClick={handleSearch}>Search</button>
                </div>
                <div className="statistics-rendering">
                    <div className="statistics-summary">
                        <h3>위험상황통계 요약</h3>
                        <div>
                            <div className="summary-container">
                            {topTwo.map((item, index) => (
                                <div key={index} className="summary-box">
                                    위험발생 {index+1} 위 : <span style={{ marginLeft: '0.5rem', fontSize: '24px', fontWeight: 'bold' }}>{item.labelName}</span>
                                </div>
                            ))}
                            </div>
                            <div className="summary-container">
                                {classes.map((item, index) => (
                                    <div key={index} className="summary-box">
                                        {item}: 
                                        <span style={{ marginLeft: '0.5rem', fontSize: '24px', fontWeight: 'bold' }}>{classCount[index]}건</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                    {/* 차트 그리기 */}
                    <div className="chart-container">
                        <h3>위험상황통계 그래프 </h3>
                        <div className="statistics-chart">
                            <div className="bar-chart">
                                <Bar data={barChartData} options={barChartOptions}/>
                            </div>
                            <div className="pie-chart">
                                <Pie data={pieChartData} options={pieChartOptions}/>
                            </div>
                        </div>
                    </div>
                                </div>
                </div>
        </div>                           
            
    );
}

export default StatisticsPage;
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useTable } from 'react-table';
import Sidebar from './SideBar';
import './LogPage.css';  // Optional: CSS for styling
import eventList from './common/eventList';
import * as XLSX from 'xlsx';
import Modal from './Modal';

const LogPage = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);  // For pagination
  const [pageSize, setPageSize] = useState(10);  // Number of records per page

  // State for search parameters
  const [selectedCctv, setSelectedCctv] = useState('');
  const [selectedStartDate, setSelectedStartDate] = useState('');
  const [selectedEndDate, setSelectedEndDate] = useState('');
  const [selectedEventName, setSelectedEventName] = useState('');

  // 체크박스 
  const [cctvChecked, setCctvChecked] = useState(false);
  const [dateChecked, setDateChecked] = useState(false);
  const [eventChecked, setEventChecked] = useState(false);

  const [selectedVideo, setSelectedVideo] = useState(null);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [videoSrc, setVideoSrc] = useState('');

  const cctvMapping = {
    1: "1층 전극동",
    2: "2층 자재창고",
    3: "출입구",
    4: "비상계단",
    5: "2층 전극동",
    6: "3층 전극동",
    7: "3층 자재창고",
    8: "4층 비상구",
    // Add other mappings as needed
  };

  const eventOptions = Object.keys(eventList).map(key => ({
    value: key,
    label: eventList[key],
  }));


  // Function to fetch logs using Axios
  const fetchLogs = async () => {
    try {
      setLoading(true);

      const searchParams = {
        selectdCctv: cctvChecked ? selectedCctv : null,
        selectdStartDate: dateChecked ? selectedStartDate : null,
        selectdEndDate: dateChecked ? selectedEndDate : null,
        selectdEventName: eventChecked ? selectedEventName : null,
        page: page,
        pageSize: pageSize
      };
      

      // Making the POST request using axios
      const response = await axios.post('http://127.0.0.1:5000/hist/records', searchParams);

      // Check for success and update logs state with the received data
      if (response.data.status === 'success') {
        setLogs(response.data.data);  // Access the 'data' array from the response
      } else {
        console.error('Failed to load logs');
      }

      setLoading(false);
    } catch (error) {
      console.error("Error fetching logs:", error);
      setLoading(false);
    }
  };

  // Fetch logs when component mounts or when page/pageSize changes
  useEffect(() => {
    fetchLogs();
  }, [page, pageSize]);

  
  const handlePlayback = () => {
    // 무조건 2024-10-18.mp4 파일을 재생하도록 설정
    const videoPath = 'http://127.0.0.1:5000/public/video/cctv_1.mp4'; 
    setVideoSrc(videoPath);
    setIsModalOpen(true);
  };

  // React Table configuration
  const columns = React.useMemo(
    () => [
      {
        Header: 'CCTV Number',
        accessor: 'CCTV_NO',
        Cell: ({ cell: { value } }) => cctvMapping[value] || value,   
      },
      {
        Header: 'Event Name',
        accessor: 'CLASS_LABEL',
        Cell: ({ cell: { value } }) => eventList[value] || value,  
      },
      {
        Header: 'Date',
        accessor: 'REG_DATE',
      },
      {
        Header: 'Time',
        accessor: 'REG_TIME',
      },
      {
        Header: 'Playback',
        accessor: 'playback',  // You can use a custom accessor since this column won't pull data from the API
        Cell: () => (
          <div className="playback-cell">
            <button onClick={() => handlePlayback()}>▶️</button>
          </div>  // Log the ID when clicked
        ),
      },
    ],
    []
  );

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = useTable({ columns, data: logs });

  const exportToExcel = () => {
    // Create a worksheet from the logs data
    const worksheet = XLSX.utils.json_to_sheet(logs.map(log => ({
      CCTV_Number: cctvMapping[log.CCTV_NO] || log.CCTV_NO,
      Event_Name: eventList[log.CLASS_LABEL] || log.CLASS_LABEL,
      Date: log.REG_DATE,
      Time: log.REG_TIME,
    })));

    // Create a new workbook
    const workbook = XLSX.utils.book_new();

    // Append the worksheet to the workbook
    XLSX.utils.book_append_sheet(workbook, worksheet, "Logs");

    // Trigger file download
    XLSX.writeFile(workbook, "logs_export.xlsx");
  };

  return (
    <div className="log-page-container">
      {/* Left Sidebar */}
      <Sidebar selectedVideo={selectedVideo} setSelectedVideo={setSelectedVideo} />

      <div className="log-page-content">
        <h2>Logs</h2>

        <div className="search-filters">
          <input 
            type="checkbox" 
            checked={cctvChecked} 
            onChange={() => setCctvChecked(!cctvChecked)} 
          />
          <label>CCTV</label>
          <select
            value={selectedCctv}
            onChange={(e) => setSelectedCctv(e.target.value)}
            disabled={!cctvChecked} // Disable if checkbox is not checked
          >
            <option value="">구역 선택</option>
            {Object.entries(cctvMapping).map(([key, value]) => (
              <option key={key} value={key}>
                {value}
              </option>
            ))}
          </select>

          <input 
            type="checkbox" 
            checked={dateChecked} 
            onChange={() => setDateChecked(!dateChecked)} 
          />
          <label>Date</label>
          <input
            type="date"
            value={selectedStartDate}
            onChange={(e) => setSelectedStartDate(e.target.value)}
            disabled={!dateChecked} // Disable if checkbox is not checked
            placeholderText='yyyy-mm-dd'
          />
          <input
            type="date"
            value={selectedEndDate}
            onChange={(e) => setSelectedEndDate(e.target.value)}
            disabled={!dateChecked} // Disable if checkbox is not checked
            placeholderText='yyyy-mm-dd'
          />
          <input 
            type="checkbox" 
            checked={eventChecked} 
            onChange={() => setEventChecked(!eventChecked)} 
          />
          <label>Event</label>
          <select
            value={selectedEventName}
            onChange={(e) => setSelectedEventName(e.target.value)}
            disabled={!eventChecked} // Disable if checkbox is not checked
          >
            <option value="">이벤트 선택</option>
            {eventOptions.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>

          <button onClick={fetchLogs}>Search</button>

          <button onClick={exportToExcel} className="export-button">Export to Excel</button>
        </div>

        {loading ? (
          <div>Loading logs...</div>
        ) : (
          <table {...getTableProps()} className="log-table">
            <thead>
              {headerGroups.map(headerGroup => (
                <tr {...headerGroup.getHeaderGroupProps()}>
                  {headerGroup.headers.map(column => (
                    <th {...column.getHeaderProps()}>{column.render('Header')}</th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody {...getTableBodyProps()}>
              {rows.map(row => {
                prepareRow(row);
                return (
                  <tr {...row.getRowProps()}>
                    {row.cells.map(cell => (
                      <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <div className="pagination">
          <button className="pagination-prev" onClick={() => setPage(prev => Math.max(prev - 1, 1)) } disabled={page === 1}>
            Previous
          </button>
          <span className="pagination-page">Page {page}</span>
          <button className="pagination-next" onClick={() => setPage(prev => prev + 1)}>Next</button>
          <select  className="pagination-select" value={pageSize} onChange={e => setPageSize(Number(e.target.value))}>
            {[10, 20, 30, 40, 50].map(size => (
              <option key={size} value={size}>
                Show {size}
              </option>
            ))}
          </select>
        </div>
        <Modal 
          isOpen={isModalOpen} 
          onClose={() => setIsModalOpen(false)} 
          videoSrc={videoSrc} 
        />
      </div>
    </div>
  );
};

export default LogPage;
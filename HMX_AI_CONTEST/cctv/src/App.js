import React, {useState} from 'react';
import './App.css';
import HomePage from './HomePage';
import StatisticsPage from './StatisticsPage';
import LogPage from './logPage';
import AlarmPage from './AlarmPage';
import logo from './img/hyundaimovexicon.ico';
import userLogo from './img/user.png';


function App() {

  //메뉴 관리
  const [selectedMenu, setSelectedMenu] = useState('home');
  const [selectedVideo, setSelectedVideo] = useState(null);

  const handleHomeClick = () => {
    setSelectedVideo(null);  
    setSelectedMenu('home'); 
  };

  return (
    <div className="app-container">
      <header className="header">
        <div className="logo-container" onClick={handleHomeClick} style={{ cursor: 'pointer' }}>
          <img src={logo} alt="Logo" className="logo" /> {/* Logo now serves as home button */}
        </div>
        <div className="menu">
          <button className={`menu-button ${selectedMenu === 'statistics' ? 'active' : ''}`} onClick={() => setSelectedMenu('statistics')}>통계</button>
          <button className={`menu-button ${selectedMenu === 'logs' ? 'active' : ''}`} onClick={() => setSelectedMenu('logs')}>로그</button>
        </div>

        {/* Add a user icon to the right side */}
        <div className="user-icon-container">
          <img src={userLogo} alt="User Icon" className="user-icon" /> {/* Use your user PNG here */}
          <span className="admin-text"> | ADMIN</span> {/* ADMIN text */}
        </div>
      </header>

      <div className="content">
        {selectedMenu === 'home' ? (
          <HomePage selectedVideo={selectedVideo} setSelectedVideo={setSelectedVideo} />
        ) : selectedMenu === 'statistics' ? (
          <StatisticsPage />
        ) : (
          <LogPage />  // Show LogPage when logs menu is selected
        )}
      </div>
    </div>
  );
}

export default App;

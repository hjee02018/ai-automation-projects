import React from 'react';
import ReactPlayer from 'react-player';
import './Modal.css'

const Modal = ({ isOpen, onClose, videoSrc }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <button className="modal-close" onClick={onClose}>X</button>
        <div className="video-container">
          <ReactPlayer
            url={videoSrc}
            controls={true}
            playing={true}
            width="100%"
            height="100%"
          />
        </div>
      </div>
    </div>
  );
};

export default Modal;

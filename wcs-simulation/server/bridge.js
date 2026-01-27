/*
    TCP 중계 서버 (Node.js)
*/

const net = require('net');
const http = require('http');
const { Server } = require('socket.io');

// 1. 웹 브라우저와 통신하기 위한 HTTP 및 WebSocket 서버 설정
const httpServer = http.createServer();
const io = new Server(httpServer, {
    cors: { origin: "*" } // 모든 도메인에서의 접속 허용
});

// 2. 설비(PLC) 접속 설정
const PLC_CONFIG = {
    ip: '192.168.1.10', // 실제 설비 IP
    port: 3000          // 설비 통신 포트
};

// 3. TCP 클라이언트 생성 (Node.js -> PLC)
const plcClient = new net.Socket();

function connectToPLC() {
    plcClient.connect(PLC_CONFIG.port, PLC_CONFIG.ip, () => {
        console.log(`✅ PLC 설비에 연결됨: ${PLC_CONFIG.ip}:${PLC_CONFIG.port}`);
    });

    // 설비로부터 데이터 수신 시
    plcClient.on('data', (rawBuffer) => {
        // [데이터 해석부] 설비의 프로토콜에 따라 분석
        // 예시: 패킷이 "STX|호기|베이|단|상태|ETX" 형태라고 가정
        const message = rawBuffer.toString();
        const parsedData = parsePlcMessage(message);

        // 해석된 데이터를 브라우저로 실시간 전송
        if (parsedData) {
            io.emit('rack_update', parsedData);
        }
    });

    plcClient.on('close', () => {
        console.log('⚠️ PLC 연결이 끊겼습니다. 5초 후 재시도...');
        setTimeout(connectToPLC, 5000);
    });

    plcClient.on('error', (err) => {
        console.error('❌ PLC 통신 에러:', err.message);
    });
}

// 4. 메시지 파싱 함수 (설비 명세에 맞춰 수정 필요)
function parsePlcMessage(msg) {
    try {
        const parts = msg.split('|');
        // 예: "1|22|5|NORMAL" -> { aisle:1, bay:22, level:5, status:'NORMAL' }
        return {
            aisle: parseInt(parts[0]),
            bay: parseInt(parts[1]),
            level: parseInt(parts[2]),
            status: parts[3], // 'NORMAL', 'EMPTY', 'BAN' 등
            timestamp: new Date().getTime()
        };
    } catch (e) {
        return null;
    }
}

// 5. 서버 가동
httpServer.listen(3001, () => {
    console.log('🚀 Bridge 서버가 3001번 포트에서 실행 중입니다.');
    connectToPLC();
});
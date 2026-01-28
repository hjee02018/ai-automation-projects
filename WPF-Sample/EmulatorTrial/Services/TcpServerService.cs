using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace EmulatorTrial.Services
{
    /// <summary>
    /// 상위 시스템(WCS)과 통신하여 명령을 수신하고 상태를 보고하는 설비 에뮬레이터 서비스
    /// </summary>
    public class TcpServerService
    {
        private TcpListener _listener;
        private bool _isRunning;
        private readonly List<TcpClient> _connectedClients = new List<TcpClient>();
        private readonly ProtocolParserService _parser;


        // 외부(ViewModel/Engine)에서 구독할 이벤트
        public event Action<string, string> OnMessageReceived; // 발신자, 메시지
        public event Action<string> OnLogMessage;              // 로그 출력용
        public event Action<int> OnClientCountChanged;       // 연결된 클라이언트 수 변경

        // 생성자 추가 必
        public TcpServerService(ProtocolParserService parser)
        {
            _parser = parser;
        }

        private void HandleReceiveData(string rawMsg)
        {
            var parsedData = _parser.ParsePacket(rawMsg);
            if(parsedData.ContainsKey("_MessageID"))
            {
                // 2단계: 분석된 데이터를 바탕으로 장비 상태 업데이트 (ViewModel 또는 Engine)
                // 예: NotifyEquipmentUpdate(parsedData);

                // 3단계: 자동 응답 발송 (ACK 등)
                string response = _parser.CreateResponse(parsedData["_MessageID"]);
                //SendMessage(response);
            }
        }

        public async Task StartListening(int port = 18888)
        {
            try
            {
                _listener = new TcpListener(IPAddress.Any, port);
                _listener.Start();
                _isRunning = true;
                OnLogMessage?.Invoke($"[Server] 서버가 포트 {port}에서 시작되었습니다.");

                while (_isRunning)
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    lock (_connectedClients) _connectedClients.Add(client);
                    OnClientCountChanged?.Invoke(_connectedClients.Count);

                    _ = HandleClient(client); // 비동기로 클라이언트 처리
                }
            }
            catch (Exception ex)
            {
                OnLogMessage?.Invoke($"[Error] 서버 시작 실패: {ex.Message}");
            }
        }

        private async Task HandleClient(TcpClient client)
        {
            string clientEndPoint = client.Client.RemoteEndPoint.ToString();
            OnLogMessage?.Invoke($"[Server] 클라이언트 연결됨: {clientEndPoint}");

            using var stream = client.GetStream();
            byte[] buffer = new byte[1024];

            try
            {
                while (client.Connected && _isRunning)
                {
                    int read = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (read == 0) break; // 연결 종료

                    string rawMsg = Encoding.UTF8.GetString(buffer, 0, read);
                    OnMessageReceived?.Invoke(clientEndPoint, rawMsg);

                    // TODO: 여기서 rawMsg를 해석(Parsing)하여 시뮬레이션 엔진에 명령 전달
                    // 예: "MOVE|1000" -> STC 주행 명령

                    // 응답 전송 (ACK)
                    byte[] response = Encoding.UTF8.GetBytes($"ACK|{rawMsg}\n");
                    await stream.WriteAsync(response, 0, response.Length);
                }
            }
            catch (Exception ex)
            {
                OnLogMessage?.Invoke($"[Error] 통신 중 오류: {ex.Message}");
            }
            finally
            {
                lock (_connectedClients) _connectedClients.Remove(client);
                OnClientCountChanged?.Invoke(_connectedClients.Count);
                OnLogMessage?.Invoke($"[Server] 클라이언트 연결 해제: {clientEndPoint}");
                client.Close();
            }
        }

        public async Task SendToAllClients(string message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message + "\n");
            List<TcpClient> clientsToRemove = new List<TcpClient>();

            foreach (var client in _connectedClients)
            {
                try
                {
                    if (client.Connected)
                    {
                        await client.GetStream().WriteAsync(data, 0, data.Length);
                    }
                }
                catch
                {
                    clientsToRemove.Add(client);
                }
            }

            lock (_connectedClients)
            {
                foreach (var c in clientsToRemove) _connectedClients.Remove(c);
            }
        }

        public void Stop()
        {
            _isRunning = false;
            _listener?.Stop();
        }
    }
}
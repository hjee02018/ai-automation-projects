using System;
using System.Windows;
using System.Windows.Media; // CompositionTarget을 위해 필요
using Microsoft.Web.WebView2.Core;
using EmulatorTrial.ViewModels;
using EmulatorTrial.Services;

namespace EmulatorTrial
{
    public partial class MainWindow : Window
    {
        private EquipmentViewModel _viewModel;
        private TcpServerService _tcpServer;


        public MainWindow()
        {
            InitializeComponent();
            _viewModel = new EquipmentViewModel();
            this.DataContext = _viewModel;

            // 26.01.26 TCP 연결 추가
            // 1. TCP 서버 서비스 인스턴스화
            _tcpServer = new TcpServerService();

            // 2. 이벤트 구독 (메시지 수신 및 로그 처리)
            _tcpServer.OnMessageReceived += (sender, msg) => {
                // UI 스레드에서 메시지 처리 (메시지 수신 시 ViewModel에 전달)
                Dispatcher.Invoke(() => {
                    _viewModel.ProcessIncomingMessage(sender, msg);
                });
            };

            _tcpServer.OnLogMessage += (log) => {
                Dispatcher.Invoke(() => {
                    _viewModel.AddLog(log);
                });
            };

            _tcpServer.OnClientCountChanged += (count) => {
                Dispatcher.Invoke(() => {
                    _viewModel.ClientCount = count;
                });
            };

            InitializeAsync();
        }

        private async void InitializeAsync()
        {
            try
            {
                // 1. TCP 서버 가동 (18888 포트 개방)
                // 무한 루프이므로 await 하지 않고 별도의 비동기 작업으로 실행합니다.
                if (_tcpServer != null)
                {
                    _ = _tcpServer.StartListening(18888);
                }

                // 2. WebView2 환경 설정
                await WebView3D.EnsureCoreWebView2Async(null);

                // 3. HTML 파일 경로 설정
                string htmlPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "srm_3d_viewer.html");

                if (System.IO.File.Exists(htmlPath))
                {
                    WebView3D.CoreWebView2.Navigate(new Uri(htmlPath).AbsoluteUri);
                }
                else
                {
                    WebView3D.NavigateToString("<h1 style='color:white;'>3D Viewer HTML File Not Found</h1>" +
                                               $"<p style='color:gray;'>Check path: {htmlPath}</p>");
                }

                // 4. 실시간 렌더링 동기화 이벤트 연결
                CompositionTarget.Rendering += OnRendering;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"초기화 중 오류 발생: {ex.Message}");
            }
        }

        private void OnRendering(object sender, EventArgs e)
        {
            if (WebView3D != null && WebView3D.CoreWebView2 != null && _viewModel.Equipments.Count > 0)
            {
                var srm = _viewModel.Equipments[0];
                // 모델에 LiftPos, ForkPos가 추가되었으므로 이제 오류가 발생하지 않습니다.
                string script = $"if(window.updateSrm) {{ window.updateSrm({srm.CurrentPos}, {srm.LiftPos}, {srm.ForkPos}); }}";
                WebView3D.ExecuteScriptAsync(script);
            }
        }
    }
}
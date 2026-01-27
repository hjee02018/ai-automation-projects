using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;

namespace EmulatorTrial.ViewModels
{
    // UI와 로직을 연결하는 뷰모델 (Data Binding의 중심)
    public class EquipmentViewModel : INotifyPropertyChanged
    {
        public ObservableCollection<Models.StackerCrane> Equipments { get; set; }
        public ObservableCollection<string> CommunicationLogs { get; set; }

        private int _clientCount;
        public int ClientCount
        {
            get => _clientCount;
            set
            {
                _clientCount = value;
                OnPropertyChanged();
            }
        }

        private Services.SimulationEngine _engine;

        public EquipmentViewModel()
        {
            // 가상 설비 초기화
            Equipments = new ObservableCollection<Models.StackerCrane>
            {
                new Models.StackerCrane { Id = "STC-01", Name = "Stacker Crane 1", IsConnected = true, CurrentPos = 0, LiftPos = 0, ForkPos = 0 },
                new Models.StackerCrane { Id = "STC-02", Name = "Stacker Crane 2", IsConnected = false, CurrentPos = 0, LiftPos = 0, ForkPos = 0 }
            };

            CommunicationLogs = new ObservableCollection<string>();

            // 시뮬레이션 엔진 시작 (P2)
            _engine = new Services.SimulationEngine(Equipments.ToList());
            _engine.Start();
        }

        /// <summary>
        /// 외부(MainWindow)에서 로그를 추가할 수 있는 메서드
        /// </summary>
        public void AddLog(string message)
        {
            // 최신 로그가 위로 오도록 삽입
            CommunicationLogs.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {message}");

            // 로그가 너무 많아지면 메모리 관리를 위해 오래된 것 삭제 (선택 사항)
            if (CommunicationLogs.Count > 100)
                CommunicationLogs.RemoveAt(100);
        }

        /// <summary>
        /// 수신된 TCP 메시지를 처리하는 메서드
        /// </summary>
        public void ProcessIncomingMessage(string sender, string message)
        {
            AddLog($"{sender} >> {message}");
            ParseCommand(message);
        }

        private void ParseCommand(string msg)
        {
            // 프로토콜 해석 및 명령 수행 (예: MOVE|STC-01|50000)
            try
            {
                string[] parts = msg.Split('|');
                if (parts.Length < 2) return;

                string command = parts[0];
                string targetId = parts[1];

                var target = Equipments.FirstOrDefault(e => e.Id == targetId);
                if (target == null) return;

                switch (command)
                {
                    case "MOVE":
                        if (parts.Length >= 3 && double.TryParse(parts[2], out double pos))
                        {
                            // SimulationEngine에서 TargetPos를 참조하도록 구현되어 있어야 함
                            // target.TargetPos = pos; 
                            target.Status = "Moving";
                        }
                        break;
                    case "STOP":
                        target.Status = "Idle";
                        break;
                }
            }
            catch (Exception ex)
            {
                AddLog($"[Error] 명령 해석 오류: {ex.Message}");
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
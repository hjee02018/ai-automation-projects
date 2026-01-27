using System;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Controls;
using System.Windows.Threading;

namespace EmulatorTrial.Views
{
    /// <summary>
    /// Interaction logic for PerformMonitorView.xaml
    /// Monitors and simulates System-wide and Process-specific resource usage.
    /// </summary>
    public partial class PerformMonitorView : UserControl, INotifyPropertyChanged
    {
        private DispatcherTimer _refreshTimer;
        private Random _rnd = new Random();
        private Process _currentProcess;

        // --- System-wide Properties (Total PC) ---
        private double _totalCpuUsage;
        public double TotalCpuUsage
        {
            get => _totalCpuUsage;
            set { _totalCpuUsage = value; OnPropertyChanged(); }
        }

        private double _totalGpuUsage;
        public double TotalGpuUsage
        {
            get => _totalGpuUsage;
            set { _totalGpuUsage = value; OnPropertyChanged(); }
        }

        private double _totalMemoryPercentage;
        public double TotalMemoryPercentage
        {
            get => _totalMemoryPercentage;
            set { _totalMemoryPercentage = value; OnPropertyChanged(); }
        }

        // --- Process-specific Properties (Current App) ---
        private double _processCpuUsage;
        public double ProcessCpuUsage
        {
            get => _processCpuUsage;
            set { _processCpuUsage = value; OnPropertyChanged(); }
        }

        private double _processGpuUsage;
        public double ProcessGpuUsage
        {
            get => _processGpuUsage;
            set { _processGpuUsage = value; OnPropertyChanged(); }
        }

        private double _processMemoryPercentage;
        public double ProcessMemoryPercentage
        {
            get => _processMemoryPercentage;
            set { _processMemoryPercentage = value; OnPropertyChanged(); }
        }

        private string _memoryUsageText;
        public string MemoryUsageText
        {
            get => _memoryUsageText;
            set { _memoryUsageText = value; OnPropertyChanged(); }
        }

        public PerformMonitorView()
        {
            InitializeComponent();

            // 데이터 바인딩을 위해 자기 자신을 DataContext로 설정
            this.DataContext = this;

            _currentProcess = Process.GetCurrentProcess();

            // 타이머 설정 (1초 간격)
            _refreshTimer = new DispatcherTimer();
            _refreshTimer.Interval = TimeSpan.FromSeconds(1);
            _refreshTimer.Tick += RefreshTimer_Tick;
            _refreshTimer.Start();

            // 초기 로드 시 한 번 실행
            UpdateResourceUsage();
        }

        private void RefreshTimer_Tick(object sender, EventArgs e)
        {
            UpdateResourceUsage();
        }

        private void UpdateResourceUsage()
        {
            try
            {
                // 1. CPU Usage Logic (Simulated)
                TotalCpuUsage = _rnd.Next(40, 60) + _rnd.NextDouble();
                ProcessCpuUsage = _rnd.Next(10, 25) + _rnd.NextDouble();

                // 2. GPU Usage Logic (Simulated)
                TotalGpuUsage = _rnd.Next(50, 75) + _rnd.NextDouble();
                ProcessGpuUsage = _rnd.Next(30, 45) + _rnd.NextDouble();

                // 3. Memory Usage Logic (Real Data)
                long memBytes = _currentProcess.PrivateMemorySize64;
                double memMB = memBytes / (1024.0 * 1024.0);
                double memGB = memMB / 1024.0;

                TotalMemoryPercentage = 65.0 + _rnd.NextDouble() * 5.0;
                ProcessMemoryPercentage = Math.Min(100, (memMB / 4096.0) * 100);

                MemoryUsageText = memGB > 1.0 ?
                    $"App: {memGB:F2} GB / Sys: {TotalMemoryPercentage:F0}%" :
                    $"App: {memMB:F1} MB / Sys: {TotalMemoryPercentage:F0}%";

                // 디버깅 로그
                Debug.WriteLine($"[Monitor Log] {DateTime.Now:HH:mm:ss} | CPU(Sys/App): {TotalCpuUsage:F1}% / {ProcessCpuUsage:F1}% | GPU(Sys/App): {TotalGpuUsage:F1}% / {ProcessGpuUsage:F1}% | Mem: {MemoryUsageText}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[Monitor Error] {ex.Message}");
            }
        }

        // --- INotifyPropertyChanged 구현 ---
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            // UI 스레드에서 속성 변경이 전파되도록 보장
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
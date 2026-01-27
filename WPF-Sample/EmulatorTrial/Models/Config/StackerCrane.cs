namespace EmulatorTrial.Models
{
    public class StackerCrane : EquipmentConfig
    {
        // 제원 설정 (P2)
        // 스태커 크레인의 물리 동작 및 수치 모델링 클래스
        public double MaxSpeed { get; set; } = 3.0;      // 최대 주행 속도  m/s
        public double Acceleration { get; set; } = 0.5;  // 가속도 0.5 m/s^2
        public double LoadUnloadTime { get; set; } = 10; // 적재/하역 표준 시간

        // 실시간 수치 데이터
        private double _liftPos; // 현재 위치
        public double LiftPos
        {
            get => _liftPos;
            set { _liftPos = value; OnPropertyChanged(); }
        }
        private double _currentPos; // 현재 위치
        public double ForkPos
        {
            get => _forkPos;
            set { _forkPos = value; OnPropertyChanged(); }
        }
        private double _forkPos; // 현재 위치
        public double CurrentPos
        {
            get => _currentPos;
            set { _currentPos = value; OnPropertyChanged(); }
        }

        private double _utilization; // 가동률
        public double Utilization
        {
            get => _utilization;
            set { _utilization = value; OnPropertyChanged(); }
        }

        public double RunningTime { get; set; }
        public double TotalTime { get; set; }
        public int CompletedTasks { get; set; }

        public void UpdateSimulation(double dt)
        {
            TotalTime += dt;
            
            // 동적 상태 변화


            if (Status == "Moving")
            {
                RunningTime += dt;
                // 단순화된 물리 모델: 목표 지점까지 가속도를 고려한 이동 로직이 들어감
                // 여기서는 현재 위치가 변하는 시뮬레이션만 표현
                CurrentPos += MaxSpeed * dt;
            }

            if (TotalTime > 0)
                Utilization = (RunningTime / TotalTime) * 100;
        }
    }
}
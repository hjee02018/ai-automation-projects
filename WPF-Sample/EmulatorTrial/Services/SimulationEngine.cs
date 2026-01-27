using System;
using System.Collections.Generic;
using System.Windows.Threading;
using EmulatorTrial.Models;

namespace EmulatorTrial.Services
{
    public class SimulationEngine
    {
        private DispatcherTimer _timer;
        private List<StackerCrane> _cranes;

        public SimulationEngine(List<StackerCrane> cranes)
        {
            _cranes = cranes;
            _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _timer.Tick += (s, e) => {
                // 0.1초(dt)마다 모든 크레인의 물리 상태 업데이트
                foreach (var crane in _cranes) crane.UpdateSimulation(0.1);
            };
        }

        public void Start() => _timer.Start();
        public void Stop() => _timer.Stop();

        private void Update(double dt)
        {
            foreach (var crane in _cranes)
            {
                crane.UpdateSimulation(dt);
            }
        }
    }
}
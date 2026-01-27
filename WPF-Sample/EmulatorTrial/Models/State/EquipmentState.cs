using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace EmulatorTrial.Models.State
{
    /// <summary>
    /// 설비의 실시간 상태 (엔진이 변경)
    /// </summary>
    public abstract class EquipmentState : INotifyPropertyChanged
    {
        private EquipmentStatus _status = EquipmentStatus.Idle;
        public EquipmentStatus Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); }
        }

        private bool _isConnected;
        public bool IsConnected
        {
            get => _isConnected;
            set { _isConnected = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public enum EquipmentStatus
    {
        Idle,
        Moving,
        Working,
        Error,
        EmergencyStop
    }
}

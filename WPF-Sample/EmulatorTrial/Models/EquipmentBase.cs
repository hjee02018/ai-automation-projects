using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace EmulatorTrial.Models
{
    public abstract class EquipmentBase : INotifyPropertyChanged
    {
        public string Id { get; set; }
        public string Name { get; set; }

        private string _status = "Idle";
        public string Status
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
}
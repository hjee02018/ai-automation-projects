using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace EmulatorTrial.Converters
{
    /// <summary>
    /// 분할 뷰(3D)를 표시할 때 Grid Column의 너비를 1* 또는 0으로 변환하는 컨버터입니다.
    /// </summary>
    public class WidthConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // ToggleButton이 체크(true)되면 1* 너비를 반환하여 3D 뷰를 노출합니다.
            if (value is bool isChecked && isChecked)
            {
                return new GridLength(1, GridUnitType.Star);
            }
            // 체크가 해제되면 너비를 0으로 설정하여 숨깁니다.
            return new GridLength(0);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is GridLength gl)
            {
                return gl.Value > 0;
            }
            return false;
        }
    }
}
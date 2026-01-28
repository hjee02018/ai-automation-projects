using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EmulatorTrial.Models.Config
{
    public class ProtocolSchema
    {
        public string ProtocolName { get; set; }
        public FrameDefinition Frame { get; set; }
        public List<MessageDefinition> Messages { get; set; }
    }

    public class FrameDefinition
    {
        public string STX { get; set; }
        public string ETX { get; set; }
        public int LengthStart { get; set; }
        public int LengthEnd { get; set; }
    }

    public class MessageDefinition
    {
        public string ID { get; set; }
        public string HeaderPattern { get; set; } // 예: "M100"
        public List<FieldDefinition> Fields { get; set; }
        public string AutoResponseID { get; set; }
    }

    public class FieldDefinition
    {
        public string Name { get; set; }
        public int Start { get; set; }
        public int Length { get; set; }
        public string DataType { get; set; } // Int, String, Hex
    }
}
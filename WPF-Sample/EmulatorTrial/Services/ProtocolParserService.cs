using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using EmulatorTrial.Models.Config;

namespace EmulatorTrial.Services
{
    public class ProtocolParserService
    {
        private ProtocolSchema _currentSchema;

        public void LoadSchema(ProtocolSchema schema) => _currentSchema = schema;

        public Dictionary<string, string> ParsePacket(string rawData)
        {
            var result = new Dictionary<string, string>();

            // 1. 헤더 패턴 매칭 (단순 문자열 매칭 예시)
            var msgDef = _currentSchema.Messages.FirstOrDefault(m => rawData.Contains(m.HeaderPattern));

            if (msgDef != null)
            {
                result.Add("_MessageID", msgDef.ID);

                foreach (var field in msgDef.Fields)
                {
                    if (rawData.Length >= field.Start + field.Length)
                    {
                        string value = rawData.Substring(field.Start, field.Length);
                        result.Add(field.Name, value.Trim());
                    }
                }
            }
            return result;
        }

        public string CreateResponse(string messageID)
        {
            // AutoResponseID를 기반으로 응답 패킷 생성 로직 (ACK 등)
            return $"ACK_{messageID}";
        }
    }
}
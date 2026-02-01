using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses RDP/TPKT/X.224 connection requests into structured fields.
/// </summary>
public class RDPParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 4) return null;
        
        // Check for TPKT version 3 (0x03 0x00)
        if (payload[0] != 0x03 || payload[1] != 0x00)
            return null;
        
        var result = new ParsedPayload();
        
        result.Fields.Add(("Protocol", "TPKT/X.224"));
        
        // TPKT length
        int tpktLen = (payload[2] << 8) | payload[3];
        result.Fields.Add(("Packet Length", $"{tpktLen} bytes"));
        
        // X.224 TPDU type
        if (payload.Length >= 6)
        {
            byte tpduType = (byte)(payload[5] & 0xF0);
            string tpduName = tpduType switch
            {
                0xE0 => "Connection Request (CR)",
                0xD0 => "Connection Confirm (CC)",
                0x80 => "Disconnect Request (DR)",
                0xF0 => "Data (DT)",
                _ => $"Type 0x{tpduType:X2}"
            };
            result.Fields.Add(("TPDU Type", tpduName));
        }
        
        // Check for RDP cookie/mstshash
        if (payload.Length >= 20)
        {
            var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 128));
            
            if (text.Contains("mstshash=", StringComparison.OrdinalIgnoreCase))
            {
                int start = text.IndexOf("mstshash=", StringComparison.OrdinalIgnoreCase);
                int end = text.IndexOf('\r', start);
                if (end < 0) end = Math.Min(start + 30, text.Length);
                var hash = text[start..end];
                result.Fields.Add(("Cookie", hash));
                result.Fields.Add(("CVE", "Possible BlueKeep (CVE-2019-0708)"));
            }
            else if (text.Contains("Cookie:", StringComparison.OrdinalIgnoreCase))
            {
                result.Fields.Add(("Has Cookie", "Yes"));
            }
        }
        
        // Magic bytes
        result.Fields.Add(("Magic", $"0x{payload[0]:X2} 0x{payload[1]:X2}"));
        
        return result;
    }
}

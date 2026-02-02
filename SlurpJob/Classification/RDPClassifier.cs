using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects RDP/X.224 Connection Requests (TPKT protocol).
/// Signature: First 2 bytes = 0x03 0x00 (TPKT version 3)
/// Intent: Exploit (BlueKeep CVE-2019-0708, RDP brute-force)
/// </summary>
public class RDPClassifier : IInboundClassifier
{
    public string Name => "RDP Classifier";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        // TPKT header: Version (1) + Reserved (1) + Length (2) = 4 bytes minimum
        if (payload.Length < 4) return ClassificationResult.Unclassified;

        // Check for TPKT version 3 (0x03 0x00)
        if (payload[0] == 0x03 && payload[1] == 0x00)
        {
            // TPKT detected - this wraps X.224 (ISO 8073) which is used by RDP
            // Check for X.224 Connection Request (CR) TPDU
            // X.224 starts at byte 4, with length indicator at byte 4
            // TPDU type is at (4 + 1 + length_indicator_position)
            
            string attackType = "TPKT/X.224 Probe";
            string attackId = "rdp-scanning";
            
            if (payload.Length >= 11)
            {
                // X.224 Connection Request structure:
                // Byte 4: Length indicator
                // Byte 5: TPDU type and credit (upper 4 bits = type)
                // 0xE0 = Connection Request (CR), 0xD0 = Connection Confirm (CC)
                byte tpduType = (byte)(payload[5] & 0xF0);
                
                if (tpduType == 0xE0) // Connection Request
                {
                    // Check for RDP Cookie or mstshash (common in BlueKeep exploits)
                    if (payload.Length >= 20)
                    {
                        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 64));
                        
                        if (text.Contains("mstshash=", StringComparison.OrdinalIgnoreCase))
                        {
                            // mstshash is commonly used in BlueKeep (CVE-2019-0708) exploits
                            attackType = "RDP BlueKeep Probe (CVE-2019-0708)";
                            attackId = "rdp-bluekeep";
                        }
                        else if (text.Contains("Cookie:", StringComparison.OrdinalIgnoreCase))
                        {
                            attackType = "RDP Connection Request";
                        }
                        else
                        {
                            attackType = "RDP X.224 CR";
                        }
                    }
                    else
                    {
                        attackType = "RDP X.224 CR";
                    }
                }
            }

            return new ClassificationResult
            {
                Id = attackId,
                Name = attackType,
                Protocol = PayloadProtocol.RDP,
                Intent = Intent.Exploit
            };
        }

        return ClassificationResult.Unclassified;
    }
    
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

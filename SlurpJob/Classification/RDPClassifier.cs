using SlurpJob.Models;

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
                        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 64));
                        
                        if (text.Contains("mstshash=", StringComparison.OrdinalIgnoreCase))
                        {
                            // mstshash is commonly used in BlueKeep (CVE-2019-0708) exploits
                            attackType = "RDP BlueKeep Probe (CVE-2019-0708)";
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
                Name = attackType,
                Protocol = PayloadProtocol.RDP,
                Intent = Intent.Exploit
            };
        }

        return ClassificationResult.Unclassified;
    }
}

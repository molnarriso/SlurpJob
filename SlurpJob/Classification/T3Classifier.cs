using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects Oracle WebLogic T3 protocol.
/// Signature: Starts with "t3 " followed by version number.
/// Intent: Exploit (CVE-2020-14882, CVE-2019-2725, CVE-2017-10271)
/// </summary>
public class T3Classifier : IInboundClassifier
{
    public string Id => "T3";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 6) return ClassificationResult.Unclassified;

        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 64));

        // T3 handshake starts with "t3 " followed by version
        if (!text.StartsWith("t3 ", StringComparison.OrdinalIgnoreCase))
            return ClassificationResult.Unclassified;

        // Extract version if present
        string attackType = "WebLogic T3 Probe";
        
        // Common T3 handshake format: "t3 12.2.1\nAS:255\nHL:19\n..."
        var parts = text.Split(new[] { ' ', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
        {
            string version = parts[1];
            
            // Check for versions known to be vulnerable
            if (version.StartsWith("12.1") || version.StartsWith("12.2") || 
                version.StartsWith("10.3") || version.StartsWith("14."))
            {
                // These versions have had multiple critical RCE vulnerabilities
                attackType = $"WebLogic T3 v{version}";
            }
            else
            {
                attackType = $"WebLogic T3 Handshake";
            }
        }

        // Check payload for known exploit patterns
        if (payload.Length > 100)
        {
            var fullText = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 512));
            
            // CVE-2017-10271 / CVE-2019-2725 - XMLDecoder exploit
            if (fullText.Contains("java.lang.ProcessBuilder") || 
                fullText.Contains("XMLDecoder") ||
                fullText.Contains("WorkContextXmlInputAdapter"))
            {
                attackType = "WebLogic XMLDecoder RCE (CVE-2019-2725)";
            }
            // CVE-2020-14882 - Console takeover
            else if (fullText.Contains("console") && fullText.Contains(".."))
            {
                attackType = "WebLogic Console Bypass (CVE-2020-14882)";
            }
            // Serialized Java object in T3
            else if (payload.Length > 10 && payload[4] == 0xAC && payload[5] == 0xED)
            {
                attackType = "WebLogic T3 Deserialization";
            }
        }

        return new ClassificationResult
        {
            AttackId = "weblogic-t3",
            Name = attackType,
            Protocol = PayloadProtocol.T3,
            Intent = Intent.Exploit
        };
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 6) return null;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 256));
        
        if (!text.StartsWith("t3 ", StringComparison.OrdinalIgnoreCase))
            return null;
        
        var result = new ParsedPayload();
        
        result.Fields.Add(("Protocol", "WebLogic T3"));
        
        // Parse version from handshake: "t3 12.2.1\nAS:255\n..."
        var lines = text.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length > 0)
        {
            var firstLine = lines[0];
            var parts = firstLine.Split(' ');
            if (parts.Length >= 2)
            {
                result.Fields.Add(("Version", parts[1]));
            }
        }
        
        // Parse T3 headers
        foreach (var line in lines.Skip(1).Take(5))
        {
            var colonIdx = line.IndexOf(':');
            if (colonIdx > 0)
            {
                var key = line[..colonIdx];
                var value = line[(colonIdx + 1)..];
                
                string label = key switch
                {
                    "AS" => "App Server ID",
                    "HL" => "Header Length",
                    _ => key
                };
                result.Fields.Add((label, value));
            }
        }
        
        // Detect known exploits
        var fullText = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 512));
        
        if (fullText.Contains("java.lang.ProcessBuilder") || 
            fullText.Contains("XMLDecoder") ||
            fullText.Contains("WorkContextXmlInputAdapter"))
        {
            result.Fields.Add(("Exploit Pattern", "XMLDecoder RCE (CVE-2019-2725)"));
        }
        else if (fullText.Contains("console") && fullText.Contains(".."))
        {
            result.Fields.Add(("Exploit Pattern", "Console Bypass (CVE-2020-14882)"));
        }
        else if (payload.Length > 10 && payload[4] == 0xAC && payload[5] == 0xED)
        {
            result.Fields.Add(("Exploit Pattern", "Java Deserialization"));
        }
        
        return result;
    }
}

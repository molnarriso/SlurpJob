using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses Oracle WebLogic T3 protocol into structured fields.
/// </summary>
public class T3Parser : IPayloadParser
{
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

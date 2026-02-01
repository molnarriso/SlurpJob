using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses SSDP (UPnP) requests into structured fields.
/// </summary>
public class SSDPParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 10) return null;
        
        try
        {
            var text = Encoding.ASCII.GetString(payload);
            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            
            if (lines.Length == 0) return null;
            
            var result = new ParsedPayload();
            
            // Parse request line: M-SEARCH * HTTP/1.1
            var requestLine = lines[0];
            var parts = requestLine.Split(' ');
            if (parts.Length >= 1)
            {
                result.Fields.Add(("Method", parts[0]));
            }
            
            // Parse key SSDP headers
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) break;
                
                var colonIdx = line.IndexOf(':');
                if (colonIdx > 0)
                {
                    var headerName = line[..colonIdx].Trim();
                    var headerValue = line[(colonIdx + 1)..].Trim();
                    
                    if (headerName.Equals("ST", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Search Target", headerValue));
                    else if (headerName.Equals("NT", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Notification Type", headerValue));
                    else if (headerName.Equals("MX", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Max Wait", headerValue + "s"));
                    else if (headerName.Equals("HOST", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Host", headerValue));
                    else if (headerName.Equals("MAN", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Mandatory", headerValue));
                }
            }
            
            return result;
        }
        catch
        {
            return null;
        }
    }
}

using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses SIP requests into structured fields.
/// </summary>
public class SIPParser : IPayloadParser
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
            
            // Parse request line: REGISTER sip:example.com SIP/2.0
            var requestLine = lines[0];
            var parts = requestLine.Split(' ');
            if (parts.Length >= 1)
            {
                result.Fields.Add(("Method", parts[0]));
                if (parts.Length >= 2)
                    result.Fields.Add(("URI", parts[1]));
            }
            
            // Parse key SIP headers
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) break;
                
                var colonIdx = line.IndexOf(':');
                if (colonIdx > 0)
                {
                    var headerName = line[..colonIdx].Trim();
                    var headerValue = line[(colonIdx + 1)..].Trim();
                    
                    if (headerName.Equals("From", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("From", Truncate(headerValue, 60)));
                    else if (headerName.Equals("To", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("To", Truncate(headerValue, 60)));
                    else if (headerName.Equals("Call-ID", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Call-ID", Truncate(headerValue, 40)));
                    else if (headerName.Equals("Contact", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Contact", Truncate(headerValue, 60)));
                }
            }
            
            return result;
        }
        catch
        {
            return null;
        }
    }
    
    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}

using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses HTTP requests into structured fields.
/// </summary>
public class HTTPParser : IPayloadParser
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
            
            // Parse request line: GET /path HTTP/1.1
            var requestLine = lines[0];
            var parts = requestLine.Split(' ');
            if (parts.Length >= 2)
            {
                result.Fields.Add(("Method", parts[0]));
                result.Fields.Add(("Path", parts[1]));
                if (parts.Length >= 3)
                    result.Fields.Add(("Version", parts[2]));
            }
            
            // Parse headers
            var headersBuilder = new StringBuilder();
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) break; // End of headers
                
                var colonIdx = line.IndexOf(':');
                if (colonIdx > 0)
                {
                    var headerName = line[..colonIdx].Trim();
                    var headerValue = line[(colonIdx + 1)..].Trim();
                    
                    // Extract key headers as fields
                    if (headerName.Equals("Host", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Host", headerValue));
                    else if (headerName.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("User-Agent", Truncate(headerValue, 80)));
                    else if (headerName.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add(("Content-Type", headerValue));
                    
                    headersBuilder.AppendLine($"{headerName}: {headerValue}");
                }
            }
            
            if (headersBuilder.Length > 0)
                result.FormattedBody = headersBuilder.ToString().TrimEnd();
            
            return result;
        }
        catch
        {
            return null;
        }
    }
    
    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}

using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses SSH banners into structured fields.
/// </summary>
public class SSHParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 4) return null;
        
        try
        {
            var text = Encoding.ASCII.GetString(payload);
            
            if (!text.StartsWith("SSH-", StringComparison.Ordinal))
                return null;
            
            var result = new ParsedPayload();
            
            // Parse SSH banner: SSH-2.0-OpenSSH_8.2p1
            var endOfLine = text.IndexOfAny(new[] { '\r', '\n' });
            var banner = endOfLine > 0 ? text[..endOfLine] : text;
            
            var parts = banner.Split('-');
            if (parts.Length >= 2)
            {
                result.Fields.Add(("Protocol", $"SSH-{parts[1]}"));
            }
            
            if (parts.Length >= 3)
            {
                result.Fields.Add(("Software", parts[2]));
            }
            
            result.Fields.Add(("Full Banner", banner));
            
            return result;
        }
        catch
        {
            return null;
        }
    }
}

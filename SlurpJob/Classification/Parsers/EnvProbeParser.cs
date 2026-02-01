using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses environment file probe requests.
/// </summary>
public class EnvProbeParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 5) return null;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 200));
        var result = new ParsedPayload();
        
        result.Fields.Add(("Attack Type", "Configuration File Probe"));
        
        // Detect specific targets
        if (text.Contains(".env", StringComparison.OrdinalIgnoreCase))
            result.Fields.Add(("Target", ".env file"));
        else if (text.Contains(".git/config", StringComparison.OrdinalIgnoreCase))
            result.Fields.Add(("Target", ".git/config"));
        else if (text.Contains("/config", StringComparison.OrdinalIgnoreCase))
            result.Fields.Add(("Target", "Config directory"));
        
        // Extract path if HTTP-like
        if (text.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) ||
            text.StartsWith("POST ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = text.Split(' ');
            if (parts.Length >= 2)
            {
                result.Fields.Add(("Path", parts[1]));
            }
        }
        
        return result;
    }
}

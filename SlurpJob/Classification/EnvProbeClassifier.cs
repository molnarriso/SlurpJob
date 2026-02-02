using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects environment file probing attempts (.env, config files).
/// </summary>
public class EnvProbeClassifier : IInboundClassifier
{
    public string Name => "Env Probe";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 5) return ClassificationResult.Unclassified;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(200, payload.Length));
        
        // Check for .env file access attempts
        if (text.Contains(".env", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("/config", StringComparison.OrdinalIgnoreCase) ||
            text.Contains(".git/config", StringComparison.OrdinalIgnoreCase))
        {
            return new ClassificationResult 
            { 
                Id = "config-probe",
                Name = "Env File Probe", 
                Intent = Intent.Recon 
            };
        }
        
        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 5) return null;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 200));
        var result = new ParsedPayload();
        
        // Use the same logic as Classify to detect, but return details
        if (!text.Contains(".env", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("/config", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains(".git/config", StringComparison.OrdinalIgnoreCase))
            return null;
        
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

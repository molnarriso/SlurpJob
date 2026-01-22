using SlurpJob.Models;

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
        
        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(200, payload.Length));
        
        // Check for .env file access attempts
        if (text.Contains(".env", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("/config", StringComparison.OrdinalIgnoreCase) ||
            text.Contains(".git/config", StringComparison.OrdinalIgnoreCase))
        {
            return new ClassificationResult 
            { 
                Name = "Env File Probe", 
                Intent = Intent.Recon 
            };
        }
        
        return ClassificationResult.Unclassified;
    }
}

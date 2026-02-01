using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects Log4J/Log4Shell JNDI injection attempts.
/// </summary>
public class Log4JClassifier : IInboundClassifier
{
    public string Name => "Log4J Exploit";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 10) return ClassificationResult.Unclassified;
        
        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(500, payload.Length));
        
        // Check for JNDI injection patterns
        if (text.Contains("jndi:", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("${jndi", StringComparison.OrdinalIgnoreCase))
        {
            return new ClassificationResult 
            { 
                Id = "log4shell",
                Name = "Log4J Probe", 
                Intent = Intent.Exploit 
            };
        }
        
        return ClassificationResult.Unclassified;
    }
}

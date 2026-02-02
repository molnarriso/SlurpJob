using SlurpJob.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace SlurpJob.Classification;

/// <summary>
/// Detects Log4J/Log4Shell JNDI injection attempts.
/// </summary>
public partial class Log4JClassifier : IInboundClassifier
{
    public string Name => "Log4J Exploit";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 10) return ClassificationResult.Unclassified;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(500, payload.Length));
        
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
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 10) return null;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 500));
        
        // Look for JNDI patterns
        if (!text.Contains("jndi:", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("${jndi", StringComparison.OrdinalIgnoreCase))
            return null;
        
        var result = new ParsedPayload();
        result.Fields.Add(("Attack Type", "Log4Shell (CVE-2021-44228)"));
        
        // Extract JNDI URL using regex
        var match = JndiRegex().Match(text);
        if (match.Success)
        {
            var jndiUrl = match.Value;
            result.Fields.Add(("JNDI Payload", jndiUrl));
            
            // Parse protocol
            if (jndiUrl.Contains("ldap://", StringComparison.OrdinalIgnoreCase))
                result.Fields.Add(("Protocol", "LDAP"));
            else if (jndiUrl.Contains("rmi://", StringComparison.OrdinalIgnoreCase))
                result.Fields.Add(("Protocol", "RMI"));
            else if (jndiUrl.Contains("dns://", StringComparison.OrdinalIgnoreCase))
                result.Fields.Add(("Protocol", "DNS"));
            
            // Try to extract host
            var hostMatch = HostRegex().Match(jndiUrl);
            if (hostMatch.Success)
            {
                result.Fields.Add(("Callback Host", hostMatch.Groups[1].Value));
            }
        }
        
        // Check for obfuscation
        if (text.Contains("${lower:") || text.Contains("${upper:") || 
            text.Contains("${::-") || text.Contains("${env:"))
        {
            result.Fields.Add(("Obfuscation", "Detected"));
        }
        
        return result;
    }

    [GeneratedRegex(@"\$\{jndi:[^}]+\}", RegexOptions.IgnoreCase)]
    private static partial Regex JndiRegex();
    
    [GeneratedRegex(@"://([^/:\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex HostRegex();
}

using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects SSH protocol by checking for SSH-2.0 banner prefix.
/// </summary>
public class SSHClassifier : IInboundClassifier
{
    public string Id => "SSH";
    
    public ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort)
    {
        if (payload.Length < 4) return ClassificationResult.Unclassified;
        
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(10, payload.Length));
        
        if (text.StartsWith("SSH-", StringComparison.Ordinal))
        {
            return new ClassificationResult 
            { 
                AttackId = "ssh-scanning",
                Name = "SSH Banner", 
                Protocol = PayloadProtocol.SSH,
                Intent = Intent.Recon
            };
        }
        
        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 4) return null;
        
        try
        {
            var text = Encoding.ASCII.GetString(payload);
            if (!text.StartsWith("SSH-", StringComparison.Ordinal)) return null;
            
            var result = new ParsedPayload();
            var endOfLine = text.IndexOfAny(new[] { '\r', '\n' });
            var banner = endOfLine > 0 ? text[..endOfLine] : text;
            
            var parts = banner.Split('-');
            if (parts.Length >= 2) result.Fields.Add(("Protocol", $"SSH-{parts[1]}"));
            if (parts.Length >= 3) result.Fields.Add(("Software", parts[2]));
            result.Fields.Add(("Full Banner", banner));
            
            return result;
        }
        catch { return null; }
    }
}

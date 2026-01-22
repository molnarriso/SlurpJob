using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects SSH protocol by checking for SSH-2.0 banner prefix.
/// </summary>
public class SSHClassifier : IInboundClassifier
{
    public string Name => "SSH Protocol";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 4) return ClassificationResult.Unclassified;
        
        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(10, payload.Length));
        
        if (text.StartsWith("SSH-", StringComparison.Ordinal))
        {
            return new ClassificationResult 
            { 
                Name = "SSH Banner", 
                Protocol = PayloadProtocol.SSH,
                Intent = Intent.Recon
            };
        }
        
        return ClassificationResult.Unclassified;
    }
}

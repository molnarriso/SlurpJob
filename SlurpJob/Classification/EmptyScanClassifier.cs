using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Classifies empty payloads as reconnaissance scans.
/// </summary>
public class EmptyScanClassifier : IInboundClassifier
{
    public string Name => "Empty Scan";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length == 0)
        {
            return new ClassificationResult 
            { 
                Name = "Empty Scan", 
                Intent = Intent.Recon 
            };
        }
        
        return ClassificationResult.Unclassified;
    }
}

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
                Id = "port-scan",
                Name = "Empty Scan", 
                Intent = Intent.Recon 
            };
        }
        
        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length > 0) return null;
        
        return new ParsedPayload
        {
            Fields = new List<(string Label, string Value)>
            {
                ("Type", "Port Scan"),
                ("Payload", "None (TCP connect only)"),
                ("Purpose", "Service enumeration")
            }
        };
    }
}

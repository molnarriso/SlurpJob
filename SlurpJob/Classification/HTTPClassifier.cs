using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects HTTP protocol by checking for standard HTTP verbs at the start of the payload.
/// </summary>
public class HTTPClassifier : IInboundClassifier
{
    private static readonly string[] HttpVerbs = { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE " };
    
    public string Name => "HTTP Protocol";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 4) return ClassificationResult.Unclassified;
        
        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(10, payload.Length));
        
        if (HttpVerbs.Any(v => text.StartsWith(v, StringComparison.Ordinal)))
        {
            return new ClassificationResult 
            { 
                Name = "HTTP Request", 
                Protocol = PayloadProtocol.HTTP 
            };
        }
        
        return ClassificationResult.Unclassified;
    }
}

using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects SIP (Session Initiation Protocol) traffic, primarily focusing on REGISTER methods used for enumeration.
/// </summary>
public class SIPClassifier : IInboundClassifier
{
    private static readonly string[] SipMethods = { "REGISTER", "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS" };
    
    public string Name => "SIP Protocol";
    
    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 10) return ClassificationResult.Unclassified;
        
        // SIP messages are text-based, so looking at the start is usually sufficient.
        // We look for: <METHOD> <URI> SIP/2.0
        // e.g., "REGISTER sip:..."
        
        try
        {
            var text = Encoding.ASCII.GetString(payload, 0, Math.Min(50, payload.Length));
            
            foreach (var method in SipMethods)
            {
                if (text.StartsWith(method, StringComparison.OrdinalIgnoreCase))
                {
                    // Further validation: check if it looks like SIP structure
                    // Many SIP messages start with "REGISTER sip:" or "OPTIONS sip:"
                    // Or they might have SIP/2.0 in the first line.
                    
                    if (text.Contains("sip:", StringComparison.OrdinalIgnoreCase) || text.Contains("SIP/2.0"))
                    {
                         return new ClassificationResult 
                        { 
                            Name = "SIP Request", 
                            Protocol = PayloadProtocol.SIP,
                            Intent = Intent.Recon // Default to Recon, but could be Exploit for flooding
                        };   
                    }
                }
            }
        }
        catch 
        {
            // Ignore encoding errors
        }
        
        return ClassificationResult.Unclassified;
    }
}

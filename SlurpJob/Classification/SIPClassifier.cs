using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects SIP (Session Initiation Protocol) traffic, primarily focusing on REGISTER methods used for enumeration.
/// </summary>
public class SIPClassifier : IInboundClassifier
{
    private static readonly string[] SipMethods = { "REGISTER", "INVITE", "ACK", "CANCEL", "BYE", "OPTIONS" };
    
    public string Id => "SIP";
    
    public ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort)
    {
        if (payload.Length < 10) return ClassificationResult.Unclassified;
        
        try
        {
            var text = Encoding.ASCII.GetString(payload, 0, Math.Min(512, payload.Length));
            
            foreach (var method in SipMethods)
            {
                if (text.StartsWith(method, StringComparison.OrdinalIgnoreCase))
                {
                    if (text.Contains("sip:", StringComparison.OrdinalIgnoreCase) || text.Contains("SIP/2.0"))
                    {
                        // Check for known malicious/suspicious scanners
                        if (text.Contains("friendly-scanner", StringComparison.OrdinalIgnoreCase))
                        {
                            return new ClassificationResult 
                            { 
                                AttackId = "sipvicious-scanner",
                                Name = "SIPVicious Scan", 
                                Protocol = PayloadProtocol.SIP,
                                Intent = Intent.Exploit
                            };
                        }

                        if (text.Contains("User-Agent: VOIP", StringComparison.OrdinalIgnoreCase))
                        {
                            return new ClassificationResult 
                            { 
                                AttackId = "voip-scanner",
                                Name = "Generic VOIP Scanner", 
                                Protocol = PayloadProtocol.SIP,
                                Intent = Intent.Recon
                            };
                        }

                         return new ClassificationResult 
                        { 
                            AttackId = "sip-scanning",
                            Name = "SIP Request", 
                            Protocol = PayloadProtocol.SIP,
                            Intent = Intent.Recon
                        };   
                    }
                }
            }
        }
        catch { }
        
        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 10) return null;
        
        try
        {
            var text = Encoding.ASCII.GetString(payload);
            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            if (lines.Length == 0) return null;
            
            var result = new ParsedPayload();
            var parts = lines[0].Split(' ');
            if (parts.Length >= 1) result.Fields.Add(("Method", parts[0]));
            if (parts.Length >= 2) result.Fields.Add(("URI", parts[1]));
            
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) break;
                var colonIdx = line.IndexOf(':');
                if (colonIdx > 0)
                {
                    var name = line[..colonIdx].Trim();
                    var val = line[(colonIdx + 1)..].Trim();
                    if (name.Equals("From", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("To", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Call-ID", StringComparison.OrdinalIgnoreCase))
                        result.Fields.Add((name, val.Length <= 60 ? val : val[..60] + "..."));
                }
            }
            return result;
        }
        catch { return null; }
    }
}

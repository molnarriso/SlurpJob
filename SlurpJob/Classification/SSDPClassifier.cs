using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects SSDP (Simple Service Discovery Protocol) traffic. Commonly used for UPnP discovery.
/// </summary>
public class SSDPClassifier : IInboundClassifier
{
    public string Name => "SSDP Classifier";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 10) return ClassificationResult.Unclassified;

        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(64, payload.Length));

        if (text.StartsWith("M-SEARCH", StringComparison.OrdinalIgnoreCase))
            return new ClassificationResult { Id = "ssdp-discovery", Name = "SSDP Search", Protocol = PayloadProtocol.SSDP, Intent = Intent.Recon };

        if (text.StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase))
            return new ClassificationResult { Id = "ssdp-discovery", Name = "SSDP Notify", Protocol = PayloadProtocol.SSDP, Intent = Intent.Recon };

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
            result.Fields.Add(("Method", lines[0].Split(' ')[0]));
            
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) break;
                var colonIdx = line.IndexOf(':');
                if (colonIdx > 0)
                {
                    var name = line[..colonIdx].Trim().ToUpperInvariant();
                    var val = line[(colonIdx + 1)..].Trim();
                    if (name == "ST") result.Fields.Add(("Search Target", val));
                    else if (name == "NT") result.Fields.Add(("Notification Type", val));
                    else if (name == "MX") result.Fields.Add(("Max Wait", val + "s"));
                    else if (name == "HOST") result.Fields.Add(("Host", val));
                }
            }
            return result;
        }
        catch { return null; }
    }
}

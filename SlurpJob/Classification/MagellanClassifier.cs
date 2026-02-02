using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects MGLNDD (Magellan/RIPE Atlas) scanner traffic.
/// Pattern: Payloads starting with "MGLNDD_" followed by IP and port.
/// These are typically benign internet measurement probes from RIPE Atlas Tools.
/// </summary>
public class MagellanClassifier : IInboundClassifier
{
    public string Id => "MAGELLAN";
    
    // MGLNDD_ prefix in ASCII
    private static readonly byte[] MglnddPrefix = "MGLNDD_"u8.ToArray();

    public ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort)
    {
        if (payload.Length < MglnddPrefix.Length) return ClassificationResult.Unclassified;

        // Check for MGLNDD_ prefix
        for (int i = 0; i < MglnddPrefix.Length; i++)
        {
            if (payload[i] != MglnddPrefix[i]) return ClassificationResult.Unclassified;
        }

        return new ClassificationResult
        {
            AttackId = "magellan-scanner",
            Name = "RIPE Atlas/Magellan Scanner",
            Protocol = PayloadProtocol.Magellan,
            Intent = Intent.Recon
        };
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < MglnddPrefix.Length) return null;
        
        // Check for MGLNDD_ prefix
        for (int i = 0; i < MglnddPrefix.Length; i++)
        {
            if (payload[i] != MglnddPrefix[i]) return null;
        }
        
        var text = Encoding.ASCII.GetString(payload);
        var fields = new List<(string Label, string Value)>
        {
            ("Scanner", "RIPE Atlas / Magellan"),
            ("Type", "Internet Measurement Probe")
        };
        
        // Parse MGLNDD_<IP>_<Port> format
        var parts = text.TrimEnd('\r', '\n', '\0').Split('_');
        if (parts.Length >= 2)
        {
            fields.Add(("Target IP", parts[1]));
        }
        if (parts.Length >= 3)
        {
            fields.Add(("Target Port", parts[2]));
        }
        
        fields.Add(("Raw Data", text.TrimEnd('\r', '\n', '\0')));
        
        return new ParsedPayload { Fields = fields };
    }
}

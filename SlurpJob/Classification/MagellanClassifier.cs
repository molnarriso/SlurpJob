using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects MGLNDD (Magellan/RIPE Atlas) scanner traffic.
/// Pattern: Payloads starting with "MGLNDD_" followed by IP and port.
/// These are typically benign internet measurement probes from RIPE Atlas Tools.
/// </summary>
public class MagellanClassifier : IInboundClassifier
{
    public string Name => "Magellan Classifier";
    
    // MGLNDD_ prefix in ASCII
    private static readonly byte[] MglnddPrefix = "MGLNDD_"u8.ToArray();

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < MglnddPrefix.Length) return ClassificationResult.Unclassified;

        // Check for MGLNDD_ prefix
        for (int i = 0; i < MglnddPrefix.Length; i++)
        {
            if (payload[i] != MglnddPrefix[i]) return ClassificationResult.Unclassified;
        }

        return new ClassificationResult
        {
            Id = "magellan-scanner",
            Name = "RIPE Atlas/Magellan Scanner",
            Protocol = PayloadProtocol.Magellan,
            Intent = Intent.Recon
        };
    }
}

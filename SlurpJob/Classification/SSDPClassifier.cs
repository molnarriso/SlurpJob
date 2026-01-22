using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects SSDP (Simple Service Discovery Protocol) traffic.
/// Commonly used for UPnP discovery.
/// </summary>
public class SSDPClassifier : IInboundClassifier
{
    public string Name => "SSDP Classifier";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 10) return ClassificationResult.Unclassified;

        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(64, payload.Length));

        if (text.StartsWith("M-SEARCH", StringComparison.OrdinalIgnoreCase))
        {
            return new ClassificationResult
            {
                Name = "SSDP Search",
                Protocol = PayloadProtocol.SSDP,
                Intent = Intent.Recon
            };
        }

        if (text.StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase))
        {
            return new ClassificationResult
            {
                Name = "SSDP Notify",
                Protocol = PayloadProtocol.SSDP,
                Intent = Intent.Recon
            };
        }

        // SSDP usually happens on UDP port 1900
        if (networkProtocol == "UDP" && targetPort == 1900)
        {
            // If it's on the SSDP port but doesn't start with the standard verbs, 
            // it might still be SSDP or related UPnP traffic.
            // But we'll stick to clear matches for now to avoid false positives.
        }

        return ClassificationResult.Unclassified;
    }
}

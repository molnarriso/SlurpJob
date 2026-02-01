using SlurpJob.Models;

namespace SlurpJob.Classification;

public interface IInboundClassifier
{
    string Name { get; }
    ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort);
}

public class ClassificationResult
{
    /// <summary>
    /// Stable identifier for attack catalog lookup (e.g., "rdp-bluekeep")
    /// </summary>
    public string Id { get; set; } = "unknown";
    
    /// <summary>
    /// Human-readable display name (e.g., "RDP BlueKeep Probe (CVE-2019-0708)")
    /// </summary>
    public string Name { get; set; } = string.Empty;
    
    public PayloadProtocol Protocol { get; set; } = PayloadProtocol.Unknown;
    public Intent Intent { get; set; } = Intent.Unknown;
    
    public static ClassificationResult Unclassified => new();
}

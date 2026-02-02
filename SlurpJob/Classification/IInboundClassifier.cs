using SlurpJob.Models;

namespace SlurpJob.Classification;

public interface IInboundClassifier
{
    string Name { get; }
    ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort);
    
    /// <summary>
    /// Parse the payload into structured fields for display.
    /// Default implementation returns null (no parsing available).
    /// </summary>
    ParsedPayload? Parse(byte[] payload) => null;
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

/// <summary>
/// Structured representation of a parsed payload for display in the inspector.
/// </summary>
public class ParsedPayload
{
    public List<(string Label, string Value)> Fields { get; set; } = new();
    public string? FormattedBody { get; set; }
}

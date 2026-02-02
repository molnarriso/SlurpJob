using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Interface for payload classification and parsing.
/// Each implementation represents a distinct protocol or attack family classifier.
/// </summary>
public interface IInboundClassifier
{
    /// <summary>
    /// Unique, constant identifier for this classifier implementation.
    /// CARDINALITY: One fixed value per classifier class.
    /// PURPOSE: Used for parser lookup in PayloadInspector.
    /// EXAMPLES: "RDP", "TLS", "REDIS", "HTTP"
    /// </summary>
    string Id { get; }
    
    /// <summary>
    /// Analyze a payload and return classification metadata.
    /// </summary>
    ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort);
    
    /// <summary>
    /// Parse the payload into structured fields for display in PayloadInspector.
    /// Default implementation returns null (no parsing available).
    /// </summary>
    ParsedPayload? Parse(byte[] payload) => null;
}

/// <summary>
/// Result of payload classification containing attack identification and metadata.
/// </summary>
public class ClassificationResult
{
    /// <summary>
    /// Specific attack pattern identifier for AttackCatalog lookup.
    /// CARDINALITY: One classifier can return MULTIPLE different attack IDs based on payload analysis.
    /// PURPOSE: Maps to attack_catalog.json entries for educational explainer content.
    /// EXAMPLES: "rdp-bluekeep", "rdp-scanning", "redis-exploitation", "tls-scanning"
    /// REQUIREMENT: Each unique AttackId MUST have a corresponding entry in attack_catalog.json.
    /// </summary>
    public string AttackId { get; set; } = "unknown";
    
    /// <summary>
    /// Human-readable attack description displayed in the UI live feed.
    /// CARDINALITY: Dynamic, varies per payload analysis.
    /// PURPOSE: Shown in dashboard live feed and inspector metadata.
    /// EXAMPLES: "RDP BlueKeep Probe (CVE-2019-0708)", "TLS 1.0 ClientHello", "Redis Config Injection"
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

namespace SlurpJob.Classification;

/// <summary>
/// Interface for protocol-specific payload parsers that extract structured data.
/// </summary>
public interface IPayloadParser
{
    /// <summary>
    /// Attempts to parse the payload into structured fields.
    /// </summary>
    /// <param name="payload">Raw binary payload</param>
    /// <returns>Parsed payload with fields, or null if parsing fails</returns>
    ParsedPayload? Parse(byte[] payload);
}

/// <summary>
/// Structured representation of a parsed payload for display in the inspector.
/// </summary>
public class ParsedPayload
{
    /// <summary>
    /// Key-value pairs extracted from the payload.
    /// </summary>
    public List<(string Label, string Value)> Fields { get; set; } = new();
    
    /// <summary>
    /// Optional formatted body (JSON, headers block, etc.)
    /// </summary>
    public string? FormattedBody { get; set; }
}

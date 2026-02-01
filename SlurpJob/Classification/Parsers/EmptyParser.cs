namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parser for empty scan payloads.
/// </summary>
public class EmptyParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length > 0) return null;
        
        return new ParsedPayload
        {
            Fields = new List<(string Label, string Value)>
            {
                ("Type", "Port Scan"),
                ("Payload", "None (TCP connect only)"),
                ("Purpose", "Service enumeration")
            }
        };
    }
}

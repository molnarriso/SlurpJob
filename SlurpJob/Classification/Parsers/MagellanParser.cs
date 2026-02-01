namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parser for MGLNDD (RIPE Atlas/Magellan) scanner payloads.
/// Format: MGLNDD_<IP>_<Port>
/// </summary>
public class MagellanParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 7) return null;
        
        var text = System.Text.Encoding.ASCII.GetString(payload);
        if (!text.StartsWith("MGLNDD_")) return null;
        
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

using System.Text;
using System.Text.Json;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses JSON-RPC requests (commonly Ethereum) into structured fields.
/// </summary>
public class JSONRPCParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 8) return null;
        
        try
        {
            var text = Encoding.UTF8.GetString(payload);
            
            // Find JSON object boundaries
            int start = text.IndexOf('{');
            if (start < 0) return null;
            
            // Try to parse as JSON
            var jsonText = text[start..];
            
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;
            
            var result = new ParsedPayload();
            
            // Extract standard JSON-RPC fields
            if (root.TryGetProperty("jsonrpc", out var version))
                result.Fields.Add(("JSON-RPC", version.GetString() ?? ""));
            
            if (root.TryGetProperty("method", out var method))
                result.Fields.Add(("Method", method.GetString() ?? ""));
            
            if (root.TryGetProperty("id", out var id))
                result.Fields.Add(("ID", id.ToString()));
            
            if (root.TryGetProperty("params", out var paramsEl))
            {
                var paramsStr = paramsEl.ToString();
                result.Fields.Add(("Params", Truncate(paramsStr, 100)));
            }
            
            // Pretty-print the full JSON as formatted body
            result.FormattedBody = JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true });
            
            return result;
        }
        catch
        {
            return null;
        }
    }
    
    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}

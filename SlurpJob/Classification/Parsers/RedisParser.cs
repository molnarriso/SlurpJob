using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses Redis RESP protocol commands into structured fields.
/// </summary>
public class RedisParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 4) return null;
        
        try
        {
            var text = Encoding.ASCII.GetString(payload);
            var result = new ParsedPayload();
            
            // RESP protocol starts with type indicator
            char typeChar = (char)payload[0];
            result.Fields.Add(("RESP Type", typeChar switch
            {
                '*' => "Array",
                '+' => "Simple String",
                '-' => "Error",
                ':' => "Integer",
                '$' => "Bulk String",
                _ => $"Unknown ({typeChar})"
            }));
            
            // Extract commands from RESP
            var commands = ExtractCommands(text);
            if (commands.Count > 0)
            {
                result.Fields.Add(("Command", commands[0].ToUpperInvariant()));
                
                if (commands.Count > 1)
                {
                    var args = string.Join(" ", commands.Skip(1).Take(5));
                    if (commands.Count > 6) args += " ...";
                    result.Fields.Add(("Arguments", args));
                }
            }
            
            result.FormattedBody = text.Replace("\r\n", "\n").TrimEnd();
            
            return result;
        }
        catch
        {
            return null;
        }
    }
    
    private static List<string> ExtractCommands(string resp)
    {
        var commands = new List<string>();
        var lines = resp.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
        
        foreach (var line in lines)
        {
            // Skip RESP markers and length indicators
            if (line.StartsWith("*") || line.StartsWith("$") || 
                line.StartsWith("+") || line.StartsWith("-") || line.StartsWith(":"))
                continue;
            
            // This is likely a command or argument
            if (!string.IsNullOrWhiteSpace(line))
                commands.Add(line);
        }
        
        return commands;
    }
}

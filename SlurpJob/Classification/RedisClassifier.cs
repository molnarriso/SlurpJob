using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects Redis RESP protocol.
/// Signature: Starts with * (RESP array) followed by RESP protocol commands.
/// Intent: Exploit (unauthenticated Redis access)
/// </summary>
public class RedisClassifier : IInboundClassifier
{
    public string Id => "REDIS";

    // Common Redis commands used in attacks
    private static readonly (string Command, string Description, Intent Intent)[] RedisCommands =
    {
        ("CONFIG GET", "Redis Config Dump", Intent.Exploit),
        ("CONFIG SET", "Redis Config Injection", Intent.Exploit),
        ("SLAVEOF", "Redis Replication Hijack", Intent.Exploit),
        ("REPLICAOF", "Redis Replication Hijack", Intent.Exploit),
        ("MODULE LOAD", "Redis Module Injection", Intent.Exploit),
        ("EVAL", "Redis Lua Injection", Intent.Exploit),
        ("SCRIPT", "Redis Script Injection", Intent.Exploit),
        ("DEBUG", "Redis Debug Command", Intent.Exploit),
        ("FLUSHALL", "Redis Data Wipe", Intent.Exploit),
        ("FLUSHDB", "Redis DB Wipe", Intent.Exploit),
        ("SHUTDOWN", "Redis Shutdown Attack", Intent.Exploit),
        ("SAVE", "Redis Persistence Attack", Intent.Exploit),
        ("BGSAVE", "Redis Background Save", Intent.Exploit),
        ("INFO", "Redis Info Probe", Intent.Recon),
        ("PING", "Redis Ping Probe", Intent.Recon),
        ("KEYS", "Redis Key Enumeration", Intent.Recon),
        ("SCAN", "Redis Key Scan", Intent.Recon),
        ("CLIENT LIST", "Redis Client Enum", Intent.Recon),
        ("DBSIZE", "Redis Size Probe", Intent.Recon),
    };

    public ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort)
    {
        if (payload.Length < 4) return ClassificationResult.Unclassified;

        // RESP protocol starts with a type character:
        // * = array, + = simple string, - = error, : = integer, $ = bulk string
        byte firstByte = payload[0];
        if (firstByte != '*' && firstByte != '+' && firstByte != '$')
            return ClassificationResult.Unclassified;

        // Validate RESP structure: should have \r\n sequences
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 256));
        
        if (!text.Contains("\r\n"))
            return ClassificationResult.Unclassified;

        // Check for specific Redis commands
        string upperText = text.ToUpperInvariant();
        foreach (var (command, description, intent) in RedisCommands)
        {
            if (upperText.Contains(command))
            {
                return new ClassificationResult
                {
                    AttackId = "redis-exploitation",
                    Name = description,
                    Protocol = PayloadProtocol.Redis,
                    Intent = intent
                };
            }
        }

        // Generic RESP detected
        return new ClassificationResult
        {
            AttackId = "redis-exploitation",
            Name = "Redis RESP Command",
            Protocol = PayloadProtocol.Redis,
            Intent = Intent.Exploit
        };
    }
    
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
        catch { return null; }
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

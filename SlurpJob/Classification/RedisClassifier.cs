using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects Redis RESP protocol.
/// Signature: Starts with * (RESP array) followed by RESP protocol commands.
/// Intent: Exploit (unauthenticated Redis access)
/// </summary>
public class RedisClassifier : IInboundClassifier
{
    public string Name => "Redis Classifier";

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

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 4) return ClassificationResult.Unclassified;

        // RESP protocol starts with a type character:
        // * = array, + = simple string, - = error, : = integer, $ = bulk string
        byte firstByte = payload[0];
        if (firstByte != '*' && firstByte != '+' && firstByte != '$')
            return ClassificationResult.Unclassified;

        // Validate RESP structure: should have \r\n sequences
        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 256));
        
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
                    Name = description,
                    Protocol = PayloadProtocol.Redis,
                    Intent = intent
                };
            }
        }

        // Generic RESP detected
        return new ClassificationResult
        {
            Name = "Redis RESP Command",
            Protocol = PayloadProtocol.Redis,
            Intent = Intent.Exploit
        };
    }
}

using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects JSON-RPC requests, commonly used for Ethereum node scanning.
/// Signature: Starts with {"id": or {"jsonrpc"
/// Intent: Recon (Ethereum node discovery, API scanning)
/// </summary>
public class JSONRPCClassifier : IInboundClassifier
{
    public string Name => "JSONRPC Classifier";

    // Common Ethereum JSON-RPC methods
    private static readonly (string Method, string Description)[] EthereumMethods = 
    {
        ("eth_blockNumber", "Ethereum Block Query"),
        ("eth_getBalance", "Ethereum Balance Query"),
        ("eth_accounts", "Ethereum Account Enum"),
        ("eth_sendRawTransaction", "Ethereum TX Injection"),
        ("eth_call", "Ethereum Contract Call"),
        ("eth_estimateGas", "Ethereum Gas Estimation"),
        ("eth_getTransactionCount", "Ethereum Nonce Query"),
        ("eth_getCode", "Ethereum Contract Query"),
        ("eth_chainId", "Ethereum Chain ID Query"),
        ("web3_clientVersion", "Web3 Version Probe"),
        ("net_version", "Network Version Probe"),
        ("personal_unlockAccount", "Ethereum Account Unlock Attempt"),
        ("personal_sendTransaction", "Ethereum TX via Personal API"),
        ("miner_start", "Ethereum Miner Control"),
        ("admin_addPeer", "Ethereum Admin Peer Add"),
    };

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 8) return ClassificationResult.Unclassified;

        var text = System.Text.Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 512));
        
        // Check for JSON-RPC structure
        bool isJsonRpc = text.StartsWith("{\"id\":", StringComparison.Ordinal) ||
                         text.StartsWith("{\"jsonrpc\"", StringComparison.Ordinal) ||
                         text.StartsWith("[{\"id\":", StringComparison.Ordinal) ||
                         text.StartsWith("[{\"jsonrpc\"", StringComparison.Ordinal);

        if (!isJsonRpc) return ClassificationResult.Unclassified;

        // Check for specific Ethereum methods
        foreach (var (method, description) in EthereumMethods)
        {
            if (text.Contains(method, StringComparison.Ordinal))
            {
                // Check for particularly dangerous methods
                Intent intent = method switch
                {
                    "personal_unlockAccount" => Intent.Exploit,
                    "personal_sendTransaction" => Intent.Exploit,
                    "miner_start" => Intent.Exploit,
                    "admin_addPeer" => Intent.Exploit,
                    "eth_sendRawTransaction" => Intent.Exploit,
                    _ => Intent.Recon
                };

                return new ClassificationResult
                {
                    Name = description,
                    Protocol = PayloadProtocol.JSONRPC,
                    Intent = intent
                };
            }
        }

        // Generic JSON-RPC detected but no specific method identified
        return new ClassificationResult
        {
            Name = "JSON-RPC Request",
            Protocol = PayloadProtocol.JSONRPC,
            Intent = Intent.Recon
        };
    }
}

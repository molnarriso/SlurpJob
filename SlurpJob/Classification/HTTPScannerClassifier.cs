using SlurpJob.Networking;
using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Helper class to detect known scanner signatures in HTTP-like payloads.
/// Called by HTTPClassifier to identify specific actors (e.g., Palo Alto, Friendly Scanner).
/// </summary>
public static class HTTPScannerClassifier
{
    private static readonly string[] PaloAltoCidrs = 
    {
        "35.203.210.0/23",
        "144.86.173.0/24",
        "147.185.132.0/23",
        "162.216.149.0/24",
        "162.216.150.0/24",
        "172.105.147.0/24",
        "198.235.24.0/24",
        "205.210.31.0/24",
        "216.25.88.0/21",
        "2604:a940:300:5b6:0:0:0:0/64",
        "2604:a940:301:225:0:0:0:0/64",
        "2604:a940:302:118:0:0:0:0/64"
    };

    public static ClassificationResult? Classify(string payloadText, string sourceIp)
    {
        // 1. Palo Alto Networks Cortex Xpanse
        // User-Agent: Hello from Palo Alto Networks...
        if (payloadText.Contains("Palo Alto Networks", StringComparison.OrdinalIgnoreCase) || 
            payloadText.Contains("Cortex-Xpanse", StringComparison.OrdinalIgnoreCase))
        {
            // Verify IP is authorized
            if (IpMatcher.IsMatch(sourceIp, PaloAltoCidrs))
            {
                return new ClassificationResult
                {
                    AttackId = "palo-alto-cortex",
                    Name = "Palo Alto Cortex Xpanse",
                    Protocol = PayloadProtocol.HTTP,
                    Intent = Intent.Recon
                };
            }
            // If checking fails, return null so it falls back to generic HTTP request
            // We could also flag as "Spoofed Palo Alto" if desired
        }

        // 2. Generic VOIP Scanner (User-Agent: VOIP)
        if (payloadText.Contains("User-Agent: VOIP", StringComparison.OrdinalIgnoreCase))
        {
            return new ClassificationResult
            {
                AttackId = "voip-scanner",
                Name = "Generic VOIP Scanner",
                Protocol = PayloadProtocol.HTTP, // Delivered via HTTP/TCP usually
                Intent = Intent.Recon
            };
        }

        return null; // No specific scanner detected
    }
}

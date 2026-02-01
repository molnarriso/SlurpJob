using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects TLS ClientHello handshakes.
/// Signature: First 2 bytes = 0x16 0x03 (Content Type: Handshake, Version: TLS)
/// </summary>
public class TLSClassifier : IInboundClassifier
{
    public string Name => "TLS Classifier";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        // TLS Record Layer: ContentType (1 byte) + Version (2 bytes) + Length (2 bytes) = minimum 5 bytes
        if (payload.Length < 5) return ClassificationResult.Unclassified;

        // Check for TLS Handshake content type (0x16) and TLS version prefix (0x03)
        if (payload[0] == 0x16 && payload[1] == 0x03)
        {
            // payload[2] contains the minor version:
            // 0x00 = SSL 3.0, 0x01 = TLS 1.0, 0x02 = TLS 1.1, 0x03 = TLS 1.2, 0x04 = TLS 1.3
            string version = payload[2] switch
            {
                0x00 => "SSL 3.0",
                0x01 => "TLS 1.0",
                0x02 => "TLS 1.1",
                0x03 => "TLS 1.2",
                0x04 => "TLS 1.3",
                _ => "TLS"
            };

            // Check if this is actually a ClientHello (handshake type 0x01)
            // The handshake message starts at byte 5 (after the 5-byte record header)
            string handshakeType = "Handshake";
            if (payload.Length >= 6 && payload[5] == 0x01)
            {
                handshakeType = "ClientHello";
            }

            return new ClassificationResult
            {
                Name = $"{version} {handshakeType}",
                Protocol = PayloadProtocol.TLS,
                Intent = Intent.Recon
            };
        }

        return ClassificationResult.Unclassified;
    }
}

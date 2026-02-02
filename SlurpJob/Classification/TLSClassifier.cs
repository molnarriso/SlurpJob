using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects TLS ClientHello handshakes. Signature: 0x16 0x03 (Handshake, TLS version)
/// </summary>
public class TLSClassifier : IInboundClassifier
{
    public string Name => "TLS Classifier";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 5) return ClassificationResult.Unclassified;

        if (payload[0] == 0x16 && payload[1] == 0x03)
        {
            string version = payload[2] switch { 0x00 => "SSL 3.0", 0x01 => "TLS 1.0", 0x02 => "TLS 1.1", 0x03 => "TLS 1.2", 0x04 => "TLS 1.3", _ => "TLS" };
            string handshakeType = payload.Length >= 6 && payload[5] == 0x01 ? "ClientHello" : "Handshake";

            return new ClassificationResult { Id = "tls-scanning", Name = $"{version} {handshakeType}", Protocol = PayloadProtocol.TLS, Intent = Intent.Recon };
        }

        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 5 || payload[0] != 0x16 || payload[1] != 0x03) return null;
        
        var result = new ParsedPayload();
        string version = payload[2] switch { 0x00 => "SSL 3.0", 0x01 => "TLS 1.0", 0x02 => "TLS 1.1", 0x03 => "TLS 1.2", 0x04 => "TLS 1.3", _ => $"TLS (0x03{payload[2]:X2})" };
        result.Fields.Add(("Version", version));
        
        int recordLen = (payload[3] << 8) | payload[4];
        result.Fields.Add(("Record Length", $"{recordLen} bytes"));
        
        if (payload.Length >= 6)
        {
            string hsType = payload[5] switch { 0x01 => "ClientHello", 0x02 => "ServerHello", 0x0B => "Certificate", _ => $"Type 0x{payload[5]:X2}" };
            result.Fields.Add(("Handshake", hsType));
        }
        
        result.Fields.Add(("Magic", $"0x{payload[0]:X2} 0x{payload[1]:X2} 0x{payload[2]:X2}"));
        return result;
    }
}

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses TLS ClientHello into structured fields.
/// </summary>
public class TLSParser : IPayloadParser
{
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 5) return null;
        
        // Check for TLS Handshake (0x16) + Version (0x03 xx)
        if (payload[0] != 0x16 || payload[1] != 0x03)
            return null;
        
        var result = new ParsedPayload();
        
        // Parse TLS version
        string version = payload[2] switch
        {
            0x00 => "SSL 3.0",
            0x01 => "TLS 1.0",
            0x02 => "TLS 1.1",
            0x03 => "TLS 1.2",
            0x04 => "TLS 1.3",
            _ => $"TLS (0x03{payload[2]:X2})"
        };
        result.Fields.Add(("Version", version));
        
        // Record length
        if (payload.Length >= 5)
        {
            int recordLen = (payload[3] << 8) | payload[4];
            result.Fields.Add(("Record Length", $"{recordLen} bytes"));
        }
        
        // Handshake type
        if (payload.Length >= 6)
        {
            string handshakeType = payload[5] switch
            {
                0x01 => "ClientHello",
                0x02 => "ServerHello",
                0x0B => "Certificate",
                0x0C => "ServerKeyExchange",
                0x0D => "CertificateRequest",
                0x0E => "ServerHelloDone",
                0x10 => "ClientKeyExchange",
                0x14 => "Finished",
                _ => $"Type 0x{payload[5]:X2}"
            };
            result.Fields.Add(("Handshake", handshakeType));
        }
        
        // Show magic bytes
        result.Fields.Add(("Magic", $"0x{payload[0]:X2} 0x{payload[1]:X2} 0x{payload[2]:X2}"));
        
        return result;
    }
}

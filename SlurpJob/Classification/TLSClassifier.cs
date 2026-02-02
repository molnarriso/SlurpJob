using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects TLS ClientHello handshakes. Signature: 0x16 0x03 (Handshake, TLS version)
/// </summary>
public class TLSClassifier : IInboundClassifier
{
    public string Id => "TLS";

    public ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort)
    {
        if (payload.Length < 5) return ClassificationResult.Unclassified;

        if (payload[0] == 0x16 && payload[1] == 0x03)
        {
            string version = payload[2] switch { 0x00 => "SSL 3.0", 0x01 => "TLS 1.0", 0x02 => "TLS 1.1", 0x03 => "TLS 1.2", 0x04 => "TLS 1.3", _ => "TLS" };
            string handshakeType = payload.Length >= 6 && payload[5] == 0x01 ? "ClientHello" : "Handshake";

            return new ClassificationResult { AttackId = "tls-scanning", Name = $"{version} {handshakeType}", Protocol = PayloadProtocol.TLS, Intent = Intent.Recon };
        }

        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        // Basic signature check: 0x16 (Handshake) + 0x03 (TLS version)
        if (payload.Length < 5 || payload[0] != 0x16 || payload[1] != 0x03) return null;
        
        var result = new ParsedPayload();
        
        // --- Record Layer ---
        // Byte 0: Content Type (0x16)
        // Byte 1-2: Version (e.g. 0x03 0x01)
        // Byte 3-4: Length
        
        string recordVersion = GetTlsVersionName(payload[1], payload[2]);
        result.Fields.Add(("Record Version", recordVersion));

        if (payload.Length < 9) return result; // Not enough for Handshake header

        // --- Handshake Layer ---
        // Byte 5: Handshake Type
        // Byte 6-8: Length
        byte handshakeType = payload[5];
        
        if (handshakeType != 0x01) // Not ClientHello
        {
             result.Fields.Add(("Handshake", $"Type 0x{handshakeType:X2}"));
             return result;
        }

        result.Fields.Add(("Handshake", "ClientHello"));
        
        // Pointer to current position, starting after Handshake Header (Type:1 + Len:3 = 4 bytes)
        // So Header starts at 5. Payload starts at 9.
        int cursor = 9;

        if (cursor + 2 > payload.Length) return result;

        // Client Version (2 bytes)
        string clientVersion = GetTlsVersionName(payload[cursor], payload[cursor+1]);
        result.Fields.Add(("Client Version", clientVersion));
        cursor += 2;

        if (cursor + 32 > payload.Length) return result;

        // Random (32 bytes)
        // We just show the first few bytes as a snippet
        string randomPrefix = BitConverter.ToString(payload, cursor, 4).Replace("-", " ");
        result.Fields.Add(("Random", $"{randomPrefix}..."));
        cursor += 32;

        // Session ID
        if (cursor + 1 > payload.Length) return result;
        int sessionIdLen = payload[cursor];
        cursor++;
        
        if (sessionIdLen > 0)
        {
            if (cursor + sessionIdLen > payload.Length) return result;
            string sessionId = BitConverter.ToString(payload, cursor, sessionIdLen).Replace("-", "");
            result.Fields.Add(("Session ID", sessionId));
            cursor += sessionIdLen;
        }

        // Cipher Suites
        if (cursor + 2 > payload.Length) return result;
        int cipherSuitesLen = (payload[cursor] << 8) | payload[cursor + 1];
        cursor += 2;



        if (cursor + cipherSuitesLen > payload.Length) return result;
        int cipherCount = cipherSuitesLen / 2;
        
        // Extract all suites compactly
        var ciphers = new List<string>(cipherCount);
        for(int i=0; i < cipherCount; i++)
        {
             // Format as "C02F" instead of "0xC02F" to save space
             ciphers.Add($"{payload[cursor + (i*2)]:X2}{payload[cursor + (i*2) + 1]:X2}");
        }
        string cipherDisplay = string.Join(" ", ciphers);
        result.Fields.Add(("Cipher Suites", $"{cipherCount} suites [{cipherDisplay}]"));
        cursor += cipherSuitesLen;

        // Compression Methods
        if (cursor + 1 > payload.Length) return result;
        int compressionLen = payload[cursor];
        cursor++;
        
        if (cursor + compressionLen > payload.Length) return result;
        // string compression = BitConverter.ToString(payload, cursor, compressionLen);
        cursor += compressionLen;

        // Extensions
        if (cursor + 2 > payload.Length) return result;
        int extensionsLen = (payload[cursor] << 8) | payload[cursor + 1];
        cursor += 2;
        
        int extensionsEnd = cursor + extensionsLen;
        if (extensionsEnd > payload.Length) extensionsEnd = payload.Length;

        while (cursor + 4 <= extensionsEnd)
        {
            int extType = (payload[cursor] << 8) | payload[cursor + 1];
            int extLen = (payload[cursor + 2] << 8) | payload[cursor + 3];
            cursor += 4;

            if (cursor + extLen > extensionsEnd) break;

            if (extType == 0x0000) // Server Name Indication (SNI)
            {
                // Parse SNI
                // List Length (2) -> Type (1) -> Name Length (2) -> Name
                if (extLen >= 5)
                {
                    int sniListLen = (payload[cursor] << 8) | payload[cursor + 1];
                    // We assume first entry is host_name (type 0)
                    if (payload[cursor + 2] == 0x00) // HostName type
                    {
                        int nameLen = (payload[cursor + 3] << 8) | payload[cursor + 4];
                        if (cursor + 5 + nameLen <= extensionsEnd)
                        {
                            string hostname = System.Text.Encoding.ASCII.GetString(payload, cursor + 5, nameLen);
                            result.Fields.Add(("SNI", hostname));
                        }
                    }
                }
            }

            cursor += extLen;
        }

        return result;
    }

    private string GetTlsVersionName(byte major, byte minor)
    {
        return (major, minor) switch
        {
            (0x03, 0x00) => "SSL 3.0",
            (0x03, 0x01) => "TLS 1.0",
            (0x03, 0x02) => "TLS 1.1",
            (0x03, 0x03) => "TLS 1.2",
            (0x03, 0x04) => "TLS 1.3",
            _ => $"0x{major:X2}{minor:X2}"
        };
    }
}

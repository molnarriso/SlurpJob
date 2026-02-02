using SlurpJob.Models;

namespace SlurpJob.Classification;

/// <summary>
/// Detects TLS ClientHello handshakes. Signature: 0x16 0x03 (Handshake, TLS version)
/// </summary>
public class TLSClassifier : IInboundClassifier
{
    public string Id => "TLS";

    public ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort)
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
        string recordVersion = GetTlsVersionName(payload[1], payload[2]);
        result.Fields.Add(("Record Version", recordVersion));

        if (payload.Length < 9) return result;

        // --- Handshake Layer ---
        byte handshakeType = payload[5];
        if (handshakeType != 0x01) // Not ClientHello
        {
             result.Fields.Add(("Handshake", $"Type 0x{handshakeType:X2}"));
             return result;
        }

        result.Fields.Add(("Handshake", "ClientHello"));
        
        int cursor = 9;
        if (cursor + 2 > payload.Length) return result;

        // Client Version
        string clientVersion = GetTlsVersionName(payload[cursor], payload[cursor+1]);
        result.Fields.Add(("Client Version", clientVersion));
        cursor += 2;

        if (cursor + 32 > payload.Length) return result;

        // Random (32 bytes)
        // Check if it's ASCII text (common in scanners/CTFs)
        byte[] randomBytes = new byte[32];
        Array.Copy(payload, cursor, randomBytes, 0, 32);
        
        if (IsAsciiPrintable(randomBytes))
        {
             string randomText = System.Text.Encoding.ASCII.GetString(randomBytes);
             result.Fields.Add(("Random", $"\"{randomText}\" (ASCII)"));
        }
        else 
        {
            // Check if just the last 28 bytes are ASCII (RFC 5246: first 4 bytes are gmt_unix_time)
            var suffix = new byte[28];
            Array.Copy(randomBytes, 4, suffix, 0, 28);
            if (IsAsciiPrintable(suffix))
            {
                 string timeHex = BitConverter.ToString(randomBytes, 0, 4).Replace("-", " ");
                 string suffixText = System.Text.Encoding.ASCII.GetString(suffix);
                 result.Fields.Add(("Random", $"{timeHex} \"{suffixText}\""));
            }
            else
            {
                 string randomPrefix = BitConverter.ToString(payload, cursor, 4).Replace("-", " ");
                 result.Fields.Add(("Random", $"{randomPrefix}..."));
            }
        }
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
        
        var ciphers = new List<string>(cipherCount);
        for(int i=0; i < cipherCount; i++)
        {
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
        cursor += compressionLen;

        // Extensions
        if (cursor + 2 > payload.Length) return result;
        int extensionsLen = (payload[cursor] << 8) | payload[cursor + 1];
        cursor += 2;
        
        int extensionsEnd = cursor + extensionsLen;
        if (extensionsEnd > payload.Length) extensionsEnd = payload.Length;

        var extensionNames = new List<string>();

        while (cursor + 4 <= extensionsEnd)
        {
            int extType = (payload[cursor] << 8) | payload[cursor + 1];
            int extLen = (payload[cursor + 2] << 8) | payload[cursor + 3];
            cursor += 4;

            if (cursor + extLen > extensionsEnd) break;
            
            // Catalog the extension
            extensionNames.Add(GetExtensionName(extType));

            if (extType == 0x0000) // Server Name Indication (SNI)
            {
                if (extLen >= 5)
                {
                    int sniListLen = (payload[cursor] << 8) | payload[cursor + 1];
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
            else if (extType == 0x0010) // ALPN
            {
                if (extLen >= 2)
                {
                    int alpnListLen = (payload[cursor] << 8) | payload[cursor + 1];
                    int alpnEnd = cursor + 2 + alpnListLen;
                    if (alpnEnd <= extensionsEnd)
                    {
                        var protocols = new List<string>();
                        int pCursor = cursor + 2;
                        while(pCursor < alpnEnd)
                        {
                            int pLen = payload[pCursor];
                            pCursor++;
                            if (pCursor + pLen > alpnEnd) break;
                            
                            string protocol = System.Text.Encoding.ASCII.GetString(payload, pCursor, pLen);
                            protocols.Add(protocol);
                            pCursor += pLen;
                        }
                        result.Fields.Add(("ALPN", string.Join(", ", protocols)));
                    }
                }
            }

            cursor += extLen;
        }
        
        if (extensionNames.Count > 0)
        {
            result.Fields.Add(("Extensions", string.Join(", ", extensionNames)));
        }

        return result;
    }

    private bool IsAsciiPrintable(byte[] data)
    {
        foreach (byte b in data)
        {
            if (b < 32 || b > 126) return false;
        }
        return true;
    }

    private string GetExtensionName(int type)
    {
        return type switch
        {
            0x0000 => "SNI",
            0x0005 => "StatusRequest",
            0x000A => "SupportedGroups",
            0x000B => "ECPointFormats",
            0x000D => "SigAlgos",
            0x000F => "Heartbeat",
            0x0010 => "ALPN",
            0x0012 => "SCT",
            0x0015 => "Padding",
            0x0017 => "ExtendedMasterSecret",
            0x0023 => "SessionTicket",
            0x002B => "SupportedVersions",
            0x002D => "PSKKeyExchangeModes",
            0x0033 => "KeyShare",
            0x3374 => "RenegotiationInfo",
            _ => $"0x{type:X4}"
        };
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

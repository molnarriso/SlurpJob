using SlurpJob.Classification;
using SlurpJob.Models;

namespace SlurpJob.Tests;

public class TLSClassifierTests
{
    private readonly TLSClassifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_TLS12ClientHello()
    {
        // TLS 1.2 ClientHello: 0x16 0x03 0x03 (handshake, TLS 1.2)
        // followed by length, then 0x01 (ClientHello type)
        byte[] payload = { 0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 443);
        
        Assert.Equal("TLS 1.2 ClientHello", result.Name);
        Assert.Equal(PayloadProtocol.TLS, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_TLS10ClientHello()
    {
        // TLS 1.0 ClientHello
        byte[] payload = { 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 443);
        
        Assert.Equal("TLS 1.0 ClientHello", result.Name);
        Assert.Equal(PayloadProtocol.TLS, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_TLS13()
    {
        // TLS 1.3 handshake (type not ClientHello)
        byte[] payload = { 0x16, 0x03, 0x04, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 443);
        
        Assert.Equal("TLS 1.3 Handshake", result.Name);
        Assert.Equal(PayloadProtocol.TLS, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonTLS()
    {
        byte[] payload = { 0x47, 0x45, 0x54, 0x20, 0x2F }; // "GET /"
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Parse_ShouldExtract_SNI_And_Details()
    {
        // Construct a simplified TLS 1.0 ClientHello with SNI
        var payload = new List<byte>();
        
        // Record Header
        payload.Add(0x16); // Handshake
        payload.Add(0x03); payload.Add(0x01); // TLS 1.0 (Record Version)
        payload.Add(0x00); payload.Add(0x00); // Length placeholder (at index 3,4)

        // Handshake Header
        int handshakeStart = payload.Count;
        payload.Add(0x01); // ClientHello
        payload.Add(0x00); payload.Add(0x00); payload.Add(0x00); // Length placeholder

        // Client Version
        payload.Add(0x03); payload.Add(0x03); // TLS 1.2

        // Random (32 bytes)
        for(int i=0; i<32; i++) payload.Add((byte)i);

        // Session ID (32 bytes)
        payload.Add(32); // Len
        for(int i=0; i<32; i++) payload.Add(0xAA);

        // Cipher Suites (2 suites: 0x002F, 0x0035 = 4 bytes)
        payload.Add(0x00); payload.Add(0x04); // Len
        payload.Add(0x00); payload.Add(0x2F);
        payload.Add(0x00); payload.Add(0x35);

        // Compression (1 method: 0x00)
        payload.Add(0x01); // Len
        payload.Add(0x00);

        // Extensions
        // SNI Extension: Type=0x0000, Len=Calculated
        // SNI Data: ListLen(2) -> Type(1, host_name) -> NameLen(2) -> "example.com"
        byte[] hostname = System.Text.Encoding.ASCII.GetBytes("example.com");
        int sniDataLen = 1 + 2 + hostname.Length; // Type(1) + NameLen(2) + Name
        int sniExtLen = 2 + sniDataLen; // ListLen(2) + Data

        // Total Extensions Block
        int extensionsBlockLen = 2 + 2 + sniExtLen; // ExtType(2) + ExtLen(2) + Data in Ext
        payload.Add((byte)(extensionsBlockLen >> 8));
        payload.Add((byte)(extensionsBlockLen & 0xFF));

        // SNI Extension
        payload.Add(0x00); payload.Add(0x00); // Type: SNI
        payload.Add((byte)(sniExtLen >> 8));
        payload.Add((byte)(sniExtLen & 0xFF)); // Len

        payload.Add((byte)(sniDataLen >> 8));
        payload.Add((byte)(sniDataLen & 0xFF)); // List Len

        payload.Add(0x00); // Type: host_name
        payload.Add((byte)(hostname.Length >> 8));
        payload.Add((byte)(hostname.Length & 0xFF)); // Name Len
        payload.AddRange(hostname);

        // Fixup Lengths
        int handshakeLen = payload.Count - handshakeStart - 4; // Minus Header(4)
        payload[handshakeStart + 1] = (byte)((handshakeLen >> 16) & 0xFF);
        payload[handshakeStart + 2] = (byte)((handshakeLen >> 8) & 0xFF);
        payload[handshakeStart + 3] = (byte)(handshakeLen & 0xFF);

        int recordLen = payload.Count - 5; // Minus Record Header(5)
        payload[3] = (byte)(recordLen >> 8);
        payload[4] = (byte)(recordLen & 0xFF);

        // Act
        var result = _classifier.Parse(payload.ToArray());

        // Assert
        Assert.NotNull(result);
        Assert.Contains(result.Fields, f => f.Label == "SNI" && f.Value == "example.com");
        Assert.Contains(result.Fields, f => f.Label == "Session ID" && f.Value.StartsWith("AAAAAAAAAAAAAAAA"));
        Assert.Contains(result.Fields, f => f.Label == "Cipher Suites" && f.Value.Contains("2 suites [002F 0035]"));
    }

    [Fact]
    public void Parse_ShouldDetect_AsciiRandom_And_Extensions()
    {
        // Reconstruct logic based on User's hex dump
        // Header: 16 03 00 (SSL 3.0) 00 69 (105 bytes)
        // Handshake: 01 (ClientHello) 00 00 65 (101 bytes)
        // Version: 03 03 (TLS 1.2)
        // Random: 55 1C A7 E4 (Time) + "random1random2random3random4" (ASCII)
        // Session: 00 (0 bytes)
        // Cipher Suites: 00 0C (12 bytes) -> 002F, 000A, 0013, 0039, 0004, 00FF
        // Compression: 01 00
        // Extensions: 00 30 (48 bytes)
        //   - SigAlgos (0x000D): 00 2C (44 bytes payload...)
        
        var payload = new List<byte>();
        // Record
        payload.Add(0x16); payload.Add(0x03); payload.Add(0x00);
        payload.Add(0x00); payload.Add(0x69);
        
        // Handshake
        payload.Add(0x01); payload.Add(0x00); payload.Add(0x00); payload.Add(0x65);
        
        // Version
        payload.Add(0x03); payload.Add(0x03);
        
        // Random
        payload.Add(0x55); payload.Add(0x1C); payload.Add(0xA7); payload.Add(0xE4); // Time
        payload.AddRange(System.Text.Encoding.ASCII.GetBytes("random1random2random3random4"));
        
        // Session ID (0)
        payload.Add(0x00);

        // Cipher Suites
        payload.Add(0x00); payload.Add(0x0C);
        payload.Add(0x00); payload.Add(0x2F);
        payload.Add(0x00); payload.Add(0x0A);
        payload.Add(0x00); payload.Add(0x13);
        payload.Add(0x00); payload.Add(0x39);
        payload.Add(0x00); payload.Add(0x04);
        payload.Add(0x00); payload.Add(0xFF);

        // Compression
        payload.Add(0x01); payload.Add(0x00);

        // Extensions Length (48 bytes)
        payload.Add(0x00); payload.Add(0x30);
        
        // Ext 1: SigAlgos (0x000D) Len 44
        payload.Add(0x00); payload.Add(0x0D);
        payload.Add(0x00); payload.Add(0x2C);
        for(int i=0; i<44; i++) payload.Add(0x00); // 44 bytes dummy content

        // Act
        var result = _classifier.Parse(payload.ToArray());

        // Assert
        Assert.NotNull(result);
        
        // Verify result contains "Extensions" list.
        Assert.Contains(result.Fields, f => f.Label == "Extensions" && f.Value.Contains("SigAlgos"));
        Assert.Contains(result.Fields, f => f.Label == "Cipher Suites" && f.Value.Contains("6 suites"));
        Assert.Contains(result.Fields, f => f.Label == "Random" && f.Value.Contains("\"random1random2"));
    }

    [Fact]
    public void Parse_ShouldExtract_ALPN()
    {
        // Minimal ALPN Payload construction
        var payload = new List<byte>();
        
        // Record & Handshake headers (Simplified valid structure)
        payload.AddRange(new byte[] { 0x16, 0x03, 0x01, 0x00, 0x30 }); // Record Hdr (Length placeholder)
        payload.AddRange(new byte[] { 0x01, 0x00, 0x00, 0x2C }); // Handshake Hdr (ClientHello)
        payload.AddRange(new byte[] { 0x03, 0x03 }); // Version
        
        // Random (32 bytes)
        for(int i=0; i<32; i++) payload.Add(0xAA);
        
        // Session ID (0)
        payload.Add(0x00);
        
        // Cipher Suites (2 bytes: 0x00 0x2F)
        payload.AddRange(new byte[] { 0x00, 0x02, 0x00, 0x2F });
        
        // Compression (1 byte: 0x00)
        payload.AddRange(new byte[] { 0x01, 0x00 });
        
        // Extensions: ALPN (0x0010)
        // Data: "h2" (len 2), "http/1.1" (len 8)
        // ALPN List Len: 1 + 2 + 1 + 8 = 12 bytes
        // Ext Len: 2 (ListLen) + 12 = 14 bytes
        
        int alpnListLen = 1 + 2 + 1 + 8;
        int extLen = 2 + alpnListLen;
        int totalExtLen = 2 + 2 + extLen; // Type(2) + Len(2) + Body
        
        payload.Add((byte)(totalExtLen >> 8));
        payload.Add((byte)(totalExtLen & 0xFF));
        
        // ALPN Extension
        payload.AddRange(new byte[] { 0x00, 0x10 }); // Type
        payload.Add((byte)(extLen >> 8)); 
        payload.Add((byte)(extLen & 0xFF)); // Len
        
        payload.Add((byte)(alpnListLen >> 8));
        payload.Add((byte)(alpnListLen & 0xFF)); // List Len
        
        // "h2"
        payload.Add(0x02); 
        payload.AddRange(System.Text.Encoding.ASCII.GetBytes("h2"));
        
        // "http/1.1"
        payload.Add(0x08);
        payload.AddRange(System.Text.Encoding.ASCII.GetBytes("http/1.1"));
        
        // Fixup Lengths
        int handshakeLen = payload.Count - 9; // 5(Rec) + 4(HS)
        payload[6] = (byte)((handshakeLen >> 16) & 0xFF);
        payload[7] = (byte)((handshakeLen >> 8) & 0xFF);
        payload[8] = (byte)(handshakeLen & 0xFF);
        
        int recordLen = payload.Count - 5;
        payload[3] = (byte)(recordLen >> 8);
        payload[4] = (byte)(recordLen & 0xFF);

        // Act
        var result = _classifier.Parse(payload.ToArray());

        // Assert
        Assert.NotNull(result);
        Assert.Contains(result.Fields, f => f.Label == "ALPN" && f.Value == "h2, http/1.1");
    }

    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        byte[] payload = { 0x16, 0x03, 0x03 }; // Too short
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 443);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

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
        
        var result = _classifier.Classify(payload, "TCP", 443);
        
        Assert.Equal("TLS 1.2 ClientHello", result.Name);
        Assert.Equal(PayloadProtocol.TLS, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_TLS10ClientHello()
    {
        // TLS 1.0 ClientHello
        byte[] payload = { 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
        
        var result = _classifier.Classify(payload, "TCP", 443);
        
        Assert.Equal("TLS 1.0 ClientHello", result.Name);
        Assert.Equal(PayloadProtocol.TLS, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_TLS13()
    {
        // TLS 1.3 handshake (type not ClientHello)
        byte[] payload = { 0x16, 0x03, 0x04, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00 };
        
        var result = _classifier.Classify(payload, "TCP", 443);
        
        Assert.Equal("TLS 1.3 Handshake", result.Name);
        Assert.Equal(PayloadProtocol.TLS, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonTLS()
    {
        byte[] payload = { 0x47, 0x45, 0x54, 0x20, 0x2F }; // "GET /"
        
        var result = _classifier.Classify(payload, "TCP", 80);
        
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
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        byte[] payload = { 0x16, 0x03, 0x03 }; // Too short
        
        var result = _classifier.Classify(payload, "TCP", 443);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

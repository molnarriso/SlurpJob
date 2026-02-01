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
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        byte[] payload = { 0x16, 0x03, 0x03 }; // Too short
        
        var result = _classifier.Classify(payload, "TCP", 443);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

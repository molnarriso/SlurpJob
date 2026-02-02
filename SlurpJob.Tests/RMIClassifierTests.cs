using SlurpJob.Classification;
using SlurpJob.Models;

namespace SlurpJob.Tests;

public class RMIClassifierTests
{
    private readonly RMIClassifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_JrmiMagic()
    {
        // JRMI magic bytes + protocol version
        byte[] payload = { 0x4A, 0x52, 0x4D, 0x49, 0x00, 0x01, 0x00 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 1099);
        
        Assert.Equal(PayloadProtocol.RMI, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_StreamProtocol()
    {
        // JRMI with StreamProtocol (0x01)
        byte[] payload = { 0x4A, 0x52, 0x4D, 0x49, 0x00, 0x01 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 1099);
        
        Assert.Contains("Java RMI", result.Name);
        Assert.Equal(PayloadProtocol.RMI, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_SingleOpProtocol()
    {
        // JRMI with SingleOpProtocol (0x02)
        byte[] payload = { 0x4A, 0x52, 0x4D, 0x49, 0x00, 0x02 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 1099);
        
        Assert.Contains("Java RMI", result.Name);
    }

    [Fact]
    public void Classify_ShouldIdentify_JavaSerializedObject()
    {
        // Java serialized object magic: AC ED 00 05
        byte[] payload = { 0xAC, 0xED, 0x00, 0x05, 0x73, 0x72, 0x00, 0x00 };
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 1099);
        
        Assert.Contains("Java Deserialization", result.Name);
        Assert.Equal(PayloadProtocol.RMI, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonRMI()
    {
        byte[] payload = { 0x47, 0x45, 0x54, 0x20, 0x2F }; // "GET /"
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        byte[] payload = { 0x4A, 0x52, 0x4D }; // Incomplete JRMI
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 1099);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

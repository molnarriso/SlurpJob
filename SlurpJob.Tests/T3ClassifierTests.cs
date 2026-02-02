using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests;

public class T3ClassifierTests
{
    private readonly T3Classifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_T3Handshake()
    {
        var payload = Encoding.ASCII.GetBytes("t3 12.2.1\nAS:255\nHL:19\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 7001);
        
        Assert.Contains("WebLogic T3", result.Name);
        Assert.Equal(PayloadProtocol.T3, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_T3WithVersion()
    {
        var payload = Encoding.ASCII.GetBytes("t3 10.3.6\nAS:255\nHL:19\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 7001);
        
        Assert.Contains("v10.3", result.Name);
        Assert.Equal(PayloadProtocol.T3, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_T3Version14()
    {
        var payload = Encoding.ASCII.GetBytes("t3 14.1.1\nAS:255\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 7001);
        
        Assert.Contains("v14.1", result.Name);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonT3()
    {
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        var payload = Encoding.ASCII.GetBytes("t3 1"); // Too short
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 7001);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldBeCaseInsensitive()
    {
        var payload = Encoding.ASCII.GetBytes("T3 12.2.1\nAS:255\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 7001);
        
        Assert.Equal(PayloadProtocol.T3, result.Protocol);
    }
}

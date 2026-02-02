using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests;

public class SIPClassifierTests
{
    private readonly SIPClassifier _classifier = new();
    
    [Fact]
    public void Classify_ShouldIdentify_RegisterRequest()
    {
        var sipPayload = "REGISTER sip:3.127.242.167:4556 SIP/2.0\r\nTo: <sip:100@3.127.242.167>\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(sipPayload);
        
        var result = _classifier.Classify(bytes, "1.2.3.4", "TCP", 5060);
        
        Assert.Equal("SIP Request", result.Name);
        Assert.Equal(PayloadProtocol.SIP, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }
    
    [Fact]
    public void Classify_ShouldIdentify_OptionsRequest()
    {
        var sipPayload = "OPTIONS sip:user@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(sipPayload);
        
        var result = _classifier.Classify(bytes, "1.2.3.4", "UDP", 5060);
        
        Assert.Equal("SIP Request", result.Name);
        Assert.Equal(PayloadProtocol.SIP, result.Protocol);
    }
    
    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        var bytes = Encoding.ASCII.GetBytes("HELLO");
        var result = _classifier.Classify(bytes, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(string.Empty, result.Name); // Default is empty string, IngestionService adds "Unclassified"
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
    
    [Fact]
    public void Classify_ShouldIgnore_NonSipHttp()
    {
        // HTTP looks different
        var bytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var result = _classifier.Classify(bytes, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(string.Empty, result.Name); // Or whatever default is, implementation returns Unclassified struct which has defaults
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

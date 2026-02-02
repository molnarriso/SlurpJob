using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests.Classification;

public class HTTPScannerTests
{
    private readonly HTTPClassifier _httpClassifier = new();
    private readonly SIPClassifier _sipClassifier = new();

    [Fact]
    public void Detects_PaloAlto_Scanner_With_Valid_IP()
    {
        var payload = "GET / HTTP/1.0\r\nUser-Agent: Hello from Palo Alto Networks, find out more about our scans\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);
        
        // Use a valid IP from the allowlist
        var validIp = "35.203.210.5";
        
        var result = _httpClassifier.Classify(bytes, validIp, "TCP", 80);
        
        Assert.Equal("palo-alto-cortex", result.AttackId);
        Assert.Equal("Palo Alto Cortex Xpanse", result.Name);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Rejects_PaloAlto_Scanner_With_Invalid_IP()
    {
        var payload = "GET / HTTP/1.0\r\nUser-Agent: Hello from Palo Alto Networks, find out more about our scans\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);
        
        // Use an invalid IP
        var invalidIp = "1.2.3.4";
        
        var result = _httpClassifier.Classify(bytes, invalidIp, "TCP", 80);
        
        // Should fall back to generic HTTP scanning because IP check failed
        Assert.Equal("http-scanning", result.AttackId);
        Assert.NotEqual("palo-alto-cortex", result.AttackId);
    }

    [Fact]
    public void Detects_Generic_VOIP_Scanner_HTTP()
    {
        var payload = "GET / HTTP/1.1\r\nUser-Agent: VOIP\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);
        
        var result = _httpClassifier.Classify(bytes, "1.2.3.4", "TCP", 80);
        
        Assert.Equal("voip-scanner", result.AttackId);
        Assert.Equal("Generic VOIP Scanner", result.Name);
    }

    [Fact]
    public void Detects_SIPVicious_Scanner()
    {
        var payload = "REGISTER sip:1.2.3.4 SIP/2.0\r\nUser-Agent: friendly-scanner\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);
        
        var result = _sipClassifier.Classify(bytes, "1.2.3.4", "UDP", 5060);
        
        Assert.Equal("sipvicious-scanner", result.AttackId);
        Assert.Equal("SIPVicious Scan", result.Name);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Detects_Generic_VOIP_Scanner_SIP()
    {
        var payload = "OPTIONS sip:100@1.2.3.4 SIP/2.0\r\nUser-Agent: VOIP\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);
        
        var result = _sipClassifier.Classify(bytes, "1.2.3.4", "UDP", 5060);
        
        Assert.Equal("voip-scanner", result.AttackId);
        Assert.Equal("Generic VOIP Scanner", result.Name);
    }
}

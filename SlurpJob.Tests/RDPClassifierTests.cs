using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests;

public class RDPClassifierTests
{
    private readonly RDPClassifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_TPKTProbe()
    {
        // Basic TPKT header: version 3, reserved 0, length
        byte[] payload = { 0x03, 0x00, 0x00, 0x13 };
        
        var result = _classifier.Classify(payload, "TCP", 3389);
        
        Assert.Contains("TPKT", result.Name);
        Assert.Equal(PayloadProtocol.RDP, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_X224ConnectionRequest()
    {
        // TPKT + X.224 Connection Request (CR) with 0xE0 type
        byte[] payload = { 
            0x03, 0x00, 0x00, 0x2B,  // TPKT header
            0x26,                      // X.224 length
            0xE0,                      // CR TPDU type
            0x00, 0x00, 0x00, 0x00, 0x00  // CR parameters
        };
        
        var result = _classifier.Classify(payload, "TCP", 3389);
        
        Assert.Equal("RDP X.224 CR", result.Name);
        Assert.Equal(PayloadProtocol.RDP, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_BlueKeepProbe()
    {
        // Simulated BlueKeep probe with mstshash cookie
        var prefix = new byte[] { 
            0x03, 0x00, 0x00, 0x2B,  // TPKT header
            0x26,                      // X.224 length
            0xE0,                      // CR TPDU type
            0x00, 0x00, 0x00, 0x00, 0x00  // CR parameters
        };
        var cookie = Encoding.ASCII.GetBytes("Cookie: mstshash=attacker\r\n");
        var payload = prefix.Concat(cookie).ToArray();
        
        var result = _classifier.Classify(payload, "TCP", 3389);
        
        Assert.Contains("BlueKeep", result.Name);
        Assert.Contains("CVE-2019-0708", result.Name);
        Assert.Equal(PayloadProtocol.RDP, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonRDP()
    {
        byte[] payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n");
        
        var result = _classifier.Classify(payload, "TCP", 80);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        byte[] payload = { 0x03, 0x00 }; // Too short
        
        var result = _classifier.Classify(payload, "TCP", 3389);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests;

public class SSDPClassifierTests
{
    private readonly SSDPClassifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_MSearchRequest()
    {
        // Payload from user request
        var payload = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);

        var result = _classifier.Classify(bytes, "1.2.3.4", "UDP", 1900);

        Assert.Equal("SSDP Search", result.Name);
        Assert.Equal(PayloadProtocol.SSDP, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_NotifyRequest()
    {
        var payload = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:80/description.xml\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n\r\n";
        var bytes = Encoding.ASCII.GetBytes(payload);

        var result = _classifier.Classify(bytes, "1.2.3.4", "UDP", 1900);

        Assert.Equal("SSDP Notify", result.Name);
        Assert.Equal(PayloadProtocol.SSDP, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonSsdp()
    {
        var bytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var result = _classifier.Classify(bytes, "1.2.3.4", "TCP", 80);

        Assert.Equal(string.Empty, result.Name);
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        var bytes = Encoding.ASCII.GetBytes("M-SEARCH");
        var result = _classifier.Classify(bytes, "1.2.3.4", "UDP", 1900);

        Assert.Equal(string.Empty, result.Name);
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

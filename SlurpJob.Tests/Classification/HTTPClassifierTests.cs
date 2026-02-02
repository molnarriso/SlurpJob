using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;
using Xunit;
using System;
using System.Collections.Generic;

namespace SlurpJob.Tests;

public class HTTPClassifierTests
{
    private readonly HTTPClassifier _classifier = new HTTPClassifier();

    [Fact]
    public void Classify_ShouldIdentify_StandardGetRequest()
    {
        var payload = Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var result = _classifier.Classify(payload, "TCP", 80);

        Assert.Equal("http-scanning", result.AttackId);
        Assert.Equal("HTTP Request", result.Name);
        Assert.Equal(PayloadProtocol.HTTP, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_ConnectRequest_AsProxyProbe()
    {
        var payload = Encoding.ASCII.GetBytes("CONNECT api.ip.pn:443 HTTP/1.1\r\nHost: api.ip.pn:443\r\n\r\n");
        var result = _classifier.Classify(payload, "TCP", 80);

        // Expectation for the NEW behavior (test will fail initially)
        Assert.Equal("http-proxy-probe", result.AttackId); 
        Assert.Equal("HTTP Proxy Probe", result.Name);
        Assert.Equal(Intent.Exploit, result.Intent);
        Assert.Equal(PayloadProtocol.HTTP, result.Protocol);
    }

    [Fact]
    public void Parse_ShouldExtractFields_ForConnectRequest()
    {
        var payload = Encoding.ASCII.GetBytes("CONNECT api.ip.pn:443 HTTP/1.1\r\nHost: api.ip.pn:443\r\nUser-Agent: Go-http-client/1.1\r\n\r\n");
        var parsed = _classifier.Parse(payload);

        Assert.NotNull(parsed);
        Assert.Contains(parsed.Fields, f => f.Label == "Method" && f.Value == "CONNECT");
        Assert.Contains(parsed.Fields, f => f.Label == "Path" && f.Value == "api.ip.pn:443");
        Assert.Contains(parsed.Fields, f => f.Label == "Host" && f.Value == "api.ip.pn:443");
    }
}

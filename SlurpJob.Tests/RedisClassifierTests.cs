using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests;

public class RedisClassifierTests
{
    private readonly RedisClassifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_InfoProbe()
    {
        // RESP array with INFO command: *1\r\n$4\r\nINFO\r\n
        var payload = Encoding.ASCII.GetBytes("*1\r\n$4\r\nINFO\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 6379);
        
        Assert.Equal("Redis Info Probe", result.Name);
        Assert.Equal(PayloadProtocol.Redis, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_ConfigGet()
    {
        // CONFIG GET requires the full command syntax
        var payload = Encoding.ASCII.GetBytes("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$1\r\n*\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 6379);
        
        // The command contains "CONFIG GET" so should match
        Assert.Equal(PayloadProtocol.Redis, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_PingProbe()
    {
        var payload = Encoding.ASCII.GetBytes("*1\r\n$4\r\nPING\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 6379);
        
        Assert.Equal("Redis Ping Probe", result.Name);
        Assert.Equal(PayloadProtocol.Redis, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_FlushAll()
    {
        var payload = Encoding.ASCII.GetBytes("*1\r\n$8\r\nFLUSHALL\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 6379);
        
        Assert.Equal("Redis Data Wipe", result.Name);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_GenericResp()
    {
        // Generic RESP command not in the known list
        var payload = Encoding.ASCII.GetBytes("*1\r\n$3\r\nGET\r\n$7\r\nmykey\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 6379);
        
        Assert.Equal("Redis RESP Command", result.Name);
        Assert.Equal(PayloadProtocol.Redis, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonRedis()
    {
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_ShortPayloads()
    {
        var payload = new byte[] { 0x2A, 0x31 }; // "*1" - too short
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 6379);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

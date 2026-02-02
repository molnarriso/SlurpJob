using SlurpJob.Classification;
using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Tests;

public class JSONRPCClassifierTests
{
    private readonly JSONRPCClassifier _classifier = new();

    [Fact]
    public void Classify_ShouldIdentify_EthBlockNumber()
    {
        var payload = Encoding.ASCII.GetBytes("{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[]}");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8545);
        
        Assert.Equal("Ethereum Block Query", result.Name);
        Assert.Equal(PayloadProtocol.JSONRPC, result.Protocol);
        Assert.Equal(Intent.Recon, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_EthGetBalance()
    {
        var payload = Encoding.ASCII.GetBytes("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"0x123\",\"latest\"],\"id\":1}");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8545);
        
        Assert.Equal("Ethereum Balance Query", result.Name);
        Assert.Equal(PayloadProtocol.JSONRPC, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_Web3ClientVersion()
    {
        var payload = Encoding.ASCII.GetBytes("{\"id\":1,\"method\":\"web3_clientVersion\"}");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8545);
        
        Assert.Equal("Web3 Version Probe", result.Name);
        Assert.Equal(PayloadProtocol.JSONRPC, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_DangerousUnlockAttempt()
    {
        var payload = Encoding.ASCII.GetBytes("{\"id\":1,\"method\":\"personal_unlockAccount\",\"params\":[\"0x123\",\"password\"]}");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8545);
        
        Assert.Equal("Ethereum Account Unlock Attempt", result.Name);
        Assert.Equal(PayloadProtocol.JSONRPC, result.Protocol);
        Assert.Equal(Intent.Exploit, result.Intent);
    }

    [Fact]
    public void Classify_ShouldIdentify_GenericJsonRpc()
    {
        var payload = Encoding.ASCII.GetBytes("{\"id\":1,\"method\":\"unknown_method\"}");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8545);
        
        Assert.Equal("JSON-RPC Request", result.Name);
        Assert.Equal(PayloadProtocol.JSONRPC, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIdentify_BatchRequest()
    {
        var payload = Encoding.ASCII.GetBytes("[{\"id\":1,\"method\":\"eth_blockNumber\"}]");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8545);
        
        Assert.Equal("Ethereum Block Query", result.Name);
        Assert.Equal(PayloadProtocol.JSONRPC, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_NonJsonRpc()
    {
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 80);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }

    [Fact]
    public void Classify_ShouldIgnore_RegularJson()
    {
        // Regular JSON that doesn't look like JSON-RPC
        var payload = Encoding.ASCII.GetBytes("{\"name\":\"test\",\"value\":123}");
        
        var result = _classifier.Classify(payload, "1.2.3.4", "TCP", 8080);
        
        Assert.Equal(PayloadProtocol.Unknown, result.Protocol);
    }
}

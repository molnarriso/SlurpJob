namespace SlurpJob.Classification;

/// <summary>
/// Static registry that maps classifier names to their payload parsers.
/// No DI needed - parsers are stateless.
/// </summary>
public static class PayloadParserRegistry
{
    private static readonly Dictionary<string, IPayloadParser> _parsers = new(StringComparer.OrdinalIgnoreCase);
    private static readonly IPayloadParser _httpParser = new Parsers.HTTPParser();
    private static readonly IPayloadParser _sipParser = new Parsers.SIPParser();
    private static readonly IPayloadParser _jsonRpcParser = new Parsers.JSONRPCParser();
    private static readonly IPayloadParser _redisParser = new Parsers.RedisParser();
    private static readonly IPayloadParser _sshParser = new Parsers.SSHParser();
    private static readonly IPayloadParser _ssdpParser = new Parsers.SSDPParser();
    private static readonly IPayloadParser _tlsParser = new Parsers.TLSParser();
    private static readonly IPayloadParser _rdpParser = new Parsers.RDPParser();
    private static readonly IPayloadParser _rmiParser = new Parsers.RMIParser();
    private static readonly IPayloadParser _t3Parser = new Parsers.T3Parser();
    private static readonly IPayloadParser _log4jParser = new Parsers.Log4JParser();
    private static readonly IPayloadParser _envProbeParser = new Parsers.EnvProbeParser();
    private static readonly IPayloadParser _emptyParser = new Parsers.EmptyParser();
    private static readonly IPayloadParser _magellanParser = new Parsers.MagellanParser();

    static PayloadParserRegistry()
    {
        // HTTP
        Register("HTTP Request", _httpParser);
        Register("HTTP Protocol", _httpParser);
        
        // SIP
        Register("SIP Request", _sipParser);
        Register("SIP Protocol", _sipParser);
        
        // JSON-RPC / Ethereum
        Register("JSON-RPC Request", _jsonRpcParser);
        Register("JSONRPC Classifier", _jsonRpcParser);
        Register("Ethereum Block Query", _jsonRpcParser);
        Register("Ethereum Balance Query", _jsonRpcParser);
        Register("Ethereum Account Enum", _jsonRpcParser);
        Register("Ethereum TX Injection", _jsonRpcParser);
        Register("Ethereum Contract Call", _jsonRpcParser);
        Register("Ethereum Gas Estimation", _jsonRpcParser);
        Register("Ethereum Nonce Query", _jsonRpcParser);
        Register("Ethereum Contract Query", _jsonRpcParser);
        Register("Ethereum Chain ID Query", _jsonRpcParser);
        Register("Web3 Version Probe", _jsonRpcParser);
        Register("Network Version Probe", _jsonRpcParser);
        Register("Ethereum Account Unlock Attempt", _jsonRpcParser);
        Register("Ethereum TX via Personal API", _jsonRpcParser);
        Register("Ethereum Miner Control", _jsonRpcParser);
        Register("Ethereum Admin Peer Add", _jsonRpcParser);
        
        // Redis
        Register("Redis RESP Command", _redisParser);
        Register("Redis Classifier", _redisParser);
        Register("Redis Config Dump", _redisParser);
        Register("Redis Config Injection", _redisParser);
        Register("Redis Replication Hijack", _redisParser);
        Register("Redis Module Injection", _redisParser);
        Register("Redis Lua Injection", _redisParser);
        Register("Redis Script Injection", _redisParser);
        Register("Redis Debug Command", _redisParser);
        Register("Redis Data Wipe", _redisParser);
        Register("Redis DB Wipe", _redisParser);
        Register("Redis Shutdown Attack", _redisParser);
        Register("Redis Persistence Attack", _redisParser);
        Register("Redis Background Save", _redisParser);
        Register("Redis Info Probe", _redisParser);
        Register("Redis Ping Probe", _redisParser);
        Register("Redis Key Enumeration", _redisParser);
        Register("Redis Key Scan", _redisParser);
        Register("Redis Client Enum", _redisParser);
        Register("Redis Size Probe", _redisParser);
        
        // SSH
        Register("SSH Banner", _sshParser);
        Register("SSH Protocol", _sshParser);
        
        // SSDP
        Register("SSDP Search", _ssdpParser);
        Register("SSDP Notify", _ssdpParser);
        Register("SSDP Classifier", _ssdpParser);
        
        // TLS
        Register("TLS Classifier", _tlsParser);
        Register("SSL 3.0 Handshake", _tlsParser);
        Register("SSL 3.0 ClientHello", _tlsParser);
        Register("TLS 1.0 Handshake", _tlsParser);
        Register("TLS 1.0 ClientHello", _tlsParser);
        Register("TLS 1.1 Handshake", _tlsParser);
        Register("TLS 1.1 ClientHello", _tlsParser);
        Register("TLS 1.2 Handshake", _tlsParser);
        Register("TLS 1.2 ClientHello", _tlsParser);
        Register("TLS 1.3 Handshake", _tlsParser);
        Register("TLS 1.3 ClientHello", _tlsParser);
        Register("TLS Handshake", _tlsParser);
        Register("TLS ClientHello", _tlsParser);
        
        // RDP
        Register("RDP Classifier", _rdpParser);
        Register("RDP BlueKeep Probe (CVE-2019-0708)", _rdpParser);
        Register("RDP Connection Request", _rdpParser);
        Register("RDP X.224 CR", _rdpParser);
        Register("TPKT/X.224 Probe", _rdpParser);
        
        // RMI / Java
        Register("RMI Classifier", _rmiParser);
        Register("Java RMI Probe", _rmiParser);
        Register("Java RMI StreamProtocol", _rmiParser);
        Register("Java RMI SingleOpProtocol", _rmiParser);
        Register("Java RMI Multiplex", _rmiParser);
        Register("Java RMI Call", _rmiParser);
        Register("Java RMI DGC", _rmiParser);
        Register("Java RMI Return", _rmiParser);
        Register("Java Deserialization", _rmiParser);
        Register("Java Deser CommonsCollections", _rmiParser);
        Register("Java Deser ysoserial", _rmiParser);
        Register("Java Deser JRMP (CVE-2017-3241)", _rmiParser);
        Register("Java Deser Spring", _rmiParser);
        
        // T3 / WebLogic
        Register("T3 Classifier", _t3Parser);
        Register("WebLogic T3 Probe", _t3Parser);
        Register("WebLogic T3 Handshake", _t3Parser);
        Register("WebLogic XMLDecoder RCE (CVE-2019-2725)", _t3Parser);
        Register("WebLogic Console Bypass (CVE-2020-14882)", _t3Parser);
        Register("WebLogic T3 Deserialization", _t3Parser);
        
        // Log4J
        Register("Log4J Probe", _log4jParser);
        Register("Log4J Exploit", _log4jParser);
        
        // Env Probe
        Register("Env File Probe", _envProbeParser);
        Register("Env Probe", _envProbeParser);
        
        // Empty
        Register("Empty Scan", _emptyParser);
        
        // Magellan / RIPE Atlas
        Register("RIPE Atlas/Magellan Scanner", _magellanParser);
        Register("Magellan Classifier", _magellanParser);
    }

    private static void Register(string classifierName, IPayloadParser parser)
    {
        _parsers[classifierName] = parser;
    }

    /// <summary>
    /// Gets the parser for the given classifier name.
    /// </summary>
    /// <returns>Parser instance, or null if no parser registered for this classifier</returns>
    public static IPayloadParser? GetParser(string classifierName)
    {
        return _parsers.TryGetValue(classifierName, out var parser) ? parser : null;
    }
}

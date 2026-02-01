c:\Development\SlurpJob\SlurpJob\Classification\Parsers\AGENTS.md

Protocol-specific payload parsers for the PayloadInspector modal.

## HTTPParser.cs
Parses HTTP requests: method, path, Host, User-Agent, headers.

## SIPParser.cs
Parses SIP requests: method, URI, From, To, Call-ID.

## JSONRPCParser.cs
Parses JSON-RPC (Ethereum): method, params, ID, pretty-prints JSON.

## RedisParser.cs
Parses Redis RESP: command, arguments.

## SSHParser.cs
Parses SSH banners: version, software.

## SSDPParser.cs
Parses SSDP/UPnP: method, search target, MX.

## TLSParser.cs
Parses TLS ClientHello: version, handshake type, magic.

## RDPParser.cs
Parses RDP/TPKT: X.224 type, cookie, BlueKeep detection.

## RMIParser.cs
Parses Java RMI and serialized objects: protocol, gadget chains.

## T3Parser.cs
Parses WebLogic T3: version, CVE exploit patterns.

## Log4JParser.cs
Parses Log4Shell: JNDI URL, protocol, callback host, obfuscation.

## EnvProbeParser.cs
Parses config file probes: target path (.env, .git).

## EmptyParser.cs
Handles empty payloads (port scans).

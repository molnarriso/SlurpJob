c:\Development\SlurpJob\SlurpJob\Classification\AGENTS.md

This folder contains classes responsible for analyzing and classifying incoming payloads. Each classifier focuses on a single pattern or protocol.
These classifiers are consumed by `SlurpJob.Services.IngestionService` which aggregates their results to produce a final `IncidentLog`.

## IInboundClassifier.cs
Interface defining the contract for all classifier implementations. Returns `ClassificationResult` with Id, Name, Protocol, and Intent.

## IPayloadParser.cs
Interface for protocol-specific payload parsers used by PayloadInspector. Parsers extract structured fields from raw payloads.

## PayloadParserRegistry.cs
Static registry mapping classifier names to parser implementations. Used by PayloadInspector to find the right parser.

## AttackInfo.cs
Model for educational attack information including Title, WhatIsIt, Impact, TechnicalNote, and References (CVE links, MITRE ATT&CK).

## AttackCatalog.cs
Static catalog of 15+ attack descriptions keyed by classifier Id. Provides fallback to protocol-level descriptions. Used by PayloadInspector to display educational content.

## Parsers/
Folder containing 13 protocol-specific parsers (HTTPParser, SIPParser, JSONRPCParser, RedisParser, SSHParser, SSDPParser, TLSParser, RDPParser, RMIParser, T3Parser, Log4JParser, EnvProbeParser, EmptyParser).

## HTTPClassifier.cs
Detects HTTP protocol by checking for standard HTTP verbs (GET, POST, etc.) at payload start.

## SSHClassifier.cs
Detects SSH protocol by checking for SSH- banner prefix.

## Log4JClassifier.cs
Detects Log4J/Log4Shell JNDI injection exploit attempts.

## EnvProbeClassifier.cs
Detects probing for sensitive config files (.env, .git/config).

## EmptyScanClassifier.cs
Classifies empty payloads as reconnaissance scans.

## SSDPClassifier.cs
Detects SSDP (Simple Service Discovery Protocol) traffic (M-SEARCH and NOTIFY) used for UPnP discovery.

## SIPClassifier.cs
Detects SIP (Session Initiation Protocol) for VoIP enumeration.

## TLSClassifier.cs
Detects TLS ClientHello handshakes by checking for 0x1603 prefix. Identifies TLS version (1.0/1.1/1.2/1.3). Intent: Recon.

## RDPClassifier.cs
Detects RDP/X.224 Connection Requests via TPKT protocol (0x0300 prefix). Identifies BlueKeep (CVE-2019-0708) probes. Intent: Exploit.

## JSONRPCClassifier.cs
Detects JSON-RPC requests used for Ethereum node scanning. Identifies specific methods (eth_blockNumber, personal_unlockAccount, etc.). Intent: Recon/Exploit depending on method.

## RedisClassifier.cs
Detects Redis RESP protocol commands. Identifies specific attack commands (CONFIG GET, FLUSHALL, SLAVEOF, etc.). Intent: Exploit/Recon.

## RMIClassifier.cs  
Detects Java RMI (Remote Method Invocation) protocol via JRMI magic. Also detects Java serialized objects for deserialization attacks. Intent: Exploit.

## T3Classifier.cs
Detects Oracle WebLogic T3 protocol. Identifies version-specific probes and CVE payloads (CVE-2019-2725, CVE-2020-14882). Intent: Exploit.

## MagellanClassifier.cs
Detects MGLNDD (RIPE Atlas/Magellan) internet measurement scanner traffic by checking for "MGLNDD_" prefix. Intent: Recon.

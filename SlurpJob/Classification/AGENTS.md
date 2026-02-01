c:\Development\SlurpJob\SlurpJob\Classification\AGENTS.md

This folder contains classes responsible for analyzing and classifying incoming payloads. Each classifier focuses on a single pattern or protocol.
These classifiers are consumed by `SlurpJob.Services.IngestionService` which aggregates their results to produce a final `IncidentLog`.

## IInboundClassifier.cs
Interface defining the contract for all classifier implementations. Returns `ClassificationResult` with Protocol, Intent, and Name.

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

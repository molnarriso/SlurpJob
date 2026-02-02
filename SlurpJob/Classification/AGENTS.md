c:\Development\SlurpJob\SlurpJob\Classification\AGENTS.md

This folder contains classes responsible for analyzing and classifying incoming payloads. Each classifier focuses on a single pattern or protocol.
These classifiers are consumed by `SlurpJob.Services.IngestionService` which aggregates their results to produce a final `IncidentLog`.

## IInboundClassifier.cs
Interface defining the contract for all classifier implementations. Returns `ClassificationResult` (Id, Name, Protocol, Intent). Also defines the optional `Parse(byte[])` method for extracting structured data from payloads.

## AttackInfo.cs
Model for educational attack information including Title, WhatIsIt, Impact, TechnicalNote, and References (CVE links, MITRE ATT&CK).

## AttackCatalog.cs
Static catalog of attack descriptions keyed by classifier Id. Loads data from `attack_catalog.json`. Provides fallback to protocol-level descriptions. Used by PayloadInspector to display educational content.

## attack_catalog.json
JSON file containing the definitions for all known attacks and protocol fallbacks. This file is copied to the output directory and loaded by `AttackCatalog` at runtime.

## [ClassifierName].cs Files
Each classifier (e.g., `HTTPClassifier.cs`, `SSHClassifier.cs`) implements `IInboundClassifier`. It contains both the `Classify()` logic for detection and the `Parse()` logic for extracting details for the UI.

- `HTTPClassifier.cs`: Detects HTTP methods (GET, POST, etc). Parses headers.
- `SSHClassifier.cs`: Detects SSH banners. Parses version strings.
- `Log4JClassifier.cs`: Detects JNDI injection attempts. Parses target protocol/host.
- `EnvProbeClassifier.cs`: Detects config file probes. Parses target filename.
- `EmptyScanClassifier.cs`: Detects zero-length payloads.
- `SSDPClassifier.cs`: Detects SSDP M-SEARCH/NOTIFY. Parses headers.
- `SIPClassifier.cs`: Detects SIP methods (REGISTER, INVITE). Parses headers.
- `TLSClassifier.cs`: Detects TLS ClientHello (0x1603). Parses SNI and version.
- `RDPClassifier.cs`: Detects RDP/X.224 (0x0300). Identifies BlueKeep. Parses cookie/mstshash.
- `JSONRPCClassifier.cs`: Detects Ethereum JSON-RPC. Parses method and params.
- `RedisClassifier.cs`: Detects Redis RESP. Parses commands and keys.
- `RMIClassifier.cs`: Detects Java RMI/Serialization. Parses gadget chains.
- `T3Classifier.cs`: Detects WebLogic T3. Parses version and known CVE payloads.
- `MagellanClassifier.cs`: Detects RIPE Atlas probes (MGLNDD_). Parses scan target.

---

### Checklist: Adding a New Classifier

When adding a new classifier, follow these steps to ensuring full integration:

1.  **Create Classifier Class**:
    - Create `[Protocol]Classifier.cs` implementing `IInboundClassifier`.
    - Implement `Classify()` to return `ClassificationResult`.
    - Implement `Parse()` to return `ParsedPayload` (or return null if not applicable).

2.  **Register Service**:
    - Add `builder.Services.AddSingleton<IInboundClassifier, [Protocol]Classifier>();` in `Program.cs`.

3.  **Update Attack Catalog**:
    - Add a new entry to `Classification/attack_catalog.json` with the `id` returned by your classifier.
    - Include `title`, `whatIsIt`, `impact`, and `technicalNote`.
    - If your classifier uses a specific protocol name, ensure the JSON entry has the `protocol` field set for fallback lookups.

4.  **Verify**:
    - Run the application and send a test payload.
    - Verify classification in the Live Feed.
    - Click the event to open Payload Inspector:
        - Check that the **Educational Info** (from `attack_catalog.json`) loads correctly.
        - Check that the **Parsed View** (from `Parse()`) shows extracted fields.


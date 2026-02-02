c:\Development\SlurpJob\SlurpJob\Classification\AGENTS.md

This folder contains classes responsible for analyzing and classifying incoming payloads. Each classifier focuses on a single pattern or protocol.
These classifiers are consumed by `SlurpJob.Services.IngestionService` which aggregates their results to produce a final `IncidentLog`.

## IInboundClassifier.cs
Interface defining the contract for all classifier implementations. 

**Key Properties:**
- `string Id { get; }`: Stable classifier identifier (e.g., "HTTP", "TLS", "RDP"). FIXED per classifier class. Used for parser lookup in PayloadInspector.

**Methods:**
- `ClassificationResult Classify(byte[], string, int)`: Analyzes payload and returns classification with:
  - `ClassifierId`: Stable ID (same as the `Id` property)
  - `AttackId`: Specific attack pattern (e.g., "http-scanning", "rdp-bluekeep"). Used for AttackCatalog lookup.
  - `ClassifierName`: Human-readable display name (e.g., "HTTP Request", "TLS 1.2 ClientHello")
  - `Protocol`: PayloadProtocol enum
  - `Intent`: Intent enum (Exploit, Recon, Benign, Unknown)
- `ParsedPayload? Parse(byte[])`: Extracts structured data for UI display (optional).

**Field Cardinality:**
- **ClassifierId**: 1:1 with classifier class (FIXED)
- **AttackId**: 1:N per classifier (DYNAMIC - one classifier can detect multiple attack types)
- **ClassifierName**: 1:N per classifier (DYNAMIC - descriptive, varies by attack variant)

## AttackInfo.cs
Model for educational attack information including Title, WhatIsIt, Impact, TechnicalNote, and References (CVE links, MITRE ATT&CK).

## AttackCatalog.cs
Static catalog of attack descriptions keyed by **AttackId** (not ClassifierId!). Loads data from `attack_catalog.json`. Provides fallback to protocol-level descriptions. Used by PayloadInspector to display educational content.

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

When adding a new classifier, follow these steps to ensure full integration:

1.  **Create Classifier Class**:
    - Create `[Protocol]Classifier.cs` implementing `IInboundClassifier`.
    - Define a **stable `Id` property** (e.g., `public string Id => "MYPROTOCOL";`). This MUST be unique and FIXED.
    - Implement `Classify()` to return `ClassificationResult` with:
      - `ClassifierId`: Set to the same value as your `Id` property
      - `AttackId`: Specific attack pattern identifier (e.g., "myprotocol-scanning", "myprotocol-exploit")
      - `ClassifierName`: Human-readable name (e.g., "MyProtocol Scanner", "MyProtocol CVE-2024-XXXX")
      - `Protocol`: Appropriate PayloadProtocol enum value
      - `Intent`: Appropriate Intent enum value
    - Implement `Parse()` to return `ParsedPayload` with extracted fields (or return null if not applicable).

2.  **Register Service**:
    - Add `builder.Services.AddSingleton<IInboundClassifier, [Protocol]Classifier>();` in `Program.cs`.

3.  **Update Attack Catalog**:
    - Add entries to `Classification/attack_catalog.json` keyed by **AttackId** (not ClassifierId!).
    - Each attack variant your classifier detects should have its own entry.
    - Include `title`, `whatIsIt`, `impact`, and `technicalNote`.
    - Set the `protocol` field for fallback lookups.

4.  **Verify**:
    - Run the application and send a test payload.
    - Verify classification in the Live Feed shows correct ClassifierName.
    - Click the event to open Payload Inspector:
        - Check that the **Parsed button is enabled** (confirms ClassifierId lookup worked).
        - Click **Parsed** to verify the `Parse()` method extracts fields correctly.
        - Check that the **Educational Info** (from `attack_catalog.json`) loads using the AttackId.

**Example:**
```csharp
public class MyProtocolClassifier : IInboundClassifier
{
    public string Id => "MYPROTOCOL";  // FIXED - used for parser lookup
    
    public ClassificationResult Classify(byte[] payload, string protocol, int port)
    {
        // Detection logic...
        return new ClassificationResult
        {
            ClassifierId = "MYPROTOCOL",  // Same as Id property
            AttackId = "myprotocol-scanning",  // Specific attack type
            ClassifierName = "MyProtocol Scanner",  // Human-readable
            Protocol = PayloadProtocol.Unknown,
            Intent = Intent.Recon
        };
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        // Extraction logic...
    }
}
```

c:\Development\SlurpJob\SlurpJob.Tests\AGENTS.md

This folder contains the Unit and Integration tests for the solution.

## Testing Strategies
- **Unit Tests:** Test individual classifiers with synthetic payloads (e.g., `SIPClassifierTests.cs`)
- **Integration Tests:** Use in-memory databases for testing services (e.g., `ReclassificationTests.cs`)
- **Real Data Tests:** Use `slurp.db` (optional local production copy) for validating classifiers against historical attacks

> **Note:** `slurp.db` is optional. Tests that require it will be automatically skipped if the file doesn't exist. All standard unit and integration tests work without it.

## PortTableServiceTests.cs
Tests for the port table loading and lookup service.

## ReclassificationTests.cs
Integration tests for the automatic reclassification logic using in-memory database.

## SIPClassifierTests.cs
Unit tests for the SIP protocol classifier.

## SSDPClassifierTests.cs
Unit tests for the SSDP/UPnP protocol classifier.

## LocalDatabaseTests.cs
Integration tests using the local `slurp.db` production database copy to validate classifiers against real attack data. **These tests are automatically skipped if `slurp.db` doesn't exist.**

## UnitTest1.cs
Default unit test file (may be empty or placeholder).

## SlurpJob.Tests.csproj
The test project file.

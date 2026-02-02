c:\Development\SlurpJob\SlurpJob\Models\AGENTS.md

This folder contains domain models and entities.

## IncidentEntities.cs
Defines the `IncidentLog` and `EvidenceLocker` classes mapped to the database.

**Key Fields in IncidentLog:**
- `ClassifierId` (FK-like): The stable ID of the classifier that detected the payload.
- `AttackId`: The specific attack pattern identified.
- `ClassifierName`: The human-readable name of the attack.

## AttackDossier.cs
Defines the `ClassificationResult` and other non-persisted models for internal processing.

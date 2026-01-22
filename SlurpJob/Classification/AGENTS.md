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

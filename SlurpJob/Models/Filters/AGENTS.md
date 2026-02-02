c:\Development\SlurpJob\SlurpJob\Models\Filters\AGENTS.md

This folder contains filter implementations for the unified filtering system.

## IncidentFilters.cs
Contains the **Unified Filter System** definitions:
1. `IIncidentFilter` interface and `FilterVerb` enum.
2. Filter implementations:
   - `CountryFilter`: By ISO code (IS/ISN'T)
   - `ClassifierFilter`: By ClassifierName (IS/ISN'T)
   - `AttackIdFilter`: By AttackId (IS/ISN'T)
   - `PortFilter`: By TargetPort (IS/ISN'T/RANGE/NOT_RANGE)
   - `IntentFilter`: By Intent (IS/ISN'T)
   - `ProtocolFilter`: By Protocol (IS/ISN'T)

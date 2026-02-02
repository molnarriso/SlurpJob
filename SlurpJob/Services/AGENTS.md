c:\Development\SlurpJob\SlurpJob\Services\AGENTS.md

This folder contains application services and business logic.

## IngestionService.cs
Hosted service that manages the lifecycle of `TcpSponge` and `UdpSponge`, and orchestrates data saving and notification. Caches the last 20 incidents in-memory for immediate dashboard display via `GetRecentIncidents()`.

## PortTableService.cs
Singleton implementation of IPortTableService. Loads the huge 65k port table into memory for O(1) lookups.

## FilterService.cs
Scoped service (per-user) managing the active filters for the unified dashboard (Map, Timeline, LiveFeed). Handles adding/removing filters and modifying verbs.

## IncidentDto.cs
Data Transfer Object for sending incident data to the dashboard (UI).

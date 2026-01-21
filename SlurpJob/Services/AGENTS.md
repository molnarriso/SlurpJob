c:\Development\SlurpJob\SlurpJob\Services\AGENTS.md

This folder contains application services and business logic.

## IngestionService.cs
Hosted service that manages the lifecycle of `TcpSponge` and `UdpSponge`, and orchestrates data saving and notification.

## IncidentDto.cs
Data Transfer Object for sending incident data to the dashboard (UI).

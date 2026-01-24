c:\Development\SlurpJob\SlurpJob\AGENTS.md

This directory contains the main source code for the SlurpJob application.

## Classification
Contains logic and classes for identifying specific threat patterns in incoming payloads.

## Components
Contains Blazor UI components (Pages, Layouts, Shared).

## Data
Contains database related classes (EF Core context, Entities).

## Hubs
Contains SignalR hubs for real-time communication with the dashboard.

## Models
Contains data models, DTOs, and enums used throughout the application.

## Networking
Contains the core low-level networking logic (Socket listener, Ingestion).

## Services
This folder contains the application services.
- `IngestionService.cs`: Background worker for capturing traffic and logging to SQLite.
- `PortTableService.cs`: Singleton loading `port_table.csv` for real-time segmented UI classification.

## LiveFeed.razor
The real-time attack stream. Displays incoming connections using a "Segmented Row" layout with protocol-specific coloring (Cyan for TCP, Orange for UDP) and port classification pills.

## wwwroot
Contains static web assets (CSS, JavaScript, images, libraries).

## Program.cs
The application entry point and dependency injection configuration.

## appsettings.json / appsettings.Development.json
Configuration files for the application.

## SlurpJob.csproj
The project file defining dependencies and build settings.

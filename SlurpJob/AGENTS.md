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
Contains application services (Hosted services, business logic). This includes the `IngestionService` which handles real-time traffic and background reclassification of old payloads on startup.

## wwwroot
Contains static web assets (CSS, JavaScript, images, libraries).

## Program.cs
The application entry point and dependency injection configuration.

## appsettings.json / appsettings.Development.json
Configuration files for the application.

## SlurpJob.csproj
The project file defining dependencies and build settings.

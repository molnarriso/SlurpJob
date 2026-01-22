c:\Development\SlurpJob\SlurpJob\Components\Pages\AGENTS.md

This folder contains the main page components (Routable Views).

## Dashboard.razor
The main "Command Center" view and **Centralized State Controller**.
- Holds the Single Source of Truth for `CountryFilter` and `ClassifierFilter`.
- Manages 3-state filtering logic (Exclusive/Filtered/None).
- Enforces mutual exclusivity between filters.
- Pushes visual updates to dumb JS views (`map2d.js`, `timeline.js`).

## Error.razor
The default error page.

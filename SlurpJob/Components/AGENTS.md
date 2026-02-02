c:\Development\SlurpJob\SlurpJob\Components\AGENTS.md

This folder contains the Razor components for the Blazor application.

## App.razor
Root component of the application.

## Routes.razor
Handles routing for the application.

## _Imports.razor
Global using directives for Razor components.

## LiveFeed.razor
Component rendering the real-time feed of incidents. Uses a two-row layout per entry.
**Critical:** `LiveEventViewModel` must include `ClassifierId` and `AttackId` to ensure the `PayloadInspector` can properly look up the parser and educational info.

## PayloadInspector.razor
Modal/Component for inspecting raw payload details (Hex/ASCII view).
**Logic:** Uses `ClassifierId` to find the correct `IInboundClassifier` for parsing, and `AttackId` to lookup educational content in `AttackCatalog`.
**Visuals:** Displays "Parsed" button only if a parser is available for the given `ClassifierId`.

## Layout
Folder containing layout components (MainLayout, NavMenu).

## Pages
Folder containing routable page components (Dashboard, etc.).

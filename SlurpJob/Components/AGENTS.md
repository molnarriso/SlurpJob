c:\Development\SlurpJob\SlurpJob\Components\AGENTS.md

This folder contains the Razor components for the Blazor application.

## App.razor
Root component of the application.

## Routes.razor
Handles routing for the application.

## _Imports.razor
Global using directives for Razor components.

## LiveFeed.razor
Component rendering the real-time feed of incidents. Uses a two-row layout per entry: Row 1 contains all metadata (timestamp, country, port, protocol, classifier, tag) in a compact horizontal layout; Row 2 displays the payload snippet.

## PayloadInspector.razor
Modal/Component for inspecting raw payload details (Hex/ASCII view).

## Layout
Folder containing layout components (MainLayout, NavMenu).

## Pages
Folder containing routable page components (Dashboard, etc.).

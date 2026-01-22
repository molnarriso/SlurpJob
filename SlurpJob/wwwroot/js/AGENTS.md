c:\Development\SlurpJob\SlurpJob\wwwroot\js\AGENTS.md

This folder contains custom JavaScript modules for visualizations.

## map2d.js
**Dumb View** for the 2D Vector Map.
- Renders heatmap based on data from C#.
- Reports clicks to C# (`OnCountryClicked`).
- Updates visual state (Highlight/Dim/Hide) based on instructions from C#.

## globe.js
Logic for the 3D Globe visualization (Three.js / Globe.gl).

## timeline.js
**Dumb View** for the stacked bar chart timeline.
- Renders chart based on data from C#.
- Reports legend clicks to C# (`OnClassifierClicked`).
- Hides/Shows datasets based on visual state pushed from C#.

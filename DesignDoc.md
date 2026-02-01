
#  Specification: SlurpJob.com
**Type:** Network Telescope / Single-Point Sensor
**Target:** .NET 10 Monolith on Linux (AWS t3.small)
**Core Philosophy:** "The Sponge" – Absorb, Classify, Log, **Visualize**.

## 1. High-Level Mission
**SlurpJob** is an integrated Network Intelligence System. Its mission is two-fold:
1.  **The Sponge:** To silently accept unsolicited traffic on all 65,535 TCP/UDP ports, capturing payloads with high fidelity without exposing vulnerabilities.
2.  **The Dashboard:** To provide the maintainer with a "Command Center" view of the internet's background radiation. It transforms raw binary streams into a living, visual narrative, allowing the maintainer to instantly distinguish between routine scans and novel attack vectors over varying timelines.

**Key Constraints:**
*   **No Replies:** The system completes TCP handshakes to allow data flow but sends **zero** application-layer data back.
*   **Total Recall:** Every connection is significant. We prioritize capturing the exact binary evidence of every attempt.
*   **Human-in-the-Loop:** The system is designed to aid the maintainer in identifying unknown threats, which are then manually analyzed and codified into the system.

## 2. System Overview: The Monolith
The application is a single compiled binary (`SlurpJob`) handling three concurrent responsibilities:

1.  **Ingestion Engine:** Raw socket management using native System calls.
2.  **Classification Brain:** A rigid, high-performance logic loop for identifying threats.
3.  **Intelligence Layer:** `PortTableService` providing O(1) in-memory port/service classification from `port_table.csv`.
4.  **Visualization Core:** A built-in Blazor Server web application hosting the dashboard.

### Network Interface Strategy
To monitor privileged ports (80, 443) safely while hosting the dashboard:
*   **Public Interface (0.0.0.0):** OS-level redirection funnels all external traffic (Ports 1–65535) into the Ingestion Engine.
*   **Local Interface (127.0.0.1):** The Dashboard binds strictly to localhost.
*   **Tunneling:** A Cloudflare Tunnel connects `slurpjob.com` directly to the Local Interface, keeping the management UI isolated from the "Sponge" ports.

## 3. Ingestion Pipeline
This logic executes for every incoming connection stream.

### A. The Funnel
Traffic is redirected at the Kernel level to two high-level bind ports (e.g., 9000/9001) to allow the application to run with standard user privileges.

### B. The Stream Lifecycle
1.  **Connect:** Accept the TCP connection or receive the UDP datagram.
2.  **Metadata Resolution:** Immediately query the Kernel to identify the **Original Target Port** (the port the attacker *thought* they were hitting).
3.  **Ingest:**
    *   Read the incoming binary stream.
    *   **Max Ingest:** 16KB hard limit. (Sufficient for initial payloads).
    *   **Timeout:** 15 Seconds. If no data is received within this window, the connection is treated as an "Empty Scan."
4.  **Terminate:** Immediately close the socket.

### C. The Brain (Classification)
The captured binary blob is passed to the Classification Engine.
*   **Mechanism:** The engine iterates through a loaded set of `IInboundClassifier` classes.
*   **Logic:** Simple, sequential checks using string matching, binary signatures, or header validation. (No heavy parsing libraries).
*   **Output:** Returns a `ClassificationResult` containing:
    *   **Name:** (e.g., "Log4J Probe", "Mirai Variant").
    *   **Tags:** (Enum-based: `Exploit`, `Recon`, `Garbage`, `Unknown`).

## 4. Data Architecture (SQLite)
The database is designed to separate "Hot" metadata (for fast charting) from "Cold" evidence (for deep inspection).

### Table A: `IncidentLog`
*Purpose: High-speed queries for the Dashboard Timeline and Map.*
*   `Id` (Int64, PK)
*   `Timestamp` (DateTime, Indexed)
*   `SourceIp` (String)
*   `CountryCode` (String, 2-Char)
*   `TargetPort` (Int)
*   `Protocol` (Enum: TCP/UDP)
*   `PrimaryTag` (Enum: `Exploit`, `Recon`, `Unknown`, etc.)
*   `ClassifierName` (String)

### Table B: `EvidenceLocker`
*Purpose: Archival of the raw attack data.*
*   `IncidentId` (FK)
*   `PayloadBlob` (Blob) - The exact binary captured from the stream.

**Retention Policy:**
Data is kept indefinitely to build a long-term historical record. Disk usage is monitored; if the disk approaches capacity, the maintainer will manually archive or prune old evidence blobs.

### D. Automatic Reclassification (On Startup)
To ensure the system evolves with new threats, the application performs a background reclassification of all "Unclassified" incidents whenever the service starts. It iterates through the `IncidentLog` table, retrieves the raw payload from the `EvidenceLocker`, and re-runs the current set of `IInboundClassifier` implementations to see if a more specific identification can be made.

## 5. Dashboard Architecture
**Technology:** ASP.NET Core Blazor Server.
**Visual Language:** "Terminal Chic" / "Sci-Fi Industrial".
*   **Palette:** Deep Grey Backgrounds (`#1a1a1a`), High-Contrast Orange (`#ff9900`) or Amber text.
*   **Typography:** Monospace fonts for data, clean Sans-Serif for headers.

### A. Connectivity (Real-Time)
The dashboard utilizes a persistent **SignalR (WebSocket)** connection. New incidents are pushed from the Ingestion Engine to the Browser immediately. **No polling.**

### B. The "Command Center" Layout

**1. The Live Feed (Left Panel)**
*   **Behavior:** A strictly chronological, scrolling list of incoming connections.
*   **Segmented Layout:** Each entry is a structured "Command Center" row with metadata segments:
    *   **Timestamp**: Precise capture time.
    *   **Country**: IP-based origin flag.
    *   **Protocol**: TCP (Cyan) or UDP (Orange) indicator.
    *   **Port**: The targeted service port.
    *   **Classification**: Real-time service description (e.g., "SSH", "RFB / VNC") from the port table.
    *   **Classifier**: The internal logic name that identified the packet.
    *   **Intent**: High-contrast badge indicating threat level (`Exploit`, `Recon`, etc.).
*   **Virtualization:** Handles thousands of rows without browser lag.
*   **Content:** Detailed metadata in Row 1, payload hex/ASCII snippet in Row 2.
*   **Silence Indicator:** A subtle status beacon to confirm the system is operational during quiet periods.

**2. The Tactical Map (Center/Bottom)**
*   **Visual:** A 2D Vector World Map.
*   **Style:** Chloropleth. Countries are shaded based on attack intensity over the selected timeframe.

**3. The Timeline (Top/Center)**
*   **Visual:** Stacked Bar Chart.
*   **X-Axis:** Time (Dynamic resolution).
*   **Y-Axis:** Incident Count.
*   **Segments:** Bars are stacked by `PrimaryTag` (e.g., How much was `Recon` vs `Exploit`?).
*   **Interactivity:**
    *   **Scopes:** 1 Hour, 24 Hours, 7 Days, 1 Month, 1 Year, All Time.
    *   Clicking a bar filters the Incident list below.

**4. The Inspector (Modal)**
*   Activated by clicking any incident in the feed or charts.
*   Displays full metadata (IP, timestamps).
*   **Evidence View:** A dual-pane Hex/ASCII viewer to manually inspect the raw binary payload.

## 6. The "Offline" Maintenance Loop
This process ensures the system evolves to match new threats.

1.  **Discovery:** The maintainer reviews the Dashboard, filtering for the `Unknown` tag.
2.  **Analysis:** Using the Inspector or external SQL tools, the maintainer identifies recurring patterns in the unclassified blobs.
3.  **Codification:** The maintainer writes a new C# class implementing `IInboundClassifier` (e.g., `Classifiers/NewIotWorm.cs`).
4.  **Update:** The application is recompiled and restarted. The new logic now applies to all *future* connections.
# Architecture Specification: SlurpJob.com (Part 1/3)
**Target System:** .NET 9 Monolith on Linux (AWS t3.small)
**Deployment:** Systemd Service (No Docker)

## 1. Core Philosophy & Requirements
**SlurpJob** is a single-server network telescope designed to accept, log, and visualize traffic on all 65,535 TCP ports.
*   **The Spirit:** A lightweight, low-maintenance "always-on" monitor. If the server dies from a massive DDoS, it dies. We prioritize architecture simplicity over enterprise-grade resilience.
*   **The Output:** A "Matrix-style" live dashboard and historical trends showing the "Invisible War" of background internet noise.

## 2. Network Architecture: "The Funnel"
To bypass OS resource limits (file descriptors/threads), the application will **not** listen on 65,535 individual sockets.

### The Redirect Strategy
We utilize the Linux Kernel (`iptables` or `nftables`) to funnel traffic into two distinct application listeners.
*   **TCP Flow:** The Kernel redirects all TCP traffic (Ports 1–65535) to **Port 9000**.
*   **UDP Flow:** The Kernel redirects all UDP traffic (Ports 1–65535) to **Port 9001**.
*   **App Layer:**
    *   `TcpListener` binds to Port 9000.
    *   `UdpClient` binds to Port 9001.

### The Origin Recovery (Crucial Design Detail)
Because traffic is redirected, the application’s sockets see the Local Port as 9000/9001. To correctly log the attack, we must query the Kernel for the original destination.
*   **TCP:** Query `SO_ORIGINAL_DST` (via `getsockopt` syscall) immediately after accepting a connection.
*   **UDP:** Use `IP_RECVORIGDSTADDR` (via `setsockopt`/`recvmsg`) to extract the destination header from the packet metadata.

## 3. Ingestion Logic: "The Sponge"
The application acts as a "Sponge"—it absorbs data to analyze it but enforces strict boundaries to manage resources.


### A. TCP Lifecycle (Connection Oriented)
1.  **Accept & Identify:** Accept Client. Immediately resolve Original Port and Source IP.
2.  **Sampling:** Read the incoming stream into a fixed buffer.
    *   **Limit:** Capture up to **32KB**.
3.  **Termination (Cut the Cord):**
    *   Once 32KB is captured, or if the client stops sending, **immediately close the connection**.
    *   **Anti-Flooding Logic:** We do *not* drain the socket. If a bot sends 500MB, we cut it off at 32KB. We prioritize freeing the socket for the next attacker over calculating the exact size of a flood.

### B. UDP Lifecycle (Fire-and-Forget)
1.  **Receive:** Read the Datagram on Port 9001.
2.  **Identify:** Extract Source IP and Original Target Port from headers.
3.  **Capture:** The sample is the entire datagram (UDP is naturally limited to ~65KB). There is no "connection" to close.

### Enrichment (Common)
*   **Geo-Tagging:** Immediately resolve Source IP to Country Code/ASN using local MaxMind DB.
*   **TLS/SNI:** If the payload looks like a TLS Client Hello, parse and store the **SNI Hostname** instead of the raw hex.

## 4. Data Architecture Strategy: "RAM-First"
To handle potentially high throughput (thousands of connections per second) without locking the database or destroying the SD card/SSD, the system uses a **State Synchronization Model**.

*   **RAM is the Source of Truth:** The current state of "Who is attacking right now?" lives entirely in memory.
*   **Disk is the Archive:** The database is updated via a "Write-Behind" process that periodically flushes aggregated snapshots of the RAM state.

## 5. Memory Hierarchy (RAM - The Hot Layer)
We utilize a **Dossier & Engagement** model to keep all history in memory (up to 1GB) while grouping attacks intelligently.


### A. The "Matrix" Buffer (Visual Feed)
*   **Purpose:** Powers the "Live Scroll" on the dashboard.
*   **Structure:** A **Circular Buffer** (Fixed-Size Queue) holding the last **50-100** raw events.
*   **Behavior:**
    *   As new connections arrive, they are pushed into this queue.
    *   Oldest events drop off instantly.
    *   **No Aggregation:** This buffer stores specific details: `Source IP`, `Exact Timestamp`, `Full Payload Snippet`.
    *   **Persistence:** None. Clears on restart.

### B. The Aggregator: "The Dossier System"
*   **Purpose:** Stores the complete history of all attacks in a structured, queryable format within RAM.
*   **Structure:** A `ConcurrentDictionary` where Key = `PayloadHash`.
    *   *Note:* For UDP empty packets, the "Hash" includes the Target Port to distinguish generic noise from specific probing (e.g., DNS vs NTP).

### C. The Safety Valve (OOM Protection)
To protect the 1GB RAM limit from "Random Data" attacks (which generate infinite unique Dossiers):
*   Before creating a **new** `AttackDossier`, check `GC.GetTotalMemory()`.
*   **Trigger:** If Memory > **900MB**.
*   **Action:** Stop creating new Dossiers. Bucket all *new* unique payloads into a global `OverflowDossier`. Existing Dossiers continue to update normally.


**The Data Classes:**
1.  **`AttackDossier` (The "Who"):** Created once per unique payload.
    *   `Protocol`: TCP/UDP.
    *   `PayloadData`: The raw text/hex (stored once).
    *   `Engagements`: A `List<Engagement>`.
2.  **`Engagement` (The "When"):** Represents a specific "wave" of attacks.
    *   `StartTime` / `EndTime`.
    *   `TotalCount`.
    *   `SourceMap`: A lightweight dictionary of `{ Country: Count }`.

## 6. Grouping & Ingestion Flow
This process ensures we capture granular detail without exploding row counts.

1.  **Arrival:** Packet arrives. Compute Hash.
2.  **Lookup:** Retrieve the `AttackDossier` for this Hash. (If missing, create one).
3.  **Session Check (Time-Boxing):**
    *   Look at the *last* `Engagement` in the Dossier's list.
    *   **Rule:** Is `(Now - Engagement.LastSeen) < 10 Minutes`?
        *   **Yes:** It's the same wave. Increment the existing Engagement's counters.
        *   **No:** It's a new wave. Create a **new** `Engagement` object and append it to the list.
4.  **Result:** We preserve the history that "Botnet X attacked on Monday" and "Botnet X attacked again on Friday" as distinct events, without duplicating the payload data.


## 7. Persistence Strategy (Disk - The Cold Layer)
We utilize **SQLite** with a **Write-Behind (Debounce)** pattern.

### The Sync Cycle
A background worker runs on a short timer (e.g., every 5 seconds). It does **not** dump the entire RAM state. It performs a **Differential Write**.

1.  **Scan:** Iterate through all Active Groups in RAM.
2.  **Identify Changes:** Look for dimensional entries (Country+Port) marked as "Dirty."
3.  **Flush to Disk:**
    *   For every dirty entry, write a **Summary Row** to the database.
    *   *Example:* If 50 attacks came from CN in the last 5 seconds, write **one row** saying: `{Time: Now, Hash: X, Country: CN, Port: 80, Count: 50}`.
4.  **Reset:** Update the `LastPersistedCount` in RAM to match the current count.

### Storage Schema (SQLite)
To maintain long-term history (months) while keeping queries fast, we split data into Definitions and Activity.

**Table A: `Signatures` (Definitions)**
*   *Purpose:* Stores the heavy text data **once**.
*   **Columns:** `Hash` (PK), `PayloadRaw` (Blob), `SniHostname` (Text), `FirstSeen` (Date).

**Table B: `ActivityLog` (The Timeline)**
*   *Purpose:* The historical record of who did what and when.
*   **Columns:**
    *   `Id` (AutoInc)
    *   `Timestamp` (DateTime) - Rounded to the sync interval (e.g., nearest 5s).
    *   `SignatureHash` (FK) - Links to the payload.
    *   `CountryCode` (Text) - "CN", "US", etc.
    *   `TargetPort` (Int) - 80, 445, etc.
    *   `Count` (Int) - How many attacks in this batch?
    *   `TotalBytes` (Long) - Sum of bytes for this batch.

**Table C: `GeoStats` (Optimization)**
*   *Purpose:* Pre-aggregated counters strictly for the Map/Globe to avoid summing millions of rows in the `ActivityLog`.
*   **Columns:** `Date` (Day), `CountryCode`, `TotalHits`.


## 8. Frontend Architecture (Blazor Server)
The frontend is built directly into the monolithic application using **ASP.NET Core Blazor Server**. This allows real-time data streaming from the RAM layer to the browser over a persistent SignalR connection without complex API polling.

### A. The Dashboard Layout
**Theme:** "Dark Mode / Cyberpunk." High contrast, monospace fonts (e.g., 'JetBrains Mono' or 'Fira Code').

1.  **The "Live Feed" (Left Column - 25% Width)**
    *   **Source:** Polls the in-memory `Matrix Buffer` (defined in Part 2) every 1 second.
    *   **Visualization:** A vertical list of the last 50 events. New items fade in at the top; old items slide out.
    *   **Content:** `[HH:mm:ss] [CN] -> [Port 445] : <Payload Snippet>`
    *   **Interaction:** Clicking a row opens the **Payload Inspector Modal**.

2.  **The "Global View" (Center - 50% Width)**
    *   **Tab System:** Users can toggle between "3D Globe" and "2D Heatmap."
    *   **3D Globe (Primary):**
        *   **Library:** `globe.gl` (JavaScript via Blazor JS Interop).
        *   **Data:** Queries the `GeoStats` table/cache.
        *   **Animation:** Draw arcs from Source Lat/Long to Server Lat/Long. Arc color depends on the Port (e.g., Red=SSH, Blue=Web, Green=Other).
    *   **2D Map (Secondary):**
        *   A standard Chloropleth map (Countries colored by attack intensity).

3.  **The "Intelligence" Panel (Right Column - 25% Width)**
    *   **Leaderboards:** "Top 10 Source Countries", "Top 10 Attacked Ports", "Top 10 Attack Signatures."
    *   **Time Selection:** "Last Hour" (RAM data) vs "Last 24h / 7 Days" (SQLite Aggregates).

### B. The Payload Inspector Modal (Security Critical)
This component visualizes the captured data.
*   **Safety Rule:** **NEVER** render payload data as HTML or execute it.
*   **Layout:** A Split-View "Hex Editor" style display.
    *   **Left Pane:** Raw Hex Dump (`00 0A 1B FF ...`).
    *   **Right Pane:** Safe ASCII Representation. Non-printable characters must be replaced with dots (`.`) or escaped codes (`\n`).
*   **Metadata:** Display the full "Group Breakdown" here—showing which Countries contributed to this specific payload signature.

## 9. Deployment Strategy (Ops)
**Infrastructure:** AWS `t3.small` (2 vCPU, 2GB RAM).
**OS:** Amazon Linux 2023 or Ubuntu LTS.

### A. Application Packaging
*   **Build:** Publish as a **Single File Executable** (Self-Contained).
    *   `dotnet publish -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true`
*   **Result:** A single binary file named `SlurpJob`.

### B. Directory Structure
```text
/opt/slurpjob/
├── SlurpJob             # The Binary
├── appsettings.json     # Config (Limits, License Keys)
├── GeoLite2-Country.mmdb # MaxMind DB
└── data/                # SQLite Files
    ├── slurp_20231001.db
    ├── slurp_20231002.db
    └── ...
```

### C. Service Management (Systemd)
*   **User:** Run as a dedicated unprivileged user (e.g., `slurpuser`).
*   **Capabilities:** Because the application binds to ports **9000** and **9001** (High Ports > 1024), **no root privileges** or `CAP_NET_BIND_SERVICE` are required.
*   **Restart:** `Restart=always` to ensure uptime.

### D. Database Maintenance (Auto-Rotation)
The application itself handles the lifecycle of the SQLite files.
*   **Startup:** Check `/data/` folder.
*   **Cleanup Task:** A nightly background task runs at 00:00 UTC. It deletes any `.db` files where the filename date is older than **10 days**.

## 10. Security & Stability Protocols

1.  **The "Panic Button" (Circuit Breaker):**
    *   The app monitors its own Process CPU usage.
    *   **Trigger:** If CPU > 90% for 60 seconds OR Inbound Traffic > 50 Mbps.
    *   **Action:** Execute a shell command to flush the `iptables` redirect rule (`iptables -t nat -F`). This effectively "unplugging" the sensor.
    *   **Recovery:** Manual restart required (or auto-retry after 1 hour).

2.  **Input Sanitization:**
    *   All UI output is strictly encoded.
    *   MaxMind Lookups are wrapped in `try/catch` to prevent crashes from malformed IPs.

## 11. Implementation Task List (For the Developer)

**Phase 1: The Networking Core**
1.  Set up the Linux VPS. Configure `iptables` to redirect TCP 1-65535 to 9000.
2.  Write C# Console App using `TcpListener` on 9000.
3.  Implement `Libc` Interop to retrieve `SO_ORIGINAL_DST`.
4.  Verify you can distinguish a connection to Port 80 vs Port 22.

**Phase 2: Data Ingestion**
1.  Implement the "Sponge" Reader (32KB sample, 5MB max drain).
2.  Integrate `MaxMind.GeoIP2`.
3.  Implement the **RAM Aggregator** (`ConcurrentDictionary` with Payload grouping).
4.  Implement the **Write-Behind Worker** and SQLite Schema (Signatures vs ActivityLog).

**Phase 3: Visualization**
1.  Set up Blazor Server project.
2.  Create the `MatrixBuffer` service and connect it to the Ingestion Logic.
3.  Build the "Live Feed" component (SignalR updates).
4.  Build the "Hex Dump" Modal.
5.  Integrate `globe.gl` and bind it to the GeoStats data.

**Phase 4: Polish & Deploy**
1.  Implement the "Panic Button" logic.
2.  Publish Single File binary.
3.  Write `systemd` unit file.
4.  **Go Live.**

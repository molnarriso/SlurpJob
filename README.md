# SlurpJob 🧽

**Network Traffic Monitor & Threat Visualizer**

SlurpJob is a high-performance **network listener and analyzer** designed to silently absorb, classify, and visualize internet background radiation. It listens on all 65,535 TCP/UDP ports, capturing payloads to identify scans, exploits, and botnet activity.

> **🤖 Agentic Ready:** This project is fully optimized for AI-driven development, featuring comprehensive `AGENTS.md` context files in every directory and a master `DesignDoc.md`.

## 🌍 Current Infrastructure
*   **Hosting:** AWS EC2 (t4g.small / ARM64)
*   **OS:** Amazon Linux 2023
*   **Domain:** [slurpjob.com](http://slurpjob.com) (Honeypot) / [dashboard.slurpjob.com](https://dashboard.slurpjob.com) (UI)
*   **License:** [GPLv3](LICENSE)

## 🎯 What It Does
*   **The Sponge:** Accepts connections on ALL ports (1-65535), reads the payload, and sends *zero* application data back.
*   **Classification:** Identifies threats (e.g., Log4J, Mirai, HTTP Recon) using lightweight pattern matching.
*   **Visualization:** Provides a real-time **Blazor Server Dashboard** to view live attacks, timelines, and a heatmap of global activity.
*   **Architecture:** Uses a "Split-Horizon" setup:
    *   **Honeypot:** Exposed on the public IP via `iptables` redirection.
    *   **Dashboard:** Securely accessible via **Cloudflare Tunnel** (ensures dashboard has a different IP from the honeypot & no open management ports).

## 🚀 How to Deploy
The project targets **AWS EC2 (Amazon Linux 2023 - ARM64)**.

### Automated Deployment
Use the included PowerShell script to run tests, build for Linux ARM64, and deploy to the server:

```powershell
./deploy.ps1
```

This script will:
1.  Run local unit tests.
2.  Publish a single-file binary for `linux-arm64`.
3.  Stop the remote service.
4.  SCP the binaries to `/opt/slurpjob/`.
5.  Restart the service.

### Manual Commands
If you need to build manually:

```bash
# Build for Linux ARM64
dotnet publish SlurpJob/SlurpJob.csproj -c Release -r linux-arm64 --self-contained -p:PublishSingleFile=true -o ./publish_arm64
```

## 📂 Project Structure
*   `SlurpJob/`: Main ASP.NET Core / Blazor application.
*   `SlurpJob.Tests/`: Unit tests.
*   `DesignDoc.md`: Detailed architectural specification.
*   `ServerSetup.md`: Full server provisioning guide (AWS/Linux setup).

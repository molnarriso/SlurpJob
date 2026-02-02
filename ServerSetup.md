# SlurpJob Infrastructure Documentation

## Executive Summary
This document outlines the deployment strategy for **SlurpJob**, a single-node network telescope designed to capture and visualize internet background radiation.

The objective is to deploy a **Total Surveillance Sensor** on a standard AWS EC2 instance that captures traffic on **all 65,535 TCP and UDP ports**—including high-value targets like Port 80 (HTTP) and Port 443 (HTTPS)—while simultaneously hosting a secure, publicly accessible web dashboard on the same server.

## The Architectural Challenge
Running a honeypot and a management dashboard on the same server presents two critical conflicts:
1.  **The Physics Conflict:** You cannot have the Honeypot listen on Port 80 (to capture web attacks) and the Dashboard listen on Port 80 (to serve the UI) at the same time on the same network interface.
2.  **The Reputation Conflict:** If the Honeypot does its job, the server IP will be flagged as "Malicious/Botnet" by threat intelligence vendors. If the Dashboard runs on that same IP, browsers (Chrome/Edge) will block users with "Deceptive Site" warnings.

## The Solution: "Split-Horizon" Architecture
To solve this, we utilize a split networking model that separates "Management Traffic" from "Attack Traffic" using distinct ingress paths.

### 1. The Secure Lane (The Dashboard)
*   **Technology:** Cloudflare Zero Trust Tunnel.
*   **Mechanism:** The server creates an encrypted *outbound* connection to Cloudflare.
*   **Result:** The Dashboard (`slurpjob.com`) resolves to Cloudflare IPs. It is protected by WAF, uses Cloudflare's clean IP reputation, and requires **zero open ports** on the server firewall.

### 2. The Trap Lane (The Honeypot)
*   **Technology:** Linux Kernel Networking (`iptables`).
*   **Mechanism:** The server's Public IP (no DNS record) is left exposed. We use `iptables` to perform "Port redirection," acting as a funnel that sucks traffic from **all** public ports and dumps it into the SlurpJob ingestion engine.
*   **Result:** The Honeypot captures 100% of traffic, including Ports 80 and 443, without interfering with the Dashboard.
*   **Note:** Direct IP scanners will continue to hit all ports. DNS-resolving bots will follow `slurpjob.com` to Cloudflare (dashboard only).

---

# Setup Guide

**Target System:** AWS EC2 (Amazon Linux 2023 - ARM64 / Graviton)
**Architecture Visual:**
*   **Honeypot:** Direct Public IP (`ens5`) $\rightarrow$ IPTables Funnel $\rightarrow$ App (Ports 9000/9001).
*   **Dashboard:** Cloudflare Tunnel (`tun0`) $\rightarrow$ App (Localhost:5000).

## Phase 1: Cloudflare Networking (The "Split")

### 1. DNS Configuration
1.  **Registrar:** Update your domain's Nameservers to the ones assigned by Cloudflare (e.g., `khloe.ns.cloudflare.com`, `rommy.ns.cloudflare.com`).
2.  **Cloudflare Dashboard (DNS Records):**
    *   Create a **CNAME Record** for the root domain (`@` or `slurpjob.com`).
    *   **Target:** Your Cloudflare Tunnel ID (e.g., `8bba5e76-5d35-4eb2-972...`).
    *   **Proxy Status:** **Proxied (Orange Cloud)** $\leftarrow$ *This routes `slurpjob.com` through the tunnel to your dashboard.*
    *   **Note:** Do NOT create an A record pointing to your public IP. The honeypot receives traffic via direct IP scanning only.

### 2. Tunnel Installation (ARM64)
Run on EC2:
```bash
# Remove old/wrong versions if any
rm cloudflared.rpm

# Download ARM64 version
curl -L --output cloudflared.rpm https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-aarch64.rpm

# Install
sudo yum localinstall cloudflared.rpm -y
```

### 3. Tunnel Setup
```bash
# Login (Copy URL to browser)
cloudflared tunnel login

# Create Tunnel (Copy the UUID output!)
cloudflared tunnel create slurp-tunnel

# Route DNS to Tunnel
cloudflared tunnel route dns slurp-tunnel slurpjob.com
```

### 4. Configure Tunnel Service
Create the system configuration file:
```bash
# Create directory
sudo mkdir -p /etc/cloudflared/

# Create config file
sudo nano /etc/cloudflared/config.yml
```

**Content (`/etc/cloudflared/config.yml`):**
*Replace `<UUID>` with your actual Tunnel ID.*
```yaml
tunnel: <UUID>
credentials-file: /etc/cloudflared/<UUID>.json

ingress:
  - hostname: slurpjob.com
    service: http://localhost:5000
  - service: http_status:404
```

**Install & Start:**
```bash
# Move credentials to system path
sudo cp /home/ec2-user/.cloudflared/<UUID>.json /etc/cloudflared/

# Install and Start Service
sudo cloudflared service install
sudo systemctl start cloudflared
sudo systemctl enable cloudflared
```

---

## Phase 2: Operating System & Firewall (The "Funnel")

### 1. Install Persistence Tools
Amazon Linux 2023 does not save IPTables rules by default.
```bash
sudo yum install iptables-services -y
```

### 2. Apply Redirection Rules
Redirects all public traffic to the application ports, while keeping SSH and Localhost safe.
*Note: AWS AL2023 usually uses interface `ens5`. Check `ip addr` to confirm.*

```bash
# 1. Flush old NAT rules
sudo iptables -t nat -F

# 2. Exempt SSH (Port 22) from redirection
sudo iptables -t nat -A PREROUTING -i ens5 -p tcp --dport 22 -j RETURN

# 3. Redirect ALL other TCP -> Port 9000
sudo iptables -t nat -A PREROUTING -i ens5 -p tcp -j REDIRECT --to-ports 9000

# 4. Redirect ALL UDP -> Port 9001
sudo iptables -t nat -A PREROUTING -i ens5 -p udp -j REDIRECT --to-ports 9001
```

### 3. Persist Rules
```bash
# Save to disk
sudo sh -c "iptables-save > /etc/sysconfig/iptables"

# Enable service on boot
sudo systemctl enable --now iptables
```

---

## Phase 3: Application Deployment

### 1. Prerequisites
Install .NET 9 Runtime (or SDK).
```bash
sudo yum install dotnet-sdk-9.0 -y
```

### 2. Publish Code
On your development machine (Windows):
```powershell
dotnet publish -c Release -r linux-arm64 --self-contained -p:PublishSingleFile=true
```
Copy the binary (`SlurpJob`) and `wwwroot` to the server (e.g., `/opt/slurpjob/`).

### 3. Systemd Service
Create the service to run the app in the background.

```bash
sudo nano /etc/systemd/system/slurpjob.service
```

**Content:**
```ini
[Unit]
Description=SlurpJob Network Telescope
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/slurpjob
ExecStart=/opt/slurpjob/SlurpJob
Restart=always
RestartSec=10
Environment=ASPNETCORE_ENVIRONMENT=Production
# Ensure it binds to localhost for the tunnel
Environment=ASPNETCORE_URLS=http://localhost:5000

[Install]
WantedBy=multi-user.target
```

**Enable & Start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now slurpjob
```

---

## Phase 4: Critical Code Configuration
Ensure these two files match this configuration for the architecture to work.

### `Program.cs` (Binding)
Must bind strictly to `localhost` to avoid conflict with the Honeypot interface.

```csharp
// ... Services setup ...

app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

// BIND TO LOCALHOST
app.Run("http://localhost:5000");
```

### `Networking/TcpSponge.cs` (Logic)
Must **not** contain any Proxy logic. It is a "Black Hole" only.

```csharp
// Inside HandleClientAsync...

// 1. Get Original Destination
var originalEp = LinuxInterop.GetOriginalDestination(socket);

// 2. Read Payload
int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);

// 3. Log Event
OnConnectionReceived?.Invoke(data);

// 4. Close (End of 'using' block) - NO RESPONSE SENT
```

---

## Phase 5: Verification

### Check Dashboard
Visit `https://slurpjob.com`. It should load via Cloudflare.

### Check Honeypot (TCP)
From a different machine (using direct public IP, not domain):
```bash
curl http://3.127.242.167  # Replace with your actual public IP
```
*   **Result:** Connection Reset / Empty Reply (Correct).
*   **Dashboard:** New event appears (Source: Your IP, Port: 80).

### Check Honeypot (UDP)
From a different machine (using direct public IP, not domain):
```bash
dig @3.127.242.167 google.com  # Replace with your actual public IP
```
*   **Result:** Timeout (Correct).
*   **Dashboard:** New event appears (Protocol: UDP).
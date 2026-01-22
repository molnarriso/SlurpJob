c:\Development\SlurpJob\AGENTS.md

This is the root directory of the SlurpJob project, a network telescope and single-point sensor.

## SlurpJob
This folder contains the main application source code (ASP.NET Core / Blazor Server).

## SlurpJob.Tests
This folder contains the unit tests for the project.

## DesignDoc.md
The master design document describing the system architecture, goals, and technical details. MUST be read by all agents.

## ServerSetup.md
Instructions for setting up the Linux server environment.

## deploy.ps1
PowerShell script to deploy the application to AWS. See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

## DEPLOYMENT.md
Comprehensive deployment guide including troubleshooting and workflows.

## chatbot_dump.ps1
Helper script to dump context for LLMs.

## context_dump.txt
A dump of the project context.

## slurpjob.service
Systemd service file for running the application on Linux.

## slurpjob.pem / slurpjob.ppk
SSH keys for server access.

## nuget.config
NuGet configuration file.

## SlurpJob.sln
The Visual Studio solution file.

---

## 🚀 Workflows & Best Practices

### 🛠 UI Development & Tuning
To speed up UI development and avoid long build/deploy cycles:
1.  **Iterate in Browser:** Use the Browser Developer Console (`F12`) to tweak CSS and HTML live.
2.  **Verify via Screenshots:** Use the `browser_subagent` to capture screenshots and confirm the visual state.
3.  **Prototype with JS:** Inject styles or dummy data via `execute_browser_javascript` to test layouts.
4.  **Implement:** Once you know what works visually, implement in the actual source files.

> [!IMPORTANT]
> **Visual Confirmation Required:** Any agent making visual/UI changes MUST capture a browser screenshot of the final result to verify the changes are working as intended. This is a mandatory step before considering the task complete. Deploy if necessary to see changes on the live site.

### 🚢 Deployment Workflow
Deploying to the AWS production server:
1.  **Script:** Run `./deploy.ps1` from the root directory.
2.  **Process:**
    - Publishes the app for `linux-arm64` (Self-contained).
    - Stops the `slurpjob` systemd service.
    - Nukes the old `slurp.db` (Caution: data is lost).
    - Uploads files via `pscp`.
    - Ensures GeoIP database is present.
    - Restarts the service.
3.  **Verification:** Always verify `https://dashboard.slurpjob.com/` after deployment.

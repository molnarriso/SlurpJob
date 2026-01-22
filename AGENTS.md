c:\Development\SlurpJob\AGENTS.md

This is the root directory of the SlurpJob project, a network telescope and exploit identifier with public dashboard.

## SlurpJob
This folder contains the main application source code (ASP.NET Core / Blazor Server).

## SlurpJob.Tests
This folder contains the unit tests for the project.

## DesignDoc.md
The master design document describing the system architecture, goals, and technical details. MUST be read by all agents.

## ServerSetup.md
Instructions for setting up the Linux server environment.

## deploy.ps1
PowerShell script to deploy the application to AWS. Runs tests, builds, and deploys.

## chatbot_dump.ps1
Helper script to dump context for LLMs.

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
5.  **Local Testing Constraint:** Do NOT rely on local execution (`dotnet run`) to verify features that require live internet traffic (like `IngestionService` receiving packets). The local environment is not public-facing. Use unit tests, static analysis, or mocked data for these cases.

> [!IMPORTANT]
> **Visual Confirmation Required:** Any agent making visual/UI changes MUST capture a browser screenshot of the final result to verify the changes are working as intended. This is a mandatory step before considering the task complete. Deploy if necessary to see changes on the live site.

### 🔄 Cycle: Test -> Deploy -> Commit
The standard lifecycle for changes is:

1.  **Test:** Run `dotnet test` locally. **Do not proceed if tests fail.**
2.  **Deploy:**
    *   Ask permission for the *first* deployment.
    *   Run `./deploy.ps1`. (See details below).
3.  **Verify:** Check `https://dashboard.slurpjob.com/` (Ctrl+F5).
4.  **Confirm & Commit:** **ONLY** after stability is confirmed:
    *   Create a concise commit message.
    *   **Complex Commits:** For refactors or large features, use a **verbose, bulleted** message instead of a single line.
    *   `git push` the changes.

### � Reference: deploy.ps1
The deployment script (`./deploy.ps1`) handles the heavy lifting:
1.  **Tests:** Runs checks. Aborts on failure.
2.  **Build:** Compiles for Linux ARM64.
3.  **Deploy:** Stops service -> Uploads binaries -> Restarts service.

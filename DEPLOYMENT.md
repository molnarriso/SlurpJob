# Deployment

Run from project root:
```powershell
.\deploy.ps1
```

## What it does
1. Builds for `linux-arm64`
2. Stops service on AWS
3. Uploads files to `/opt/slurpjob/`
4. Starts service

Database is preserved between deployments.

## After Deploy
Hard-refresh browser (Ctrl+F5) to clear cache.

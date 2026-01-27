# Deploy SlurpJob to AWS (OpenSSH Version)

# Load Configuration
if (Test-Path "deploy.config.ps1") {
    . ./deploy.config.ps1
} else {
    Write-Error "Configuration file 'deploy.config.ps1' not found. Please copy 'deploy.config.example.ps1' to 'deploy.config.ps1'."
    exit 1
}

Write-Host "Deploying to $User@$ServerIp..." -ForegroundColor DarkGray

# Running Tests
Write-Host "--- Step 1: Running Tests ---" -ForegroundColor Cyan
dotnet test SlurpJob.Tests/SlurpJob.Tests.csproj
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed! Deployment aborted."
    exit 1
}

# Publishing for Linux ARM64
Write-Host "--- Step 2: Publishing ---" -ForegroundColor Cyan
dotnet publish SlurpJob/SlurpJob.csproj -c Release -r linux-arm64 --self-contained -p:PublishSingleFile=true -o ./publish_arm64
if ($LASTEXITCODE -ne 0) {
    Write-Error "Publish failed!"
    exit 1
}

# Compressing Files (7-Zip)
Write-Host "--- Step 3: Compressing ---" -ForegroundColor Cyan
if (Test-Path "deploy.7z") { Remove-Item "deploy.7z" }
7z a -mx=1 deploy.7z .\publish_arm64\*
if ($LASTEXITCODE -ne 0) {
    Write-Error "Compression failed! Ensure 7z is in your PATH."
    exit 1
}

# Preparing SSH Environment
Write-Host "--- Step 4: Securing SSH Key & Verifying Host ---" -ForegroundColor Cyan
# Fixes "Permissions too open" error for OpenSSH
icacls $Key /inheritance:r | Out-Null
icacls $Key /grant:r "$($env:USERNAME):R" | Out-Null

# Uploading Archive & Script
Write-Host "--- Step 5: Uploading ---" -ForegroundColor Cyan
# -o StrictHostKeyChecking=accept-new automatically handles the host verification
scp -i $Key -o StrictHostKeyChecking=accept-new deploy.7z server_deploy.sh "$User@$($ServerIp):$RemotePath"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Upload failed! Check your config and network connection."
    exit 1
}

# Executing Remote Deployment
Write-Host "--- Step 6: Remote Execution ---" -ForegroundColor Cyan
ssh -i $Key -o StrictHostKeyChecking=accept-new "$User@$ServerIp" "chmod +x $RemotePath/server_deploy.sh && cd $RemotePath && ./server_deploy.sh"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Remote deployment script failed!"
    exit 1
}

Write-Host "Deployment Complete!" -ForegroundColor Green

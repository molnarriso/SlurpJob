# Deploy SlurpJob to AWS

# Load Configuration
if (Test-Path "deploy.config.ps1") {
    . ./deploy.config.ps1
} else {
    Write-Error "Configuration file 'deploy.config.ps1' not found. Please copy 'deploy.config.example.ps1' to 'deploy.config.ps1' and update your settings."
    exit 1
}

Write-Host "Deploying to $User@$ServerIp..." -ForegroundColor DarkGray

Write-Host "0. Running Tests..." -ForegroundColor Cyan
dotnet test SlurpJob.Tests/SlurpJob.Tests.csproj

if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed! Deployment aborted."
    exit 1
}

Write-Host "1. Publishing for Linux ARM64..." -ForegroundColor Cyan
dotnet publish SlurpJob/SlurpJob.csproj -c Release -r linux-arm64 --self-contained -p:PublishSingleFile=true -o ./publish_arm64

if ($LASTEXITCODE -ne 0) {
    Write-Error "Publish failed!"
    exit 1
}

Write-Host "2. Compressing Files (7-Zip)..." -ForegroundColor Cyan
# -t7z is default, -mx=1 is fastest compression
if (Test-Path "deploy.7z") { Remove-Item "deploy.7z" }
7z a -mx=1 deploy.7z .\publish_arm64\*

Write-Host "4. Uploading Archive & Script..." -ForegroundColor Cyan
# Upload both the zip and the helper script
pscp -batch -i $Key deploy.7z server_deploy.sh $User@$ServerIp`:$RemotePath

Write-Host "5. Executing Remote Deployment..." -ForegroundColor Cyan
# Execute the helper script
plink -batch -i $Key -ssh $User@$ServerIp "chmod +x $RemotePath/server_deploy.sh && cd $RemotePath && ./server_deploy.sh"

Write-Host "Deployment Complete!" -ForegroundColor Green

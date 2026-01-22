# Deploy SlurpJob to AWS

$ServerIp = "3.127.242.167"
$User = "ec2-user"
$Key = "slurpjob.ppk"
$RemotePath = "/opt/slurpjob/"

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

Write-Host "2. Stopping Service..." -ForegroundColor Cyan
plink -batch -i $Key -ssh $User@$ServerIp "sudo systemctl stop slurpjob"


Write-Host "3. Uploading Files..." -ForegroundColor Cyan
pscp -batch -i $Key -r publish_arm64/* $User@$ServerIp`:$RemotePath

Write-Host "3b. Downloading GeoIP Database (City)..." -ForegroundColor Cyan
plink -batch -i $Key -ssh $User@$ServerIp "if [ ! -f $RemotePath/GeoLite2-City.mmdb ]; then sudo curl -L -o $RemotePath/GeoLite2-City.mmdb https://git.io/GeoLite2-City.mmdb; fi"

Write-Host "4. Starting Service..." -ForegroundColor Cyan
plink -batch -i $Key -ssh $User@$ServerIp "sudo chmod +x $RemotePath/SlurpJob && sudo systemctl start slurpjob"

Write-Host "Deployment Complete!" -ForegroundColor Green

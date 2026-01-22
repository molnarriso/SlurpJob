# Deployment Configuration Template
# Copy this file to deploy.config.ps1 and fill in your details

$ServerIp = "YOUR_SERVER_IP"  # e.g. 1.2.3.4
$User = "ec2-user"            # e.g. ubuntu, ec2-user
$Key = "slurpjob.ppk"         # Path to your private key file
$RemotePath = "/opt/slurpjob/" # Target directory on the server

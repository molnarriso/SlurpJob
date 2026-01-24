#!/bin/bash
set -e

# 1. Ensure 7zip is installed
if ! command -v 7z &> /dev/null; then
    echo "Installing p7zip..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y p7zip-full
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y p7zip p7zip-plugins
    elif command -v yum &> /dev/null; then
        sudo yum install -y p7zip p7zip-plugins
    else
        echo "Error: Package manager not found. Please install p7zip manually."
        exit 1
    fi
fi

# 2. Stop Service
echo "Stopping Service..."
sudo systemctl stop slurpjob

# 3. Extract Archive
echo "Extracting deploy.7z..."
# -y : assume Yes on all queries (overwrite)
7z x deploy.7z -y > /dev/null

# 3. Cleanup
echo "Cleaning up..."
rm deploy.7z

# 4. Set Permissions
chmod +x SlurpJob

# 5. Restart Service
echo "Restarting Service..."
sudo systemctl restart slurpjob

echo "Server-side deployment successful."

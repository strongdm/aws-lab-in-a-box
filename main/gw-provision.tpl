#!/usr/bin/env bash
#--------------------------------------------------------------
# StrongDM Gateway Provisioning Script
#
# This script configures an EC2 instance to run as a StrongDM Gateway.
# The gateway serves as the entry point for StrongDM clients to access
# protected resources. This script:
#
# - Installs and configures the StrongDM CLI
# - Sets up the gateway with the provided relay token
# - Configures the system for optimal gateway operation
# - Disables conflicting services like UFW firewall
#--------------------------------------------------------------

export SDM_RELAY_TOKEN=${sdm_relay_token}
export TARGET_USER=${target_user}
export SDM_HOME="/home/$TARGET_USER/.sdm"
apt-get update -y | logger -t sdminstall
apt-get upgrade -y | logger -t sdminstall
apt-get install -y unzip | logger -t sdminstall
curl -J -O -L https://app.strongdm.com/releases/cli/linux && unzip sdmcli* && rm sdmcli*
systemctl disable ufw.service
systemctl stop ufw.service
# Install SDM
%{ if sdm_domain != "" }
sudo ./sdm install --relay --token=$SDM_RELAY_TOKEN --user=$TARGET_USER --domain=${sdm_domain}| logger -t sdminstall
%{ endif }
%{ if sdm_domain == "" }
sudo ./sdm install --relay --token=$SDM_RELAY_TOKEN --user=$TARGET_USER| logger -t sdminstall
%{ endif }

%{ if create_hcvault }
# Setup Vault authentication for StrongDM relay
echo "Setting up Vault authentication for StrongDM relay" | logger -t sdminstall

# Install Vault client
sudo apt-get install -y jq curl | logger -t sdminstall
curl -O https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_linux_amd64.zip
unzip vault_${vault_version}_linux_amd64.zip
sudo cp vault /usr/local/bin/vault
sudo chmod +x /usr/local/bin/vault
rm vault_${vault_version}_linux_amd64.zip vault

# Create the Vault authentication script
sudo tee /usr/local/bin/vault-auth.sh <<VAULT_AUTH_EOF
#!/bin/bash

export VAULT_ADDR="${vault_url}"
export AWS_REGION="${aws_region}"

# Authenticate to Vault using AWS auth method
# Get instance identity document and signature from EC2 metadata service
INSTANCE_IDENTITY=\$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | base64 -w 0)
INSTANCE_SIGNATURE=\$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/signature | tr -d '\n')

# Nonce storage location
NONCE_FILE="/var/lib/vault-nonce"

# Check if we have a stored nonce
if [ -f "\$NONCE_FILE" ]; then
    NONCE=\$(cat "\$NONCE_FILE")
    echo "Using stored nonce for authentication" | logger -t vault-auth
    VAULT_RESPONSE=\$(vault write -format=json auth/aws/login role=strongdm identity=\$INSTANCE_IDENTITY signature=\$INSTANCE_SIGNATURE nonce=\$NONCE)
else
    echo "First time authentication, will store nonce" | logger -t vault-auth
    VAULT_RESPONSE=\$(vault write -format=json auth/aws/login role=strongdm identity=\$INSTANCE_IDENTITY signature=\$INSTANCE_SIGNATURE)
    # Extract and store the nonce for future use
    NONCE=\$(echo "\$VAULT_RESPONSE" | jq -r '.auth.metadata.nonce')
    if [ "\$NONCE" != "null" ] && [ -n "\$NONCE" ]; then
        echo "\$NONCE" | sudo tee "\$NONCE_FILE" > /dev/null
        sudo chmod 600 "\$NONCE_FILE"
        echo "Stored nonce for future authentications" | logger -t vault-auth
    fi
fi

VAULT_TOKEN=\$(echo "\$VAULT_RESPONSE" | jq -r '.auth.client_token')

if [ "\$VAULT_TOKEN" != "null" ] && [ -n "\$VAULT_TOKEN" ]; then
    # Update /etc/sysconfig/sdm with the new token
    mkdir -p /etc/sysconfig
    
    # Remove existing VAULT_TOKEN line if it exists
    sudo sed -i '/^VAULT_TOKEN=/d' /etc/sysconfig/sdm-proxy 2>/dev/null || true
    
    # Add the new VAULT_TOKEN
    echo "VAULT_TOKEN=\$VAULT_TOKEN" | sudo tee -a /etc/sysconfig/sdm-proxy
    
    # Restart the sdm-proxy service to pick up the new token
    sudo systemctl restart sdm-proxy
    
    echo "\$(date): Successfully authenticated to Vault, updated VAULT_TOKEN, and restarted sdm-proxy" | logger -t vault-auth
else
    echo "\$(date): Failed to authenticate to Vault" | logger -t vault-auth
fi
VAULT_AUTH_EOF

# Make the script executable
sudo chmod +x /usr/local/bin/vault-auth.sh

# Run the initial authentication
/usr/local/bin/vault-auth.sh

# Setup cron job to run every 3 hours
echo "*/29 * * * * root /usr/local/bin/vault-auth.sh" | sudo tee -a /etc/crontab

echo "Vault authentication setup complete" | logger -t sdminstall
%{ endif }
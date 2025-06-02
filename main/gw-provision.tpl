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
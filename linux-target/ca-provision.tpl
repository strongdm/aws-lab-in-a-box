#!/usr/bin/env bash
#--------------------------------------------------------------
# Linux Target SSH CA Provisioning Script
#
# This script configures a Linux target for SSH certificate-based
# authentication with StrongDM. It sets up the SSH CA public key
# and configures SSH to trust certificates signed by StrongDM's
# certificate authority, eliminating the need for password or
# key-based authentication.
#
# Key operations:
# - Installs the StrongDM SSH CA public key
# - Configures SSH to accept certificate authentication
# - Sets up proper permissions and SSH configuration
#--------------------------------------------------------------

export TARGET_USER=${target_user}
apt-get update -y | logger -t sdminstall
apt-get upgrade -y | logger -t sdminstall
apt-get install -y unzip | logger -t sdminstall
systemctl disable ufw.service
systemctl stop ufw.service
echo "Copying SSHCA ${sshca} to /etc/ssh/sdm_ca.pub" | logger -t sdminstall
echo "${sshca}" | sudo tee -a /etc/ssh/sdm_ca.pub
echo "Setting SSH CA permissions" | logger -t sdminstall
chmod 600 /etc/ssh/sdm_ca.pub
echo "Enabling $TARGET_USER to login using SSH CA" | logger -t sdminstall
mkdir /etc/ssh/sdm_users
sudo echo "strongdm" > /etc/ssh/sdm_users/$TARGET_USER
echo "Reconfiguring SSHD" | logger -t sdminstall
echo "TrustedUserCAKeys /etc/ssh/sdm_ca.pub" | sudo tee -a /etc/ssh/sshd_config.d/100-strongdm.conf
echo "AuthorizedPrincipalsFile /etc/ssh/sdm_users/%u" | sudo tee -a /etc/ssh/sshd_config.d/100-strongdm.conf
echo "Restarting SSHD" | logger -t sdminstall
systemctl restart ssh
echo "StrongDM target configuration done" | logger -t sdminstall
sudo systemctl restart ssh
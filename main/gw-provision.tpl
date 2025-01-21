#!/usr/bin/env bash

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
sudo ./sdm install --relay --token=$SDM_RELAY_TOKEN --user=$TARGET_USER | logger -t sdminstall
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

%{ if has_domain_controller }
#--------------------------------------------------------------
# Configure hostname with domain suffix
#--------------------------------------------------------------
echo "Configuring hostname with domain suffix" | logger -t sdminstall

CURRENT_HOSTNAME=$(hostname)
FULL_HOSTNAME="$CURRENT_HOSTNAME.${domain_name}.local"

echo "Current hostname: $CURRENT_HOSTNAME" | logger -t sdminstall
echo "Setting FQDN to: $FULL_HOSTNAME" | logger -t sdminstall

# Set the hostname with domain
hostnamectl set-hostname "$FULL_HOSTNAME"

# Update /etc/hosts to include FQDN
sed -i "s/127.0.1.1.*/127.0.1.1 $FULL_HOSTNAME $CURRENT_HOSTNAME/" /etc/hosts

# If the entry doesn't exist, add it
grep -q "127.0.1.1" /etc/hosts || echo "127.0.1.1 $FULL_HOSTNAME $CURRENT_HOSTNAME" >> /etc/hosts

echo "Hostname configured: $(hostname -f)" | logger -t sdminstall

#--------------------------------------------------------------
# Configure DNS to use Domain Controller
#--------------------------------------------------------------
echo "Configuring DNS to use Domain Controller" | logger -t sdminstall

DC_IP="${dc_ip}"
if [ -n "$DC_IP" ]; then
    echo "Setting DNS to Domain Controller IP: $DC_IP" | logger -t sdminstall

    # Configure systemd-resolved to use DC as DNS
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/dc-dns.conf <<EOF
[Resolve]
DNS=$DC_IP
Domains=${domain_name}.local
FallbackDNS=
DNSSEC=no
EOF

    # Override main resolved.conf to ensure DC DNS is primary
    cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=$DC_IP
Domains=${domain_name}.local
FallbackDNS=
DNSSEC=no
DNSOverTLS=no
EOF

    systemctl restart systemd-resolved

    # Clear DNS cache
    resolvectl flush-caches

    echo "DNS configured to use Domain Controller" | logger -t sdminstall
else
    echo "WARNING: DC IP not provided, skipping DNS configuration" | logger -t sdminstall
fi

#--------------------------------------------------------------
# Configure network to ignore DHCP DNS
#--------------------------------------------------------------
echo "Configuring network to ignore DHCP DNS" | logger -t sdminstall

# Find the netplan config file
NETPLAN_FILE=$(ls /etc/netplan/*.yaml 2>/dev/null | head -1)

if [ -n "$NETPLAN_FILE" ]; then
    echo "Updating netplan configuration: $NETPLAN_FILE" | logger -t sdminstall

    cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      dhcp4-overrides:
        use-dns: false
        use-domains: false
      nameservers:
        addresses: [$DC_IP]
        search: [${domain_name}.local]
EOF

    netplan apply
    echo "Netplan configuration updated" | logger -t sdminstall
fi

# Disable cloud-init network management to prevent overrides
mkdir -p /etc/cloud/cloud.cfg.d
cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<EOF
network: {config: disabled}
EOF

echo "Network configuration complete" | logger -t sdminstall

#--------------------------------------------------------------
# Import Domain Controller CA Certificate
#--------------------------------------------------------------
echo "Importing Domain Controller CA certificate" | logger -t sdminstall

# Write the CA certificate to a file
cat > /usr/local/share/ca-certificates/${domain_name}-ca.crt <<'EOFCERT'
${dc_ca_certificate}
EOFCERT

# Update CA certificates
if update-ca-certificates; then
    echo "Successfully imported DC CA certificate" | logger -t sdminstall
else
    echo "ERROR: Failed to update CA certificates" | logger -t sdminstall
fi

#--------------------------------------------------------------
# Install Active Directory Domain Join Packages
#--------------------------------------------------------------
echo "Installing Active Directory domain join packages..." | logger -t sdminstall
apt-get install -y sssd-ad sssd-tools realmd adcli | logger -t sdminstall

#--------------------------------------------------------------
# Join Active Directory Domain
#--------------------------------------------------------------
echo "Joining Active Directory domain..." | logger -t sdminstall
echo "${domain_password}" | realm join -v -U ${domain_admin} ${domain_name}.local | logger -t sdminstall

if [ $? -eq 0 ]; then
    echo "Successfully joined domain ${domain_name}.local" | logger -t sdminstall

    #--------------------------------------------------------------
    # Configure PAM for automatic home directory creation
    #--------------------------------------------------------------
    echo "Configuring PAM to create home directories automatically..." | logger -t sdminstall
    pam-auth-update --enable mkhomedir

    # Also ensure it's configured in common-session
    if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
        echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session
    fi

    #--------------------------------------------------------------
    # Configure SSSD for better group enumeration
    #--------------------------------------------------------------
    echo "Configuring SSSD for group enumeration..." | logger -t sdminstall

    # Add enumeration for better group resolution
    if ! grep -q "enumerate = True" /etc/sssd/sssd.conf; then
        sed -i "/\[domain\/${domain_name}.local\]/a enumerate = True" /etc/sssd/sssd.conf
    fi

    # Set proper permissions on sssd.conf
    chmod 600 /etc/sssd/sssd.conf

    # Restart SSSD to apply changes
    systemctl restart sssd
    echo "SSSD configuration updated and restarted" | logger -t sdminstall

else
    echo "ERROR: Failed to join domain ${domain_name}.local" | logger -t sdminstall
fi
%{ endif }

echo "Copying SSHCA ${sshca} to /etc/ssh/sdm_ca.pub" | logger -t sdminstall
echo "${sshca}" | sudo tee -a /etc/ssh/sdm_ca.pub
echo "Setting SSH CA permissions" | logger -t sdminstall
chmod 600 /etc/ssh/sdm_ca.pub

%{ if has_domain_controller }
#--------------------------------------------------------------
# Configure SSH to allow any valid domain user via AuthorizedPrincipalsCommand
#--------------------------------------------------------------
echo "Configuring SSH to allow domain users via AuthorizedPrincipalsCommand" | logger -t sdminstall

# Create a script that returns "strongdm" principal for any authenticated user
cat > /usr/local/bin/sdm-principals.sh <<'EOFSCRIPT'
#!/bin/bash
# This script returns the "strongdm" principal for SSH certificate authentication
# It is called by sshd for each SSH connection attempt
# For domain-joined machines, all valid domain users are allowed
echo "strongdm"
EOFSCRIPT

chmod 755 /usr/local/bin/sdm-principals.sh
echo "Created AuthorizedPrincipalsCommand script" | logger -t sdminstall

# Configure SSH to use the principals command instead of per-user files
cat > /etc/ssh/sshd_config.d/100-strongdm.conf <<'EOFSSHD'
# StrongDM SSH Certificate Authentication Configuration
TrustedUserCAKeys /etc/ssh/sdm_ca.pub

# Use AuthorizedPrincipalsCommand to dynamically return "strongdm" principal
# This allows any valid domain user to authenticate without creating per-user files
AuthorizedPrincipalsCommand /usr/local/bin/sdm-principals.sh
AuthorizedPrincipalsCommandUser nobody
EOFSSHD

echo "Configured SSH with AuthorizedPrincipalsCommand for domain users" | logger -t sdminstall

%{ else }
#--------------------------------------------------------------
# Configure SSH with per-user principals file (non-domain joined)
#--------------------------------------------------------------
echo "Enabling $TARGET_USER to login using SSH CA" | logger -t sdminstall
mkdir -p /etc/ssh/sdm_users
echo "strongdm" > /etc/ssh/sdm_users/$TARGET_USER

echo "Reconfiguring SSHD" | logger -t sdminstall
cat > /etc/ssh/sshd_config.d/100-strongdm.conf <<EOFSSHD
# StrongDM SSH Certificate Authentication Configuration
TrustedUserCAKeys /etc/ssh/sdm_ca.pub

# Use per-user principals file
AuthorizedPrincipalsFile /etc/ssh/sdm_users/%u
EOFSSHD

echo "Configured SSH with AuthorizedPrincipalsFile for local user $TARGET_USER" | logger -t sdminstall
%{ endif }

echo "Restarting SSHD" | logger -t sdminstall
systemctl restart ssh
echo "StrongDM target configuration done" | logger -t sdminstall
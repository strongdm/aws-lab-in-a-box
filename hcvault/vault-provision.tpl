#!/usr/bin/env bash
export VAULT_ADDR=http://$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4):8200/
export TARGET_USER=${target_user}
apt-get update -y | logger -t sdminstall
apt-get upgrade -y | logger -t sdminstall
apt-get install -y unzip jq| logger -t sdminstall
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

echo "Downloading HashiCorp Vault" | logger -t sdminstall
curl -O https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_linux_amd64.zip

echo "Installing HashiCorp Vault" | logger -t sdminstall

unzip vault_${vault_version}_linux_amd64.zip

sudo cp vault /usr/bin/vault

sudo chmod +x /usr/bin/vault

sudo tee /lib/systemd/system/vault.service <<EOF
[Unit]
Description="HashiCorp Vault"
Documentation="https://developer.hashicorp.com/vault/docs"
ConditionFileNotEmpty="/etc/vault.d/vault.hcl"

[Service]
User=${target_user}
Group=${target_user}
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/bin/vault server -config=/etc/vault.d/
ExecReload=/bin/kill --signal HUP
KillMode=process
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir /etc/vault.d/
sudo mkdir /opt/vault
sudo chown ${target_user}:${target_user} /opt/vault
tee /etc/vault.d/kms-seal.hcl <<EOF
seal "awskms" {
  region     = "${region}"
  kms_key_id = "${kms_key_id}"
}
EOF

tee /etc/vault.d/storage.hcl <<EOF
storage "file" {
  path = "/opt/vault"
}
EOF

tee /etc/vault.d/vault.hcl <<EOF
ui            = true
EOF

tee /etc/vault.d/listener.hcl <<EOF
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
EOF

sudo chown -R ${target_user}:${target_user} /etc/vault.d
sudo systemctl daemon-reload

sudo service vault start
sudo systemctl enable vault.service
echo "Waiting for Vault to start"
sleep 30
export VAULT_ADDR=http://$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4):8200/

vault operator init \
    -recovery-shares=3 \
    -recovery-threshold=2 \
    -format=json | tee ~/vault-init.json
    
echo "Waiting for Vault to generate keys"
sleep 30

export VAULT_TOKEN=$(cat ~/vault-init.json | jq -r .root_token)

vault auth enable aws
vault write -force auth/aws/config/client

vault secrets enable kv

# Enable SSH secret engine for client certificate signing
vault secrets enable ssh

# Configure SSH CA for client certificate signing
vault write ssh/config/ca generate_signing_key=true

tee kvaccess.hcl <<EOF
# KV access permissions
path "kv/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

# SSH certificate signing permissions
path "ssh/sign/*" {
  capabilities = ["create", "update"]
}

path "ssh/config/ca" {
  capabilities = ["read"]
}
EOF
cat kvaccess.hcl | vault policy write kvaccess -

vault write auth/aws/role/strongdm \
    policies="kvaccess,default" \
    auth_type="ec2" \
    bound_region="${region}" \
    bound_iam_instance_profile_arn="${relay_instance_profile_arn}" \
    token_ttl=1800 \
    token_max_ttl=1800

# Create SSH role for client certificate signing
# Create JSON payload for the SSH role based on working API example
cat > /tmp/ssh_role.json <<EOF
{
  "algorithm_signer": "default",
  "allow_bare_domains": true,
  "allow_empty_principals": false,
  "allow_host_certificates": false,
  "allow_subdomains": true,
  "allow_user_certificates": true,
  "allow_user_key_ids": true,
  "allowed_critical_options": "",
  "allowed_domains": "*",
  "allowed_domains_template": false,
  "allowed_extensions": "permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc",
  "allowed_user_key_lengths": {},
  "allowed_users": "*",
  "allowed_users_template": false,
  "default_critical_options": {},
  "default_extensions": {
    "permit-agent-forwarding": "",
    "permit-port-forwarding": "",
    "permit-pty": "",
    "permit-user-rc": ""
  },
  "default_extensions_template": false,
  "default_user": "",
  "default_user_template": false,
  "key_id_format": "",
  "key_type": "ca",
  "max_ttl": 600,
  "not_before_duration": 30,
  "ttl": 300
}
EOF

vault write ssh/roles/client @/tmp/ssh_role.json

# Clean up temporary file
rm /tmp/ssh_role.json
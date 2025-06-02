#--------------------------------------------------------------
# StrongDM Certificate Authority Configuration
#
# This file retrieves the public keys for StrongDM's SSH and RDP Certificate
# Authorities. These certificates are essential for certificate-based
# authentication and are used by target resources to validate StrongDM
# client connections without requiring password-based authentication.
#
# Components:
# - SSH CA public key for Linux target authentication
# - RDP CA public key for Windows target authentication
# - Foundation for certificate-based access control
#--------------------------------------------------------------

# Retrieve the SSH Certificate Authority public key from StrongDM
data "sdm_ssh_ca_pubkey" "ssh_pubkey_query" {
}

# Retrieve the RDP Certificate Authority public key from StrongDM
data "sdm_rdp_ca_pubkey" "rdp_pubkey_query" {
}
#--------------------------------------------------------------
# Main Module Outputs
#
# Operator-facing values with no other consumer in this module.
#--------------------------------------------------------------

output "ndes_url" {
  description = "NDES enrollment URL for the ADCS/NDES server, once create_adcs is enabled"
  value       = one(module.adcs[*].ndes_url)
}

output "adcs_fqdn" {
  description = "Fully qualified domain name of the ADCS/NDES server, once create_adcs is enabled"
  value       = one(module.adcs[*].adcs_fqdn)
}

#--------------------------------------------------------------
# Windows RDP Certificate Authority Extraction Script
#--------------------------------------------------------------
# This shell script extracts the StrongDM RDP Certificate Authority
# certificate and formats it as JSON for use in Terraform templates.
# 
# Key Functions:
# - Retrieves RDP CA certificate from StrongDM admin CLI
# - Formats certificate data as JSON string for Terraform consumption
# - Enables secure RDP connections through StrongDM infrastructure
#
# Dependencies:
# - sdm CLI tool must be installed and authenticated
# - jq utility for JSON processing
# - Proper StrongDM admin permissions for certificate access
#--------------------------------------------------------------

#!/bin/bash
echo "{\"certificate\": $(sdm admin rdp view-ca | jq -Rsa) }"

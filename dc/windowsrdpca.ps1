#--------------------------------------------------------------
# Windows RDP Certificate Authority PowerShell Script
#--------------------------------------------------------------
# This PowerShell script extracts the StrongDM RDP Certificate Authority
# certificate for Windows environments and formats it as JSON.
# 
# Key Functions:
# - Validates that SDM CLI is available and accessible
# - Retrieves RDP CA certificate from StrongDM admin CLI
# - Formats certificate data as JSON for Terraform consumption
# - Provides error handling for missing dependencies
#
# Dependencies:
# - sdm CLI tool must be installed and authenticated
# - PowerShell execution policy must allow script execution
# - Proper StrongDM admin permissions for certificate access
#--------------------------------------------------------------

try {
    $sdmCommand = Get-Command sdm -ErrorAction Stop
} catch {
    Write-Error "The 'sdm' command is not available. Please ensure it is installed and accessible in your PATH."
    exit 1  # Exit with an error code
}
# Capture the output of the sdm command (assuming it's multiple lines)
$certificate = sdm admin rdp view-ca

# Join the lines into a single string (if it's an array of lines)
 $certificateString = $certificate -join "`n"
 # Create a JSON object with the certificate value
$formattedOutput = @{ "certificate" = $certificateString }
# Convert the object to a JSON string
$jsonOutput = $formattedOutput | ConvertTo-Json -Compress

# Output the final JSON string
Write-Output $jsonOutput
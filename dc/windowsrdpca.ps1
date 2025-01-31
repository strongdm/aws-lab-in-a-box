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
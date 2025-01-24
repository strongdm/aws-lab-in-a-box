<powershell>
Start-Transcript -Path "C:\SDMDomainSetup.log" -Append
"Disable NLA"
$regKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$regValueName = "UserAuthentication"

# Check if the registry key exists
if (Test-Path $regKeyPath) {
    # Set the registry value to disable NLA (0 means disabled, 1 means enabled)
    Set-ItemProperty -Path $regKeyPath -Name $regValueName -Value 0
    Write-Host "Network Level Authentication (NLA) has been disabled."
} else {
    Write-Host "Registry path not found. Ensure you're running this with administrative privileges."
}
"Changing DNS"
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses @("${dc_ip}")
# Define domain and credentials
"Joining Domain"
$domain = "${name}.local"  # Replace with your domain name
$domainUser = "${name}\domainadmin"  # Replace with a domain admin username
$domainPassword = "${domain_password}"  # Replace with the domain admin password

# Convert the password to a secure string
$securePassword = ConvertTo-SecureString -String $domainPassword -AsPlainText -Force

# Create a PSCredential object
$credential = New-Object System.Management.Automation.PSCredential ($domainUser, $securePassword)

# Join the computer to the domain
Add-Computer -DomainName $domain -Credential $credential -Restart -Force

# Output result
Write-Host "Computer has been joined to the domain and will restart."
</powershell>
#--------------------------------------------------------------
# Windows Domain Join PowerShell Template
#--------------------------------------------------------------
# This PowerShell template script configures Windows instances to
# join an Active Directory domain in the StrongDM AWS Lab-in-a-Box.
# 
# Key Functions:
# - Disables Network Level Authentication (NLA) for RDP access
# - Configures DNS settings to point to domain controller
# - Joins the Windows instance to the specified AD domain
# - Creates local domain administrator account
# - Sets up proper domain authentication
#
# Template Variables:
# - ${dc_ip}: IP address of the domain controller
# - ${name}: Domain name prefix
# - ${domain_password}: Domain administrator password
#--------------------------------------------------------------

<powershell>
Start-Transcript -Path "C:\SDMDomainSetup.log" -Append

"Installing AWS PowerShell Tools"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name AWS.Tools.Common -Force -AllowClobber
Write-Host "AWS PowerShell Tools installed successfully"

"Changing DNS"
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses @("${dc_ip}")

# Get the AWS-assigned hostname (e.g., ip-10-0-0-123)
"Getting AWS-assigned hostname from instance metadata"
$awsHostname = Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/local-hostname
$newComputerName = $awsHostname.Split('.')[0]  # Extract just the hostname part (ip-10-0-0-123)

Write-Host "Current computer name: $env:COMPUTERNAME"
Write-Host "New computer name will be: $newComputerName"

# Define domain and credentials
"Joining Domain with new computer name"
$domain = "${name}.local"  # Replace with your domain name
$domainUser = "${name}\domainadmin"  # Replace with a domain admin username
$domainPassword = "${domain_password}"  # Replace with the domain admin password

# Convert the password to a secure string
$securePassword = ConvertTo-SecureString -String $domainPassword -AsPlainText -Force

# Create a PSCredential object
$credential = New-Object System.Management.Automation.PSCredential ($domainUser, $securePassword)

# Rename computer and join the domain in a single operation (only one reboot required)
Add-Computer -DomainName $domain -NewName $newComputerName -Credential $credential -Restart -Force

# Output result
Write-Host "Computer will be renamed to $newComputerName and joined to the domain. Restarting now."
</powershell>
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

# Point DNS at the domain controller. The adapter is discovered rather than
# assumed: this previously hardcoded -InterfaceAlias "Ethernet", which matches
# no adapter on this AMI, so DNS was never set, the domain never resolved, and
# the join below failed. The ADCS module already discovers it this way.
"Changing DNS"
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
if ($null -eq $adapter) {
    throw "No network adapter is Up; cannot point DNS at the domain controller"
}
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("${dc_ip}")
Write-Host "DNS on adapter '$($adapter.Name)' (index $($adapter.ifIndex)) set to ${dc_ip}"

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

# Wait for the domain to resolve before attempting the join. DNS was only just
# repointed, and a join against an unresolvable domain fails immediately.
$resolved = $false
foreach ($attempt in 1..10) {
    try {
        Resolve-DnsName -Name $domain -Type A -ErrorAction Stop | Out-Null
        $resolved = $true
        Write-Host "Domain $domain resolved on attempt $attempt"
        break
    } catch {
        Write-Host "Domain $domain not resolvable yet (attempt $attempt): $_"
        Start-Sleep -Seconds 15
    }
}
if (-not $resolved) {
    throw "Domain $domain never resolved; not attempting to join"
}

# Rename the computer and join the domain in one operation, so only one reboot
# is needed. -ErrorAction Stop matters: without it a failed join was not fatal,
# the instance rebooted anyway, and nothing recorded that it had never joined.
foreach ($attempt in 1..5) {
    try {
        Add-Computer -DomainName $domain -NewName $newComputerName -Credential $credential -Force -ErrorAction Stop
        Write-Host "Joined $domain as $newComputerName on attempt $attempt"
        "Joined $domain as $newComputerName at $(Get-Date -Format o)" | Out-File "C:\domainjoin.done"
        break
    } catch {
        Write-Host "Domain join attempt $attempt failed: $_"
        if ($attempt -eq 5) {
            throw "Domain join failed after 5 attempts: $_"
        }
        Start-Sleep -Seconds 30
    }
}

Write-Host "Computer renamed to $newComputerName and joined to the domain. Restarting now."
Restart-Computer -Force
</powershell>
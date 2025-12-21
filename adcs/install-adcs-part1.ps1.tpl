<powershell>
#--------------------------------------------------------------
# ADCS/NDES Installation - Part 1: Domain Join
#
# This script performs initial setup:
# 1. Configure DNS to point to Domain Controller
# 2. Join the Active Directory domain
# 3. Schedule Part 2 to run after reboot
#--------------------------------------------------------------

# Logging function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Output $logMessage
    Add-Content -Path "C:\ADCSSetup.log" -Value $logMessage
}

Write-Log "=========================================="
Write-Log "ADCS/NDES Installation - Part 1: Domain Join"
Write-Log "=========================================="

# Configuration variables from Terraform
$computerName = "${computer_name}"
$domainName = "${domain_name}"
$domainFQDN = "${domain_fqdn}"
$dcIP = "${dc_ip}"
$dcFQDN = "${dc_fqdn}"
$domainAdmin = "${domain_admin_user}"
$domainPassword = "${domain_password}"
$caCommonName = "${ca_common_name}"
$templateName = "${certificate_template_name}"
$ndesServiceAccount = "${ndes_service_account}"

Write-Log "Configuration:"
Write-Log "  Computer Name: $computerName"
Write-Log "  Domain: $domainFQDN"
Write-Log "  DC IP: $dcIP"
Write-Log "  CA Common Name: $caCommonName"
Write-Log "  Template Name: $templateName"

#--------------------------------------------------------------
# Step 1: Configure DNS to use Domain Controller
#--------------------------------------------------------------
Write-Log "Step 1: Configuring DNS to point to Domain Controller..."

try {
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
    if ($adapter) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dcIP
        Write-Log "DNS configured successfully to use DC at $dcIP"

        # Verify DNS resolution
        $dnsTest = Resolve-DnsName -Name $domainFQDN -ErrorAction SilentlyContinue
        if ($dnsTest) {
            Write-Log "DNS resolution test successful for $domainFQDN"
        } else {
            Write-Log "WARNING: DNS resolution test failed for $domainFQDN"
        }
    } else {
        Write-Log "ERROR: No active network adapter found"
    }
} catch {
    Write-Log "ERROR configuring DNS: $_"
}

#--------------------------------------------------------------
# Step 2: Rename Computer and Join Active Directory Domain
#--------------------------------------------------------------
Write-Log "Step 2: Checking domain membership and hostname..."

try {
    # Get current hostname
    $currentHostname = $env:COMPUTERNAME
    Write-Log "Current hostname: $currentHostname"
    Write-Log "Target hostname: $computerName"

    # Check if already domain-joined
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $isDomainJoined = $computerSystem.PartOfDomain
    $currentDomain = $computerSystem.Domain

    Write-Log "Domain joined: $isDomainJoined"
    if ($isDomainJoined) {
        Write-Log "Current domain: $currentDomain"
    }

    # Check if already has correct name and domain membership
    if ($isDomainJoined -and $currentDomain -eq $domainFQDN -and $currentHostname -eq $computerName) {
        Write-Log "Machine already has correct name ($computerName) and is joined to $domainFQDN"
        Write-Log "Skipping domain join and reboot - domain membership already complete"
        Write-Log "ADCS installation should have already been attempted via scheduled task"
        Write-Log "If ADCS is not installed, check C:\ADCSSetup.log"
        exit 0
    }

    Write-Log "Domain join required..."

    # Create credential object
    $securePassword = ConvertTo-SecureString $domainPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", $securePassword)

    # Rename computer and join domain in single operation
    Add-Computer -DomainName $domainFQDN -NewName $computerName -Credential $credential -Force -ErrorAction Stop
    Write-Log "Successfully renamed to $computerName and joined domain $domainFQDN"
    Write-Log "System will reboot to complete domain join..."

    # Download Part 2 script from S3
    Write-Log "Downloading Part 2 installation script from S3..."
    try {
        $bucketName = "${s3_bucket}"
        $scriptKey = "install-adcs-part2.ps1"
        $scriptPath = "C:\ADCSInstall-Part2.ps1"
        $region = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/region" -TimeoutSec 5

        # Download Part 2 script
        Read-S3Object -BucketName $bucketName -Key $scriptKey -File $scriptPath -Region $region
        Write-Log "Part 2 script downloaded successfully to $scriptPath"
    } catch {
        Write-Log "ERROR downloading Part 2 script: $_"
        exit 1
    }

    # Create scheduled task to run Part 2 after reboot
    # Note: Create as SYSTEM first (before domain join), then Part 2 will use domain credentials for AD operations
    Write-Log "Creating scheduled task to run Part 2 after reboot..."

    $taskName = "ADCSInstallPart2"
    $taskAction = "PowerShell.exe -ExecutionPolicy Bypass -File `"$scriptPath`""

    # Create task as SYSTEM since we're not domain-joined yet
    $result = schtasks.exe /create `
        /tn $taskName `
        /tr $taskAction `
        /sc onstart `
        /ru "SYSTEM" `
        /rl HIGHEST `
        /f

    if ($LASTEXITCODE -eq 0) {
        Write-Log "Scheduled task '$taskName' created successfully"
    } else {
        Write-Log "ERROR creating scheduled task: $result"
        exit 1
    }

    # Reboot to complete domain join
    Write-Log "Rebooting system to complete domain join..."
    Start-Sleep -Seconds 5
    Restart-Computer -Force

} catch {
    Write-Log "ERROR during domain join: $_"
    Write-Log "Installation cannot continue without domain membership"
    exit 1
}

</powershell>

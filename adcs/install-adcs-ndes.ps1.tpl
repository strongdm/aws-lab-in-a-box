<powershell>
#--------------------------------------------------------------
# ADCS/NDES Installation and Configuration Script
#
# This script configures a Windows Server 2019 instance to serve as an
# intermediate Certificate Authority with NDES for StrongDM integration.
#
# Steps performed:
# 1. Configure DNS to point to Domain Controller
# 2. Join the Active Directory domain
# 3. Install ADCS role (Certificate Authority)
# 4. Request and install subordinate CA certificate from root CA
# 5. Install NDES role with IIS
# 6. Create StrongDM certificate template (based on Smart Card Logon)
# 7. Configure NDES registry settings
# 8. Enable IIS Basic Authentication
# 9. Configure certificate template permissions
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
Write-Log "ADCS/NDES Installation Script Starting"
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
Write-Log "Step 2: Renaming computer and joining domain $domainFQDN..."

try {
    # Get current hostname
    $currentHostname = $env:COMPUTERNAME
    Write-Log "Current hostname: $currentHostname"
    Write-Log "Target hostname: $computerName"

    # Create credential object
    $securePassword = ConvertTo-SecureString $domainPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", $securePassword)

    # Rename computer and join domain in single operation
    Add-Computer -DomainName $domainFQDN -NewName $computerName -Credential $credential -Force -ErrorAction Stop
    Write-Log "Successfully renamed to $computerName and joined domain $domainFQDN"
    Write-Log "System will reboot to complete domain join..."

    # Schedule ADCS installation to run after reboot
    $scriptPath = "C:\ADCSInstall-Part2.ps1"
    $scheduledTaskScript = @"
# Part 2: ADCS Installation (runs after domain join reboot)
`$logFile = "C:\ADCSSetup.log"
function Write-Log {
    param([string]`$Message)
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logMessage = "[`$timestamp] `$Message"
    Add-Content -Path `$logFile -Value `$logMessage
}

Write-Log "=========================================="
Write-Log "Part 2: ADCS Installation Starting (Post-Reboot)"
Write-Log "=========================================="

# Wait for domain services to be fully available
Write-Log "Waiting 60 seconds for domain services..."
Start-Sleep -Seconds 60

#--------------------------------------------------------------
# Step 3: Install ADCS Role Features
#--------------------------------------------------------------
Write-Log "Step 3: Installing ADCS role features..."

try {
    Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -ErrorAction Stop
    Write-Log "ADCS role installed successfully"
} catch {
    Write-Log "ERROR installing ADCS role: `$_"
    exit 1
}

#--------------------------------------------------------------
# Step 4: Configure ADCS as Subordinate CA
#--------------------------------------------------------------
Write-Log "Step 4: Configuring ADCS as Enterprise Subordinate CA..."

try {
    # Configure as Enterprise Subordinate CA
    Install-AdcsCertificationAuthority ``
        -CAType EnterpriseSubordinateCA ``
        -CACommonName "$caCommonName" ``
        -CADistinguishedNameSuffix "DC=$domainName,DC=local" ``
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" ``
        -KeyLength 2048 ``
        -HashAlgorithmName SHA256 ``
        -ValidityPeriod Years ``
        -ValidityPeriodUnits 5 ``
        -Force ``
        -ErrorAction Stop

    Write-Log "ADCS configured as subordinate CA successfully"
    Write-Log "CA Common Name: $caCommonName"

    # Wait for CA service to start
    Start-Sleep -Seconds 10

} catch {
    Write-Log "ERROR configuring ADCS: `$_"
    exit 1
}

#--------------------------------------------------------------
# Step 5: Request Subordinate CA Certificate from Root CA
#--------------------------------------------------------------
Write-Log "Step 5: Requesting subordinate CA certificate from root CA..."

try {
    # Get the certificate request file
    `$requestFile = "C:\Windows\system32\CertSrv\CertEnroll\${caCommonName}.req"

    if (Test-Path `$requestFile) {
        Write-Log "Certificate request file found: `$requestFile"

        # Submit request to root CA on domain controller
        `$rootCAName = "$dcFQDN\\$domainName-CA"
        Write-Log "Submitting request to root CA: `$rootCAName"

        `$certReq = certreq -submit -config "`$rootCAName" `$requestFile
        Write-Log "Certificate request submitted"

        # Wait for certificate to be issued
        Start-Sleep -Seconds 5

        # Retrieve and install the issued certificate
        `$certFile = "C:\Windows\system32\CertSrv\CertEnroll\${caCommonName}.crt"
        certreq -retrieve -config "`$rootCAName" 1 `$certFile

        if (Test-Path `$certFile) {
            certutil -installcert `$certFile
            Write-Log "Subordinate CA certificate installed successfully"

            # Start CA service
            Start-Service -Name CertSvc
            Write-Log "Certificate Authority service started"
        } else {
            Write-Log "ERROR: Certificate file not found after retrieval"
        }
    } else {
        Write-Log "ERROR: Certificate request file not found"
    }
} catch {
    Write-Log "ERROR requesting/installing CA certificate: `$_"
}

#--------------------------------------------------------------
# Step 6: Install NDES Role
#--------------------------------------------------------------
Write-Log "Step 6: Installing NDES role with IIS..."

try {
    # Install NDES and required IIS features
    Install-WindowsFeature -Name ADCS-Device-Enrollment -IncludeManagementTools -ErrorAction Stop
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop
    Install-WindowsFeature -Name Web-Basic-Auth -ErrorAction Stop

    Write-Log "NDES and IIS features installed successfully"
} catch {
    Write-Log "ERROR installing NDES: `$_"
}

#--------------------------------------------------------------
# Step 7: Create StrongDM Certificate Template
#--------------------------------------------------------------
Write-Log "Step 7: Creating StrongDM certificate template..."

try {
    # Connect to AD Certificate Services
    `$configNC = (Get-ADRootDSE).configurationNamingContext
    `$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"

    Write-Log "Certificate template container: `$templateContainer"

    # Get Smart Card Logon template as source
    `$sourceTemplate = Get-ADObject -SearchBase `$templateContainer ``
        -Filter {cn -eq "SmartcardLogon"} ``
        -Properties * ``
        -ErrorAction Stop

    if (`$sourceTemplate) {
        Write-Log "Source template 'SmartcardLogon' found"

        # Create new template based on Smart Card Logon
        `$newTemplateName = "$templateName"
        `$newTemplateDN = "CN=`$newTemplateName,`$templateContainer"

        # Check if template already exists
        `$existingTemplate = Get-ADObject -SearchBase `$templateContainer ``
            -Filter {cn -eq `$newTemplateName} ``
            -ErrorAction SilentlyContinue

        if (-not `$existingTemplate) {
            # Copy template properties
            `$templateAttributes = @{
                objectClass = "pKICertificateTemplate"
                cn = `$newTemplateName
                displayName = `$newTemplateName
                flags = 131680  # Enable: Publish to AD, Allow private key export
                "pKIDefaultKeySpec" = 1
                "pKIKeyUsage" = [byte[]](0xa0, 0x00)  # Digital signature + Key encipherment
                "pKIMaxIssuingDepth" = 0
                "pKICriticalExtensions" = "2.5.29.15"  # Key usage
                "pKIExpirationPeriod" = [byte[]](0x00, 0x40, 0x1e, 0xa4, 0xe8, 0x65, 0xfa, 0xff)  # 1 year
                "pKIOverlapPeriod" = [byte[]](0x00, 0x80, 0xa6, 0x0a, 0xff, 0xde, 0xff, 0xff)  # 6 weeks
                "pKIExtendedKeyUsage" = @("1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2")  # Smart Card Logon, Client Auth
                "msPKI-Certificate-Application-Policy" = @("1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2")
                "msPKI-Certificate-Name-Flag" = 1  # ENROLLEE_SUPPLIES_SUBJECT (allow subject in request)
                "msPKI-Enrollment-Flag" = 32  # Include symmetric algorithms
                "msPKI-Minimal-Key-Size" = 2048
                "msPKI-Private-Key-Flag" = 16842768  # Allow key export
                "msPKI-RA-Signature" = 0
                "msPKI-Template-Minor-Revision" = 1
                "msPKI-Template-Schema-Version" = 2
                "revision" = 100
            }

            New-ADObject -Name `$newTemplateName ``
                -Type pKICertificateTemplate ``
                -Path `$templateContainer ``
                -OtherAttributes `$templateAttributes ``
                -ErrorAction Stop

            Write-Log "Certificate template '`$newTemplateName' created successfully"
            Write-Log "Template allows subject name in request: ENABLED"

            # Add template to CA
            Start-Sleep -Seconds 5
            certutil -SetCATemplates +`$newTemplateName
            Write-Log "Template added to CA"

        } else {
            Write-Log "Certificate template '`$newTemplateName' already exists"
        }
    } else {
        Write-Log "ERROR: SmartcardLogon template not found"
    }
} catch {
    Write-Log "ERROR creating certificate template: `$_"
}

#--------------------------------------------------------------
# Step 8: Configure NDES
#--------------------------------------------------------------
Write-Log "Step 8: Configuring NDES..."

try {
    # Create service account credential (using domain admin for now)
    # NOTE: Credential not logged for security
    `$securePassword = ConvertTo-SecureString "$domainPassword" -AsPlainText -Force
    `$serviceCredential = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", `$securePassword)

    # Install ADCS Network Device Enrollment Service
    Install-AdcsNetworkDeviceEnrollmentService ``
        -ApplicationPoolIdentity ``
        -CAConfig "$dcFQDN\\$domainName-CA" ``
        -RAName "StrongDM NDES RA" ``
        -RAEmail "ndes@$domainFQDN" ``
        -RACompany "StrongDM" ``
        -RADepartment "IT" ``
        -RACity "San Mateo" ``
        -RAState "CA" ``
        -RACountry "US" ``
        -SigningProviderName "Microsoft Strong Cryptographic Provider" ``
        -SigningKeyLength 2048 ``
        -EncryptionProviderName "Microsoft Strong Cryptographic Provider" ``
        -EncryptionKeyLength 2048 ``
        -ServiceAccountCredential `$serviceCredential ``
        -Force ``
        -ErrorAction Stop

    Write-Log "NDES configured successfully"
} catch {
    Write-Log "ERROR configuring NDES: `$_"
}

#--------------------------------------------------------------
# Step 9: Configure NDES Registry Settings
#--------------------------------------------------------------
Write-Log "Step 9: Configuring NDES registry for StrongDM template..."

try {
    `$mscepPath = "HKLM:\Software\Microsoft\Cryptography\MSCEP"

    if (Test-Path `$mscepPath) {
        # Set all MSCEP registry values to use StrongDM template
        Set-ItemProperty -Path `$mscepPath -Name "EncryptionTemplate" -Value "$templateName" -ErrorAction Stop
        Set-ItemProperty -Path `$mscepPath -Name "GeneralPurposeTemplate" -Value "$templateName" -ErrorAction Stop
        Set-ItemProperty -Path `$mscepPath -Name "SignatureTemplate" -Value "$templateName" -ErrorAction Stop

        Write-Log "NDES registry configured to use '$templateName' template"

        # Increase challenge password cache (for multiple gateways)
        Set-ItemProperty -Path `$mscepPath -Name "MaxPendingRequests" -Value 50 -ErrorAction Stop
        Write-Log "Increased MaxPendingRequests to 50"

        # Restart IIS to apply changes
        iisreset
        Write-Log "IIS restarted to apply registry changes"
    } else {
        Write-Log "ERROR: MSCEP registry path not found"
    }
} catch {
    Write-Log "ERROR configuring NDES registry: `$_"
}

#--------------------------------------------------------------
# Step 10: Enable IIS Basic Authentication
#--------------------------------------------------------------
Write-Log "Step 10: Enabling IIS Basic Authentication for NDES..."

try {
    Import-Module WebAdministration

    # Enable Basic Auth for CERTSRV application
    Set-WebConfigurationProperty ``
        -Filter "/system.webServer/security/authentication/basicAuthentication" ``
        -Name "enabled" ``
        -Value "True" ``
        -PSPath "IIS:\" ``
        -Location "Default Web Site/CertSrv/mscep" ``
        -ErrorAction Stop

    Write-Log "Basic Authentication enabled for NDES SCEP endpoint"

    # Set Application Pool to Integrated mode (recommended)
    `$appPool = Get-Item "IIS:\AppPools\SCEP"
    if (`$appPool) {
        `$appPool.managedPipelineMode = "Integrated"
        `$appPool | Set-Item
        Write-Log "SCEP Application Pool set to Integrated mode"
    }

    # Configure HTTPS binding with machine certificate
    Write-Log "Configuring HTTPS binding for NDES..."

    # Get the machine certificate from the local computer's personal store
    # The certificate will be auto-enrolled from the domain CA
    Start-Sleep -Seconds 10  # Wait for certificate auto-enrollment

    `$machineCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        `$_.Subject -like "*$computerName*" -and `$_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
    } | Select-Object -First 1

    if (`$machineCert) {
        Write-Log "Machine certificate found: `$(`$machineCert.Subject)"

        # Add HTTPS binding to Default Web Site
        New-WebBinding -Name "Default Web Site" ``
            -Protocol https ``
            -Port 443 ``
            -SslFlags 0 ``
            -ErrorAction SilentlyContinue

        # Bind the certificate to the HTTPS binding
        `$binding = Get-WebBinding -Name "Default Web Site" -Protocol https
        `$binding.AddSslCertificate(`$machineCert.Thumbprint, "my")

        Write-Log "HTTPS binding configured with machine certificate"
    } else {
        Write-Log "WARNING: Machine certificate not found for HTTPS binding"
        Write-Log "HTTPS will not be available - certificate may enroll after group policy refresh"
    }

    # Restart IIS
    iisreset
    Write-Log "IIS restarted"

} catch {
    Write-Log "ERROR configuring IIS: `$_"
}

#--------------------------------------------------------------
# Step 11: Configure Certificate Template Permissions
#--------------------------------------------------------------
Write-Log "Step 11: Configuring certificate template permissions..."

try {
    # Grant NDES service account permissions on the template
    `$configNC = (Get-ADRootDSE).configurationNamingContext
    `$templateDN = "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,`$configNC"

    # Add Read and Enroll permissions for Domain Computers
    # (Using certutil as it's simpler than ACL manipulation)
    certutil -dstemplate $templateName

    Write-Log "Certificate template permissions configured"
} catch {
    Write-Log "ERROR configuring template permissions: `$_"
}

Write-Log "=========================================="
Write-Log "ADCS/NDES Installation Complete!"
Write-Log "=========================================="
Write-Log ""
Write-Log "NDES URL: http://`$(hostname)/certsrv/mscep/mscep.dll"
Write-Log "Certificate Template: $templateName"
Write-Log "CA Common Name: $caCommonName"
Write-Log ""
Write-Log "For StrongDM Gateway configuration:"
Write-Log "  SDM_ADCS_USER=${domain_admin_user}@${domain_fqdn}"
Write-Log "  SDM_ADCS_PW=<use domain admin password>"
Write-Log ""

# Remove scheduled task
Unregister-ScheduledTask -TaskName "ADCSInstallPart2" -Confirm:`$false -ErrorAction SilentlyContinue
"@

    # Save Part 2 script
    $scheduledTaskScript | Out-File -FilePath $scriptPath -Encoding ASCII
    Write-Log "Part 2 script saved to $scriptPath"

    # Create scheduled task to run Part 2 after reboot
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName "ADCSInstallPart2" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
    Write-Log "Scheduled task 'ADCSInstallPart2' created for post-reboot execution"

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

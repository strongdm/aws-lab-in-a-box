#--------------------------------------------------------------
# Domain Controller Promotion Script (For Packer-Built AMI)
#--------------------------------------------------------------
# This PowerShell template script promotes a Packer-built Windows Server
# to an Active Directory Domain Controller. The Packer AMI already has:
# - ADDS Windows Feature installed
# - DNS Windows Feature installed
# - PowerShell modules (ADDSDeployment, DnsServer) installed
# - AWS Tools for PowerShell installed
# - Base system configuration completed
#
# This script performs:
# - Domain Controller promotion (ADDS Forest creation)
# - ADCS Windows Feature installation (after DC promotion)
# - ADCS configuration as Enterprise Root CA
# - RDP certificate authentication setup
# - Domain users creation
# - Group Policy configuration for StrongDM
#
# Template Variables:
# - ${rdpca_base64}: RDP certificate authority certificate (base64 encoded)
# - ${name}: Domain name prefix for forest creation
# - ${password}: Administrator password for DC
# - ${domain_users_hash}: Hash of domain users (triggers recreation on change)
# - ${s3_bucket}: S3 bucket containing domain users JSON
# - ${s3_key}: S3 key for domain users JSON file
#--------------------------------------------------------------
# Domain Users Hash: ${domain_users_hash}
# This hash ensures user_data changes when domain_users list is modified

Start-Transcript -Path "C:\SDMDomainSetup.log" -Append

"[DCInstall] Starting DC installation from Packer AMI $(Get-Date)"
"[DCInstall] This AMI has ADDS and DNS features pre-installed"

# Decode and write RDP CA certificate from base64
$rdpcaContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("${rdpca_base64}"))
$rdpcaContent | Out-File "C:\rdp.cer" -Encoding ASCII

#--------------------------------------------------------------
# OPTIMIZATION: Skip computer rename entirely
#--------------------------------------------------------------
# The hostname is not critical - DNS will resolve the DC by its FQDN
# (hostname.domain.local) regardless of the actual computer name.
# This saves one full reboot cycle (~2 minutes)
$currentName = $env:COMPUTERNAME
"[DCInstall] Using current computer name: $currentName"
"[DCInstall] DC will be accessible via DNS at $currentName.${name}.local"

#--------------------------------------------------------------
# Phase 1: Promote to Domain Controller (triggers reboot)
#--------------------------------------------------------------

# OPTIMIZATION: Quick feature check - if using Packer AMI, skip detailed verification
# Only do full check if marker suggests this might not be Packer AMI
if (-not (Test-Path "C:\packer-features.done")) {
    "[DCInstall] Verifying ADDS and DNS features are installed..."
    $addsFeature = Get-WindowsFeature -Name AD-Domain-Services
    $dnsFeature = Get-WindowsFeature -Name DNS

    if (-not $addsFeature.Installed) {
        "[DCInstall] ERROR: ADDS feature not installed! This AMI may not be from Packer."
        "[DCInstall] Installing ADDS now as fallback..."
        Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
    }

    if (-not $dnsFeature.Installed) {
        "[DCInstall] ERROR: DNS feature not installed! This AMI may not be from Packer."
        "[DCInstall] Installing DNS now as fallback..."
        Install-WindowsFeature DNS -IncludeAllSubFeature -IncludeManagementTools
    }

    "[DCInstall] ADDS and DNS features confirmed installed"
} else {
    "[DCInstall] Packer AMI detected, skipping feature verification (already verified at build time)"
}

# Import required modules (should be available from Packer installation)
Import-Module ADDSDeployment -ErrorAction SilentlyContinue
Import-Module DnsServer -ErrorAction SilentlyContinue

# Create Step2.ps1 for post-DC-promotion tasks
$scriptPath = "C:\Step2.ps1"
$scriptContent = @'
#--------------------------------------------------------------
# Phase 3: Post-DC-Promotion Tasks (ADCS, Users, GPOs)
#--------------------------------------------------------------
Start-Transcript -Path "C:\SDMDomainSetup.log" -Append
$retryCount = 0
"[DCInstall] Starting Phase 3: ADCS and Post-Configuration $(Get-Date)"

#--------------------------------------------------------------
# Install and Configure ADCS (Enterprise Root CA)
#--------------------------------------------------------------
if (((-not (Test-Path "C:\adcs.done")) -and (Test-Path "C:\addssetup.done") -and (Test-Path "C:\restart.done"))) {

    "[DCInstall] ADCS not yet configured. Starting installation..."

    # OPTIMIZATION: Wait for NTDS (Active Directory) service with exponential backoff
    # Start with shorter intervals since DC should be ready quickly
    $waitSeconds = 10
    while (!(Get-Service -Name "NTDS" -ErrorAction SilentlyContinue) -and $retryCount -lt 12) {
        "[DCInstall] Waiting for NTDS service to be running... Attempt $retryCount/12 (waiting $waitSeconds seconds) $(Get-Date)"
        Start-Sleep -Seconds $waitSeconds
        $retryCount++
        # Exponential backoff: 10, 10, 15, 15, 20, 20, 30, 30, 30...
        if ($retryCount -ge 4 -and $waitSeconds -lt 30) { $waitSeconds = [Math]::Min($waitSeconds + 5, 30) }
    }

    # If NTDS still not running after retries, force a reboot
    if (($retryCount -ge 12) -and (-not (Test-Path "C:\restart2.done"))) {
        "[DCInstall] NTDS service still not running, forcing reboot... $(Get-Date)"
        "Preparing for Manual Restart $(Get-Date)" | Out-File "c:\restart2.done"
        Restart-Computer -Force
    }

    # OPTIMIZATION: Install ADCS Windows Feature (only after DC is operational)
    if (Get-Service -Name "NTDS" -ErrorAction SilentlyContinue) {
        "[DCInstall] NTDS service is running, installing ADCS feature... $(Get-Date)"

        # Check if ADCS feature is already installed, if not install it
        $adcsFeature = Get-WindowsFeature -Name ADCS-Cert-Authority
        if (-not $adcsFeature.Installed) {
            Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
            "[DCInstall] ADCS feature installed successfully"
        } else {
            "[DCInstall] ADCS feature already installed, proceeding to configuration"
        }

        # Wait for AD to be fully operational before configuring ADCS
        # The NTDS service being running doesn't guarantee AD schema is ready
        "[DCInstall] Waiting for Active Directory to be fully operational..."
        $adReadyRetries = 0
        $adReady = $false
        while (-not $adReady -and $adReadyRetries -lt 10) {
            try {
                # Try to query AD - if this succeeds, AD is operational
                Import-Module ActiveDirectory -ErrorAction Stop
                $null = Get-ADDomain -ErrorAction Stop
                $adReady = $true
                "[DCInstall] Active Directory is operational and ready"
            } catch {
                $adReadyRetries++
                "[DCInstall] AD not fully ready yet, waiting 30 seconds... (Attempt $adReadyRetries/10)"
                Start-Sleep -Seconds 30
            }
        }

        if (-not $adReady) {
            "[DCInstall] WARNING: Active Directory may not be fully operational after 5 minutes"
            "[DCInstall] Proceeding with ADCS configuration anyway..."
        }

        # Configure ADCS with retry logic
        Import-Module ADCSDeployment -ErrorAction Stop
        "[DCInstall] Configuring ADCS as Enterprise Root CA... $(Get-Date)"

        # Define CA details
        $caCommonName = "${name}-CA"
        $caKeyLength = 2048
        $caHashAlgorithm = "SHA256"

        # Retry ADCS configuration up to 3 times with increasing delays
        $adcsConfigured = $false
        $adcsRetries = 0
        $maxAdcsRetries = 3

        while (-not $adcsConfigured -and $adcsRetries -lt $maxAdcsRetries) {
            $adcsRetries++
            "[DCInstall] ADCS configuration attempt $adcsRetries of $maxAdcsRetries... $(Get-Date)"

            try {
                Install-ADCSCertificationAuthority -CAType EnterpriseRootCA `
                    -CACommonName $caCommonName `
                    -KeyLength $caKeyLength `
                    -HashAlgorithm $caHashAlgorithm `
                    -ValidityPeriod Years `
                    -ValidityPeriodUnits 10 `
                    -OverwriteExistingKey `
                    -OverwriteExistingDatabase `
                    -Force

                "[DCInstall] ADCS configured successfully as Enterprise Root CA"
                "ADCS Set up." | Out-File "C:\adcs.done"
                $adcsConfigured = $true
            } catch {
                "[DCInstall] ERROR: ADCS configuration attempt $adcsRetries failed: $_"

                if ($adcsRetries -lt $maxAdcsRetries) {
                    $waitTime = $adcsRetries * 60  # Wait 60, 120 seconds between retries
                    "[DCInstall] Waiting $waitTime seconds before retry..."
                    Start-Sleep -Seconds $waitTime
                } else {
                    "[DCInstall] FATAL: Failed to configure ADCS after $maxAdcsRetries attempts"
                    "[DCInstall] Manual intervention required - check AD domain controller status"
                }
            }
        }
    }
} else {
    if (Test-Path "C:\adcs.done") {
        "[DCInstall] ADCS already configured successfully (marker file exists)"
    }
}

#--------------------------------------------------------------
# Import StrongDM Certificates and Create Domain Users
#--------------------------------------------------------------
if (((-not (Test-Path "C:\sdm.done")) -and (Test-Path "C:\adcs.done"))) {
    $service = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue

    # Import StrongDM certificates to Active Directory
    if ($null -ne $service -and $service.Status -eq "Running") {
        "[DCInstall] Importing StrongDM Certificates to AD..."
        Import-Certificate -FilePath "c:\rdp.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
        certutil -dspublish -f C:\rdp.cer RootCA
        certutil -dspublish -f C:\rdp.cer NTAuthCA
        "[DCInstall] StrongDM certificates published to AD"
    } else {
        "[DCInstall] WARNING: ADCS is not running. Cannot import certificates"
    }

    # Ensure required modules are loaded
    Import-Module ActiveDirectory
    Import-Module GroupPolicy

    $service = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -eq "Running") {
        $domainadminpass = (ConvertTo-SecureString -String "${password}!" -AsPlainText -Force)

        #--------------------------------------------------------------
        # Create Domain Admin User
        #--------------------------------------------------------------
        "[DCInstall] Creating Domain Admin user..."
        $adminUserParams = @{
            SamAccountName = "domainadmin"
            Name           = "Domain Admin"
            GivenName      = "Domain"
            Surname        = "Admin"
            DisplayName    = "Domain Admin"
            UserPrincipalName = "domainadmin@${name}.local"
            AccountPassword = $domainadminpass
            Enabled        = $true
            PasswordNeverExpires = $true
        }

        try {
            New-ADUser @adminUserParams
            Add-ADGroupMember -Identity "Domain Admins" -Members "domainadmin"
            "[DCInstall] Domain admin user 'domainadmin' created and added to Domain Admins group"
        } catch {
            "[DCInstall] WARNING: Failed to create domain admin user (may already exist): $_"
        }

        #--------------------------------------------------------------
        # Download and Create Domain Users from S3
        #--------------------------------------------------------------
        %{ if has_domain_users }
        try {
            "[DCInstall] Downloading domain users from S3: ${s3_bucket}/${s3_key}"
            $usersJsonFile = "C:\domain-users.json"

            # Download the JSON file from S3 using AWS Tools for PowerShell
            try {
                Read-S3Object -BucketName "${s3_bucket}" -Key "${s3_key}" -File $usersJsonFile
                "[DCInstall] Successfully downloaded domain users file from S3"
            } catch {
                "[DCInstall] AWS Tools not available, using direct HTTPS download"
                # Fallback: Use direct HTTPS download via EC2 instance metadata
                $region = (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/region" -TimeoutSec 5)
                $s3Url = "https://${s3_bucket}.s3.$region.amazonaws.com/${s3_key}"
                Invoke-WebRequest -Uri $s3Url -OutFile $usersJsonFile -UseBasicParsing
                "[DCInstall] Downloaded domain users via direct HTTPS"
            }

            # Parse and create users
            if (Test-Path $usersJsonFile) {
                $domainUsers = Get-Content $usersJsonFile | ConvertFrom-Json
                "[DCInstall] Found $($domainUsers.Count) users to create"

                foreach ($user in $domainUsers) {
                    $currentUserParams = @{
                        SamAccountName = $user.SamAccountName
                        Name           = "$($user.GivenName) $($user.Surname)"
                        GivenName      = $user.GivenName
                        Surname        = $user.Surname
                        DisplayName    = "$($user.GivenName) $($user.Surname)"
                        UserPrincipalName = "$($user.SamAccountName)@${name}.local"
                        AccountPassword = $domainadminpass
                        Enabled        = $true
                        PasswordNeverExpires = $true
                    }

                    try {
                        New-ADUser @currentUserParams

                        # Add to Domain Admins group if domainadmin flag is true
                        if ($user.PSObject.Properties.Name -contains 'domainadmin' -and $user.domainadmin -eq $true) {
                            Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
                            "[DCInstall] User $($user.SamAccountName) created and added to Domain Admins"
                        } else {
                            "[DCInstall] User $($user.SamAccountName) created"
                        }
                    } catch {
                        "[DCInstall] WARNING: Failed to create user $($user.SamAccountName): $_"
                    }
                }

                # Clean up the JSON file
                Remove-Item $usersJsonFile -Force
                "[DCInstall] Domain users creation completed successfully"
            } else {
                "[DCInstall] ERROR: Could not find downloaded users file at $usersJsonFile"
            }
        } catch {
            "[DCInstall] ERROR: Failed to download or process domain users from S3: $_"
            "[DCInstall] Exception details: $($_.Exception.Message)"
        }
        %{ else }
        "[DCInstall] No domain users to create (domain_users variable not set)"
        %{ endif }

        #--------------------------------------------------------------
        # Configure Group Policy for StrongDM RDP Authentication
        #--------------------------------------------------------------
        "[DCInstall] Configuring Group Policy for StrongDM..."

        # Define GPO name and domain settings
        $GPOName = "Disable NLA and Enable Smart Card Authentication"
        $Domain = "DC=${name},DC=local"

        # Create a new GPO if it doesn't exist
        $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if ($null -eq $GPO) {
            $GPO = New-GPO -Name $GPOName -Comment "GPO to disable NLA and enable smart card authentication for all RDP connections"
            "[DCInstall] New GPO '$GPOName' created"
        } else {
            "[DCInstall] GPO '$GPOName' already exists"
        }

        # Disable NLA (Network Level Authentication)
        $RegistryKeyPathNLA = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        $RegistryValueNameNLA = "UserAuthentication"
        $GPO | Set-GPRegistryValue -Key $RegistryKeyPathNLA -ValueName $RegistryValueNameNLA -Type DWord -Value 0
        "[DCInstall] NLA disabled in GPO"

        # Enable Smart Card service (SCardSvr) to start automatically
        $RegistryKeyPathSmartCardService = "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr"
        $RegistryValueNameSmartCardService = "Start"
        try {
            $GPO | Set-GPRegistryValue -Key $RegistryKeyPathSmartCardService -ValueName $RegistryValueNameSmartCardService -Type DWord -Value 2
            "[DCInstall] Smart Card Service enabled to start automatically in GPO"
        } catch {
            "[DCInstall] ERROR: Failed to set Smart Card Service registry value: $_"
        }

        # Set certificate enforcement per KB5014754
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -PropertyType DWORD -Value 1 -Force
            "[DCInstall] Strong Certificate Binding Enforcement configured"
        } catch {
            "[DCInstall] ERROR: Couldn't set certificate enforcement. Certificate logins may fail: $_"
        }

        # Link the GPO to the domain
        try {
            New-GPLink -Name $GPOName -Target "$Domain" -LinkEnabled Yes -Enforced Yes
            "[DCInstall] GPO linked to the domain"
        } catch {
            "[DCInstall] WARNING: Failed to link GPO (may already be linked): $_"
        }

        # Force GPO update
        Invoke-GPUpdate -Force
        "[DCInstall] Group Policy update triggered"

        #--------------------------------------------------------------
        # Store CA Certificate and Computer Name in Parameter Store
        #--------------------------------------------------------------
        "[DCInstall] Storing CA certificate and computer name in Parameter Store..."

        # Import AWS Tools for PowerShell (SSM module)
        try {
            Import-Module AWS.Tools.SimpleSystemsManagement -ErrorAction Stop
            "[DCInstall] AWS SSM PowerShell module loaded successfully"
        } catch {
            "[DCInstall] WARNING: Failed to load AWS.Tools.SimpleSystemsManagement module: $_"
            "[DCInstall] Parameter Store operations may fail"
        }

        try {
            # Get the current computer name
            $computerName = $env:COMPUTERNAME
            $domainFqdn = "${name}.local"
            $computerFqdn = "$computerName.$domainFqdn"

            "[DCInstall] Computer FQDN: $computerFqdn"

            # Export the CA certificate in Base64 format
            $caCertPath = "C:\ca-certificate.cer"
            $caName = "${name}-CA"

            # Get the CA certificate from the Certificate Authority
            # Method: Export from local certificate store where ADCS publishes it
            "[DCInstall] Exporting CA certificate from certificate store..."

            try {
                # Get the CA certificate from the local machine's Root store
                # ADCS publishes its own cert to the Trusted Root Certification Authorities
                $caCert = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object { $_.Subject -match "CN=$caName" } | Select-Object -First 1

                if ($caCert) {
                    # Export the certificate to a file
                    $certBytes = $caCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($caCertPath, $certBytes)
                    "[DCInstall] CA certificate exported successfully from certificate store"
                } else {
                    "[DCInstall] WARNING: Could not find CA certificate in Root store, trying alternate method..."
                    # Fallback: Use certutil to get the CA cert directly from CA config
                    $null = certutil -config - -ca.cert "$caCertPath" 2>&1
                }
            } catch {
                "[DCInstall] WARNING: Failed to export CA certificate: $_"
            }

            if (Test-Path $caCertPath) {
                # Read the certificate and convert to PEM format
                $caCertBytes = [System.IO.File]::ReadAllBytes($caCertPath)
                $caCertBase64 = [System.Convert]::ToBase64String($caCertBytes)

                # Convert to PEM format with proper headers for Linux compatibility
                # Split Base64 into 64-character lines as per PEM standard
                $pemLines = @()
                for ($i = 0; $i -lt $caCertBase64.Length; $i += 64) {
                    $lineLength = [Math]::Min(64, $caCertBase64.Length - $i)
                    $pemLines += $caCertBase64.Substring($i, $lineLength)
                }
                $caCertPem = "-----BEGIN CERTIFICATE-----`n" + ($pemLines -join "`n") + "`n-----END CERTIFICATE-----"

                "[DCInstall] CA certificate exported successfully (PEM format)"

                # Store in Parameter Store
                # Note: Requires IAM permissions for SSM:PutParameter

                # Store CA Certificate in PEM format
                $paramNameCert = "/${name}/dc/ca-certificate"
                try {
                    Write-SSMParameter -Name $paramNameCert -Value $caCertPem -Type "String" -Overwrite $true
                    "[DCInstall] CA certificate stored in Parameter Store (PEM format): $paramNameCert"
                } catch {
                    "[DCInstall] WARNING: Failed to store CA certificate in Parameter Store: $_"
                    "[DCInstall] This may be due to missing IAM permissions (ssm:PutParameter)"
                }

                # Store Computer FQDN
                $paramNameFqdn = "/${name}/dc/fqdn"
                try {
                    Write-SSMParameter -Name $paramNameFqdn -Value $computerFqdn -Type "String" -Overwrite $true
                    "[DCInstall] Computer FQDN stored in Parameter Store: $paramNameFqdn"
                } catch {
                    "[DCInstall] WARNING: Failed to store FQDN in Parameter Store: $_"
                    "[DCInstall] This may be due to missing IAM permissions (ssm:PutParameter)"
                }

                # Store Computer Name (short name)
                $paramNameComputer = "/${name}/dc/computer-name"
                try {
                    Write-SSMParameter -Name $paramNameComputer -Value $computerName -Type "String" -Overwrite $true
                    "[DCInstall] Computer name stored in Parameter Store: $paramNameComputer"
                } catch {
                    "[DCInstall] WARNING: Failed to store computer name in Parameter Store: $_"
                    "[DCInstall] This may be due to missing IAM permissions (ssm:PutParameter)"
                }

                # Store Domain Administrator SID
                $paramNameAdminSid = "/${name}/dc/domain-admin-sid"
                try {
                    $domainAdminUser = Get-ADUser -Identity "domainadmin" -ErrorAction Stop
                    $domainAdminSid = $domainAdminUser.SID.Value
                    "[DCInstall] Domain Administrator SID: $domainAdminSid"

                    Write-SSMParameter -Name $paramNameAdminSid -Value $domainAdminSid -Type "String" -Overwrite $true
                    "[DCInstall] Domain Administrator SID stored in Parameter Store: $paramNameAdminSid"
                } catch {
                    "[DCInstall] WARNING: Failed to retrieve or store Domain Administrator SID: $_"
                    "[DCInstall] This may be due to user not existing or missing IAM permissions"
                }

                # Clean up certificate file
                Remove-Item $caCertPath -Force -ErrorAction SilentlyContinue

            } else {
                "[DCInstall] WARNING: CA certificate file not found at $caCertPath"
                "[DCInstall] ADCS may not be properly configured"
            }

        } catch {
            "[DCInstall] ERROR: Failed to export/store CA certificate: $_"
            "[DCInstall] Exception details: $($_.Exception.Message)"
            # Don't fail the entire setup if Parameter Store fails - it's not critical
        }

        "Certificates and GPOs updated" | Out-File "C:\sdm.done"
        "[DCInstall] Domain Controller setup completed successfully! $(Get-Date)"
    } else {
        "[DCInstall] ERROR: NTDS service is not running. Cannot complete configuration."
    }
}

Stop-Transcript
'@
$scriptContent | Out-File -FilePath $scriptPath -Force

#--------------------------------------------------------------
# Promote to Domain Controller (triggers reboot)
#--------------------------------------------------------------
if (-not (Test-Path "C:\addssetup.done")) {
    "[DCInstall] Promoting server to Domain Controller..."
    "[DCInstall] Domain: ${name}.local, NetBIOS: ${name}"

    try {
        Install-ADDSForest -DomainName "${name}.local" -DomainNetbiosName "${name}" `
           -DomainMode WinThreshold -ForestMode WinThreshold `
           -DatabasePath C:/Windows/NTDS -SysvolPath C:/Windows/SYSVOL `
           -LogPath C:/Windows/NTDS -NoRebootOnCompletion:$false -Force:$true `
           -SafeModeAdministratorPassword (ConvertTo-SecureString "${password}" -AsPlainText -Force)

        "AD Set up." | Out-File "C:\addssetup.done"
    } catch {
        "[DCInstall] ERROR: Failed to promote to Domain Controller: $_"
        Stop-Transcript
        exit 1
    }

    "Preparing for Manual Restart $(Get-Date)" | Out-File "c:\restart.done"

    # OPTIMIZATION: Schedule Step2.ps1 to run 2 minutes after reboot (reduced from 5)
    # DC services are usually ready within 1-2 minutes, no need to wait 5
    "[DCInstall] Scheduling Phase 3 script to run after reboot..."
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # OPTIMIZATION: Use -Force to overwrite if task already exists
    Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger `
        -TaskName "RunScheduledScript" -Description "Phase 3: ADCS and Post-Configuration" -Force

    "[DCInstall] Phase 3 script scheduled. Rebooting to complete DC promotion..."
    Stop-Transcript
    Restart-Computer -Force
}

Stop-Transcript

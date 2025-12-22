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

                # Configure CA policy to automatically issue certificates (including subordinate CA requests)
                "[DCInstall] Configuring CA policy for automatic certificate issuance..."
                try {
                    certutil -setreg policy\RequestDisposition 1
                    "[DCInstall] CA policy set to auto-issue certificates (RequestDisposition=1)"

                    # Restart Certificate Services to apply the policy change
                    Restart-Service certsvc -Force
                    "[DCInstall] Certificate Services restarted with new policy"
                } catch {
                    "[DCInstall] WARNING: Failed to configure auto-issuance policy: $_"
                    "[DCInstall] Subordinate CA requests may require manual approval"
                }

                # Enable PowerShell Remoting (WinRM) for remote management
                "[DCInstall] Enabling PowerShell Remoting (WinRM)..."
                try {
                    Enable-PSRemoting -Force -SkipNetworkProfileCheck
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
                    "[DCInstall] PowerShell Remoting enabled successfully"
                } catch {
                    "[DCInstall] WARNING: Failed to enable PowerShell Remoting: $_"
                }

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
        $GPOName = "Enable Smart Card Authentication"
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
        # Configure DNS Reverse Lookup Zone
        #--------------------------------------------------------------
        "[DCInstall] Configuring DNS reverse lookup zone..."

        try {
            Import-Module DnsServer -ErrorAction Stop

            # Get the DC's IP address
            $computerName = $env:COMPUTERNAME
            $dcIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "10.*" }).IPAddress

            if ($dcIP) {
                "[DCInstall] DC IP Address: $dcIP"

                # Create reverse lookup zone for 10.0.0.0/8 network
                $networkId = "10.0.0.0/8"
                $zoneName = "10.in-addr.arpa"

                # Check if reverse zone exists
                $existingZone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue

                if (-not $existingZone) {
                    "[DCInstall] Creating reverse lookup zone: $zoneName"
                    Add-DnsServerPrimaryZone -NetworkID $networkId -ReplicationScope "Forest" -DynamicUpdate "Secure"
                    "[DCInstall] Reverse lookup zone created successfully"
                } else {
                    "[DCInstall] Reverse lookup zone already exists: $zoneName"
                }

                # Add PTR record for the DC itself
                $domainFqdn = "${name}.local"
                $dcFqdn = "$computerName.$domainFqdn"

                # For a /8 network, we need to use octets 2.3.4 as the PTR record name
                # For example, 10.0.0.17 becomes "17.0.0" in the 10.in-addr.arpa zone
                $ipParts = $dcIP.Split('.')
                $ptrRecordName = "$($ipParts[3]).$($ipParts[2]).$($ipParts[1])"

                "[DCInstall] Adding PTR record: $ptrRecordName -> $dcFqdn"

                # Remove existing PTR record if it exists
                $existingPTR = Get-DnsServerResourceRecord -ZoneName $zoneName -RRType Ptr -Name $ptrRecordName -ErrorAction SilentlyContinue
                if ($existingPTR) {
                    Remove-DnsServerResourceRecord -ZoneName $zoneName -RRType Ptr -Name $ptrRecordName -Force -ErrorAction SilentlyContinue
                    "[DCInstall] Removed existing PTR record"
                }

                # Add PTR record
                Add-DnsServerResourceRecordPtr -ZoneName $zoneName -Name $ptrRecordName -PtrDomainName $dcFqdn
                "[DCInstall] PTR record added successfully: $dcIP -> $dcFqdn"

                # Verify the PTR record
                $ptrRecord = Resolve-DnsName -Name $dcIP -Type PTR -ErrorAction SilentlyContinue
                if ($ptrRecord) {
                    "[DCInstall] PTR record verified: $($ptrRecord.NameHost)"
                } else {
                    "[DCInstall] WARNING: Could not verify PTR record"
                }

            } else {
                "[DCInstall] WARNING: Could not determine DC IP address in 10.0.0.0/8 range"
            }

        } catch {
            "[DCInstall] ERROR: Failed to configure DNS reverse zone: $_"
            "[DCInstall] Exception details: $($_.Exception.Message)"
        }

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

        #--------------------------------------------------------------
        # Create StrongDM Certificate Template
        #--------------------------------------------------------------
        "[DCInstall] Creating StrongDM certificate template..."

        try {
            # Import AD module
            Import-Module ActiveDirectory -ErrorAction Stop

            # Get configuration naming context
            $configNC = (Get-ADRootDSE).configurationNamingContext
            $templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

            "[DCInstall] Certificate template container: $templateContainer"

            # Get Smart Card Logon template as source
            $sourceTemplate = Get-ADObject -SearchBase $templateContainer `
                -Filter {cn -eq "SmartcardLogon"} `
                -Properties * `
                -ErrorAction Stop

            if ($sourceTemplate) {
                "[DCInstall] Source template 'SmartcardLogon' found"

                # Define the new template name
                $newTemplateName = "StrongDM"
                $newTemplateDN = "CN=$newTemplateName,$templateContainer"

                # Check if template already exists
                $existingTemplate = Get-ADObject -SearchBase $templateContainer `
                    -Filter {cn -eq $newTemplateName} `
                    -ErrorAction SilentlyContinue

                if (-not $existingTemplate) {
                    # Generate a unique OID for this template
                    # Use the source template's OID as base and generate a new one
                    $sourceOID = $sourceTemplate.'msPKI-Cert-Template-OID'
                    if ($sourceOID) {
                        # Generate new OID by incrementing the last component
                        $oidParts = $sourceOID -split '\.'
                        $lastPart = [int]$oidParts[-1] + (Get-Random -Minimum 100 -Maximum 999)
                        $oidParts[-1] = $lastPart.ToString()
                        $newOID = $oidParts -join '.'
                        "[DCInstall] Generated OID for template: $newOID"
                    } else {
                        # Fallback: create from scratch using Microsoft's private enterprise number
                        $newOID = "1.3.6.1.4.1.311.21.8.$(Get-Random -Minimum 10000000 -Maximum 99999999).$(Get-Random -Minimum 1000000 -Maximum 9999999).$(Get-Random -Minimum 1000000 -Maximum 9999999).$(Get-Random -Minimum 1000000 -Maximum 9999999).$(Get-Random -Minimum 1000000 -Maximum 9999999).$(Get-Random -Minimum 1 -Maximum 99).1.$(Get-Random -Minimum 1 -Maximum 999)"
                        "[DCInstall] Generated new OID from scratch: $newOID"
                    }

                    # Copy template properties
                    $templateAttributes = @{
                        objectClass = "pKICertificateTemplate"
                        cn = $newTemplateName
                        name = $newTemplateName
                        displayName = $newTemplateName
                        flags = 66256
                        "pKIDefaultKeySpec" = 1
                        "pKIKeyUsage" = [byte[]](0xa0, 0x00)
                        "pKIMaxIssuingDepth" = 0
                        "pKICriticalExtensions" = "2.5.29.15"
                        "pKIExpirationPeriod" = [byte[]](0x00, 0x40, 0x39, 0x87, 0x2e, 0xe1, 0xfe, 0xff)
                        "pKIOverlapPeriod" = [byte[]](0x00, 0x3A, 0xA4, 0x6B, 0xF7, 0xFF, 0xFF, 0xFF)
                        "pKIExtendedKeyUsage" = @("1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2")
                        "msPKI-Cert-Template-OID" = $newOID
                        "msPKI-Certificate-Application-Policy" = @("1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.5.7.3.2")
                        "msPKI-Certificate-Name-Flag" = 1
                        "msPKI-Enrollment-Flag" = 41
                        "msPKI-Minimal-Key-Size" = 2048
                        "msPKI-Private-Key-Flag" = 16842768
                        "msPKI-RA-Signature" = 0
                        "msPKI-Template-Minor-Revision" = 1
                        "msPKI-Template-Schema-Version" = 2
                        "revision" = 100
                    }

                    New-ADObject -Name $newTemplateName `
                        -Type pKICertificateTemplate `
                        -Path $templateContainer `
                        -OtherAttributes $templateAttributes `
                        -ErrorAction Stop

                    "[DCInstall] Certificate template '$newTemplateName' created successfully"
                    "[DCInstall] Template validity: 1 day, renewal: 1 hour"

                    # Grant permissions on the template
                    Start-Sleep -Seconds 2
                    $templateDN = "CN=$newTemplateName,$templateContainer"

                    $template = Get-ADObject -Identity $templateDN -Properties nTSecurityDescriptor -ErrorAction Stop
                    $acl = $template.nTSecurityDescriptor

                    $domainComputersGroup = Get-ADGroup -Identity "Domain Computers" -ErrorAction Stop
                    $domainComputersSID = New-Object System.Security.Principal.SecurityIdentifier($domainComputersGroup.SID)

                    $enrollGuid = New-Object Guid "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                    $autoEnrollGuid = New-Object Guid "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

                    $readRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $domainComputersSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    )

                    $enrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $domainComputersSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $enrollGuid,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    )

                    $autoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $domainComputersSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $autoEnrollGuid,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    )

                    $acl.AddAccessRule($readRule)
                    $acl.AddAccessRule($enrollRule)
                    $acl.AddAccessRule($autoEnrollRule)

                    $authUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

                    $authReadRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $authUsersSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    )

                    $authEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $authUsersSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $enrollGuid,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    )

                    $acl.AddAccessRule($authReadRule)
                    $acl.AddAccessRule($authEnrollRule)

                    Set-ADObject -Identity $templateDN -Replace @{nTSecurityDescriptor=$acl} -ErrorAction Stop

                    "[DCInstall] Certificate template permissions configured"
                    "[DCInstall] Added Read, Enroll, and AutoEnroll for Domain Computers"
                    "[DCInstall] Added Read and Enroll for Authenticated Users"

                    # Publish template to CA
                    "[DCInstall] Publishing template to Certificate Authority..."

                    $caName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Name "Active").Active

                    if ($caName) {
                        "[DCInstall] CA Name: $caName"

                        $result = certutil -SetCATemplates +$newTemplateName 2>&1
                        "[DCInstall] certutil output: $result"

                        if ($LASTEXITCODE -eq 0) {
                            "[DCInstall] Template '$newTemplateName' published to CA successfully"

                            "[DCInstall] Restarting Certificate Services..."
                            Restart-Service -Name CertSvc -Force
                            Start-Sleep -Seconds 5
                            "[DCInstall] Certificate Services restarted"
                        } else {
                            "[DCInstall] WARNING: Failed to publish template to CA (exit code: $LASTEXITCODE)"
                        }
                    } else {
                        "[DCInstall] WARNING: Could not determine CA name"
                    }

                } else {
                    "[DCInstall] Certificate template '$newTemplateName' already exists"
                }
            } else {
                "[DCInstall] WARNING: SmartcardLogon template not found"
            }
        } catch {
            "[DCInstall] ERROR creating certificate template: $_"
        }

        #--------------------------------------------------------------
        # Create Web Server Certificate for ADCS Server
        #--------------------------------------------------------------
        "[DCInstall] Creating Web Server certificate for ADCS server..."

        try {
            # Create certificate request INF for ADCS server
            $adcsServerFqdn = "${name}-adcs.${name}.local"
            $certReqInf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$adcsServerFqdn"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1

[RequestAttributes]
CertificateTemplate=WebServer
"@

            $infFile = "C:\ADCSWebServerCert.inf"
            $reqFile = "C:\ADCSWebServerCert.req"
            $cerFile = "C:\ADCSWebServerCert.cer"
            $pfxFile = "C:\ADCSWebServerCert.pfx"
            $pfxPassword = "${password}"

            Set-Content -Path $infFile -Value $certReqInf
            "[DCInstall] Created certificate request INF for ADCS server"

            # Generate certificate request
            # Note: Use -user flag to explicitly create in user context (avoids the conflict prompt)
            "[DCInstall] Running: certreq -new -user $infFile $reqFile"
            $newOutput = certreq -new -user $infFile $reqFile 2>&1
            "[DCInstall] certreq -new result: $newOutput"
            if (-not (Test-Path $reqFile)) {
                throw "Failed to create certificate request file"
            }
            "[DCInstall] Generated certificate request for ADCS server"

            # Submit to local CA with explicit CA configuration
            # Note: Must use full "Server\CAName" format, not "." when using user context certificates
            $caConfigLines = certutil 2>&1 | Select-String -Pattern "Config:"
            if ($caConfigLines) {
                # Get the first Config line (the local CA on this DC)
                $caConfigLine = $caConfigLines | Select-Object -First 1
                $caConfig = $caConfigLine.ToString() -replace '.*"([^"]+)".*', '$1'
                "[DCInstall] Detected CA config: $caConfig"
            } else {
                # Fallback: construct from registry
                $caName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction SilentlyContinue).PSChildName | Select-Object -First 1
                if ($caName) {
                    $computerFqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
                    $caConfig = "$computerFqdn\$caName"
                    "[DCInstall] Constructed CA config from registry: $caConfig"
                } else {
                    throw "Could not determine CA configuration"
                }
            }

            "[DCInstall] Running: certreq -submit -config `"$caConfig`" $reqFile $cerFile"
            $submitOutput = certreq -submit -config "$caConfig" $reqFile $cerFile 2>&1
            "[DCInstall] certreq -submit result: $submitOutput"
            if (-not (Test-Path $cerFile)) {
                throw "Failed to submit certificate request - certificate file not created"
            }
            "[DCInstall] Submitted certificate request to CA"

            # Accept and install certificate
            "[DCInstall] Running: certreq -accept $cerFile"
            $acceptOutput = certreq -accept $cerFile 2>&1
            "[DCInstall] certreq -accept result: $acceptOutput"
            "[DCInstall] Certificate issued for ADCS server"

            # Export certificate with private key to PFX
            # First, find the certificate we just installed
            $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=$adcsServerFqdn"} | Select-Object -First 1

            if ($cert) {
                "[DCInstall] Found certificate, thumbprint: $($cert.Thumbprint)"

                # Export to PFX
                $pfxSecurePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
                Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $pfxSecurePassword -Force
                "[DCInstall] Exported certificate to PFX: $pfxFile"

                # Store PFX in Parameter Store for ADCS server to retrieve
                try {
                    "[DCInstall] Importing AWS.Tools.SimpleSystemsManagement module..."
                    Import-Module AWS.Tools.SimpleSystemsManagement -ErrorAction Stop
                    "[DCInstall] AWS module imported successfully"

                    # Read PFX file as base64
                    "[DCInstall] Reading PFX file: $pfxFile"
                    $pfxBytes = [System.IO.File]::ReadAllBytes($pfxFile)
                    $pfxBase64 = [System.Convert]::ToBase64String($pfxBytes)
                    "[DCInstall] PFX file encoded to base64 ($($pfxBytes.Length) bytes)"

                    # Store in Parameter Store
                    $paramNamePfx = "/${name}/adcs/webserver-cert-pfx"
                    $paramNamePassword = "/${name}/adcs/webserver-cert-password"

                    "[DCInstall] Storing PFX in Parameter Store: $paramNamePfx"
                    Write-SSMParameter -Name $paramNamePfx -Value $pfxBase64 -Type "String" -Overwrite $true
                    "[DCInstall] PFX stored successfully"

                    "[DCInstall] Storing password in Parameter Store: $paramNamePassword"
                    Write-SSMParameter -Name $paramNamePassword -Value $pfxPassword -Type "SecureString" -Overwrite $true
                    "[DCInstall] Password stored successfully"

                    "[DCInstall] Web Server certificate stored in Parameter Store"
                } catch {
                    "[DCInstall] WARNING: Failed to store certificate in Parameter Store: $_"
                    "[DCInstall] Exception details: $($_.Exception.Message)"
                }

                # Clean up certificate from current user store (not needed on DC)
                Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue

                # Clean up temporary files
                Remove-Item $infFile, $reqFile, $cerFile, $pfxFile -Force -ErrorAction SilentlyContinue
                "[DCInstall] Cleaned up temporary certificate files"
            } else {
                "[DCInstall] WARNING: Could not find issued certificate for $adcsServerFqdn"
            }

            "[DCInstall] Web Server certificate creation completed"

        } catch {
            "[DCInstall] WARNING: Failed to create Web Server certificate for ADCS: $_"
            "[DCInstall] Exception details: $($_.Exception.Message)"
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

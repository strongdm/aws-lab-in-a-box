#--------------------------------------------------------------
# Domain Controller Installation PowerShell Template
#--------------------------------------------------------------
# This PowerShell template script installs and configures a Windows
# Active Directory Domain Controller in the StrongDM AWS Lab-in-a-Box.
#
# Key Functions:
# - Installs Active Directory Domain Services (ADDS) role
# - Installs DNS server role and configures DNS settings
# - Creates new Active Directory forest and domain
# - Configures domain controller networking and security
# - Sets up RDP certificate authentication
# - Creates domain users and organizational structure
# - Configures StrongDM integration with Active Directory
#
# Template Variables:
# - ${rdpca_base64}: RDP certificate authority certificate (base64 encoded)
# - ${name}: Domain name prefix for forest creation
# - ${domain_users_hash}: Hash of domain users (triggers recreation on change)
# - ${s3_bucket}: S3 bucket containing domain users JSON
# - ${s3_key}: S3 key for domain users JSON file
#--------------------------------------------------------------
# Domain Users Hash: ${domain_users_hash}
# This hash ensures user_data changes when domain_users list is modified

Start-Transcript -Path "C:\SDMDomainSetup.log" -Append

# Decode and write RDP CA certificate from base64
$rdpcaContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("${rdpca_base64}"))
$rdpcaContent | Out-File "C:\rdp.cer" -Encoding ASCII
if (-not (Test-Path "C:\rename.done")) {
    "[DCInstall] Setting computer name"
    Rename-Computer -NewName dc1 -Restart
    "Computer name changed." | Out-File "C:\rename.done"

}

"[DCInstall] Loading Server Manager Module"
Import-Module ServerManager

if (((-not (Test-Path "C:\addsinstall.done")) -and (Test-Path "C:\rename.done"))) {
    "[DCInstall] Starting Installation of ADDS"
    Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
    "[DCInstall] Starting Installation of DNS"
    Install-WindowsFeature DNS -IncludeAllSubFeature -IncludeManagementTools    
    "ADDS / DNS Installed." | Out-File "C:\addsinstall.done"
}



Import-Module ADDSDeployment
Import-Module DnsServer
$scriptPath = "C:\Step2.ps1"
$scriptContent = @'
Start-Transcript -Path "C:\SDMDomainSetup.log" -Append
$retryCount = 0
"Starting ADCS Loop $(Get-Date)"
if (((-not (Test-Path "C:\adcs.done")) -and (Test-Path "C:\addssetup.done") -and (Test-Path "C:\restart.done"))) {

            if (-not (Get-Service -Name "CertSvc")) {
                "Certificate Services doesn't exist. Installing it"
                while (!((Get-Service -Name "NTDS")) -and $retryCount -lt 10) {
                    "Waiting for NTDS to be running $(Get-Date)"
                    Write-Host "File not found. Retrying... ($retryCount/10)"
                    Start-Sleep -Seconds 30  # Wait for 30 seconds before retrying
                    $retryCount++
                }
                if (($retryCount -ge 10) -and (-not (Test-Path "C:\restart2.done"))) {
                    "Preparing for Manual Restart $(Get-Date)" | Out-File "c:\restart2.done"
                    Restart-Computer -Force   
                }
                if (Get-Service -Name "NTDS") {
                    "[DCInstall] Starting Installation of CA $(Get-Date)"
                    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
                }

            
            Start-Sleep -Seconds 30
            $service = Get-Service -Name "CertSvc"
            if ($service.Status -ne "Running") {
                Import-Module ADCSDeployment
                "[DCInstall] Starting Installation of ADCS $(Get-Date)"
                # Define CA details
                $caCommonName = "${name}-CA"  # The Common Name for the CA (e.g., "MyEnterpriseCA")
                $caKeyLength = 2048               # Key length for the CA certificate (2048 bits)
                $caHashAlgorithm = "SHA256"       # Hash algorithm (SHA256 recommended)

                # Install and configure the Enterprise CA
                # Note: Root CAs require a minimum validity period of 5 years to meet AD range constraints
                    Install-ADCSCertificationAuthority -CAType EnterpriseRootCA `
                    -CACommonName $caCommonName `
                    -KeyLength $caKeyLength `
                    -HashAlgorithm $caHashAlgorithm `
                    -ValidityPeriod Years `
                    -ValidityPeriodUnits 10 `
                    -Force

                # Configure CA policy to automatically issue certificates (including subordinate CA requests)
                "Configuring CA policy for automatic certificate issuance..."
                try {
                    certutil -setreg policy\RequestDisposition 1
                    "CA policy set to auto-issue certificates (RequestDisposition=1)"

                    # Restart Certificate Services to apply the policy change
                    Restart-Service certsvc -Force
                    "Certificate Services restarted with new policy"
                } catch {
                    "WARNING: Failed to configure auto-issuance policy: $_"
                    "Subordinate CA requests may require manual approval"
                }

                # Enable PowerShell Remoting (WinRM) for remote management
                "Enabling PowerShell Remoting (WinRM)..."
                try {
                    Enable-PSRemoting -Force -SkipNetworkProfileCheck
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
                    "PowerShell Remoting enabled successfully"
                } catch {
                    "WARNING: Failed to enable PowerShell Remoting: $_"
                }

            "ADCS Set up." | Out-File "C:\adcs.done"
            }
            } else { "ADCS is already installed" }
        
          
}

if (((-not (Test-Path "C:\sdm.done")) -and (Test-Path "C:\adcs.done"))) {
    $service = Get-Service -Name "CertSvc"
    if ($service.Status -eq "Running") {
        "Importing StrongDM Certificates"
        Import-Certificate -FilePath "c:\rdp.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
        certutil -dspublish -f C:\rdp.cer RootCA 
        certutil -dspublish -f C:\rdp.cer NTAuthCA
    } else { "ADCS Is not installed yet. Cannot Import certificates" } 
     # Ensure the required modules are loaded
    Import-Module GroupPolicy
    $service = Get-Service -Name "NTDS"
    if ($service.Status -eq "Running") {
        $domainadminpass = (ConvertTo-SecureString -String "${password}!" -AsPlainText -Force)
        "Creating Domain Admin"
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

        New-ADUser @adminUserParams

        # Add the user to the Domain Admins group
        Add-ADGroupMember -Identity "Domain Admins" -Members "domainadmin"

        Write-Host "Active Directory domain $domain has been created, and the domain admin user $adminUsername has been created and added to the Domain Admins group."

        # Download and create domain users from S3
        %{ if has_domain_users }
        try {
            "Downloading domain users from S3: ${s3_bucket}/${s3_key}"
            $usersJsonFile = "C:\domain-users.json"

            # Download the JSON file from S3 using AWS Tools for PowerShell
            # First, try using Read-S3Object if AWS Tools are available
            try {
                Read-S3Object -BucketName "${s3_bucket}" -Key "${s3_key}" -File $usersJsonFile
                "Successfully downloaded domain users file from S3"
            } catch {
                "AWS Tools not available, using direct HTTPS download"
                # Fallback: Use direct HTTPS download via EC2 instance metadata for credentials
                $region = (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/placement/region" -TimeoutSec 5)
                $s3Url = "https://${s3_bucket}.s3.$region.amazonaws.com/${s3_key}"
                Invoke-WebRequest -Uri $s3Url -OutFile $usersJsonFile -UseBasicParsing
                "Downloaded domain users via direct HTTPS"
            }

            # Parse and create users
            if (Test-Path $usersJsonFile) {
                $domainUsers = Get-Content $usersJsonFile | ConvertFrom-Json
                "Found $($domainUsers.Count) users to create"

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

                    New-ADUser @currentUserParams

                    # Add to Domain Admins group if domainadmin flag is true
                    if ($user.PSObject.Properties.Name -contains 'domainadmin' -and $user.domainadmin -eq $true) {
                        Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
                        "Active Directory User $($user.SamAccountName) has been created and added to Domain Admins"
                    } else {
                        "Active Directory User $($user.SamAccountName) has been created"
                    }
                }

                # Clean up the JSON file
                Remove-Item $usersJsonFile -Force
                "Domain users creation completed successfully"
            } else {
                "ERROR: Could not find downloaded users file at $usersJsonFile"
            }
        } catch {
            "ERROR: Failed to download or process domain users from S3: $_"
            "Exception details: $($_.Exception.Message)"
        }
        %{ else }
        "No domain users to create (domain_users variable not set)"
        %{ endif }

        # Define GPO name and domain settings
        $GPOName = "Disable NLA and Enable Smart Card Authentication"
        $Domain = "DC=${name},DC=local"

        # Create a new GPO if it doesn't exist
        $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if ($null -eq $GPO) {
            $GPO = New-GPO -Name $GPOName -Comment "GPO to disable NLA and enable smart card authentication for all RDP connections"
            Write-Host "New GPO '$GPOName' created."
        } else {
            Write-Host "GPO '$GPOName' already exists."
        }

        # Set the Group Policy setting to disable NLA (Network Level Authentication)
        $RegistryKeyPathNLA = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        $RegistryValueNameNLA = "UserAuthentication"

        # Disable NLA by setting the registry key to 0
        $GPO | Set-GPRegistryValue -Key $RegistryKeyPathNLA -ValueName $RegistryValueNameNLA -Type DWord -Value 0
        Write-Host "NLA setting has been configured in the GPO."

        # Set the Group Policy setting to enable Smart Card service (SCardSvr) to start automatically
        $RegistryKeyPathSmartCardService = "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr"
        $RegistryValueNameSmartCardService = "Start"

        # Set the registry value to '2' (Automatic startup) for Smart Card Service
        try {
            $GPO | Set-GPRegistryValue -Key $RegistryKeyPathSmartCardService -ValueName $RegistryValueNameSmartCardService -Type DWord -Value 2
            Write-Host "Smart Card Service (SCardSvr) has been enabled to start automatically in the GPO."
        } catch {
            Write-Host "Error: Failed to set Smart Card Service registry value. Please ensure the key path is correct."
            exit
        }
        # Set the right Certificate Enforcement per KBKB5014754
        try {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -PropertyType DWORD -Value 1 -Force 
            Write-Host "Strong Certificate Enforcement Disabled."
        } catch {
            Write-Host "Error: Couldn't set appropiate certificate enforcement. Certificate logins will fail!."
            exit
        }


        # Link the GPO to the domain (or specific OU)
        New-GPLink -Name $GPOName -Target "$Domain" -LinkEnabled Yes -Enforced Yes
        Write-Host "GPO linked to the domain."

        # Force the GPO update on all machines in the domain (optional, can be run later)
        Invoke-GPUpdate -Force
        Write-Host "Group Policy update has been triggered."
        "Certificates and GPOs updated" | Out-File "C:\sdm.done"
    }
}
'@
$scriptContent | Out-File -FilePath $scriptPath -Force

if (((-not (Test-Path "C:\addssetup.done")) -and (Test-Path "C:\addsinstall.done"))) {
    if (Install-ADDSForest -DomainName ${name}.local -DomainNetbiosName ${name} `
       -DomainMode WinThreshold -ForestMode WinThreshold `
       -DatabasePath C:/Windows/NTDS -SysvolPath C:/Windows/SYSVOL `
        -LogPath C:/Windows/NTDS -NoRebootOnCompletion:$false -Force:$true `
        -SafeModeAdministratorPassword (ConvertTo-SecureString "${password}" -AsPlainText -Force)) {
    "AD Set up." | Out-File "C:\addssetup.done"
    }
    "Preparing for Manual Restart $(Get-Date)" | Out-File "c:\restart.done"
    # Define the action to run the PowerShell script
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""

    # Set the trigger to run 5 minutes from now
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)

    # Set the task to run with highest privileges
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    # Register the scheduled task
    Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -TaskName "RunScheduledScript" -Description "Scheduled task to run script in 5 minutes."

    Write-Host "Part 2 has been created to run as a script in 5 minutes."
    Restart-Computer -Force
}


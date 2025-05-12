<powershell>
Start-Transcript -Path "C:\SDMDomainSetup.log" -Append

"${rdpca}" | Out-File "C:\rdp.cer"
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
                    Install-ADCSCertificationAuthority -CAType EnterpriseRootCA `
                    -CACommonName $caCommonName `
                    -KeyLength $caKeyLength `
                    -HashAlgorithm $caHashAlgorithm `
                    -ValidityPeriod Years `
                    -ValidityPeriodUnits 2 `
                    -Force
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


</powershell>
<persist>true</persist>
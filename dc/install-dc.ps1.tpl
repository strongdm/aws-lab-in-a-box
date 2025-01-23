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


if (((-not (Test-Path "C:\addssetup.done")) -and (Test-Path "C:\addsinstall.done"))) {
    if (Install-ADDSForest -DomainName ${name}.local -DomainNetbiosName ${name} `
       -DomainMode WinThreshold -ForestMode WinThreshold `
       -DatabasePath C:/Windows/NTDS -SysvolPath C:/Windows/SYSVOL `
        -LogPath C:/Windows/NTDS -NoRebootOnCompletion:$false -Force:$true `
        -SafeModeAdministratorPassword (ConvertTo-SecureString "${password}" -AsPlainText -Force)) {
    "AD Set up." | Out-File "C:\addssetup.done"
    }
    Restart-Computer
}


if (((-not (Test-Path "C:\adcs.done")) -and (Test-Path "C:\addssetup.done"))) {
        try {
            $service = Get-Service -Name "CertSvc" -ErrorAction Stop
            if (-not ($service.Status -eq "Running")) {
                while (Get-ADDomain) {
                    "[DCInstall] Starting Installation of CA"
                    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

                    Import-Module ADCSDeployment
                    "[DCInstall] Starting Installation of ADCS"
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
                } else {
                    Start-Sleep -seconds 5
                }
            } else { "ADCS is already installed" }
        }  catch {
        "ADCS is already installed"
        }      
}

if (((-not (Test-Path "C:\sdm.done")) -and (Test-Path "C:\adcs.done"))) {
    Import-Certificate -FilePath "c:\rdp.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
    certutil -dspublish -f C:\rdp.cer RootCA 
    certutil -dspublish -f C:\rdp.cer NTAuthCA 
     # Ensure the required modules are loaded
    Import-Module GroupPolicy

    # Define GPO name and domain settings
    $GPOName = "Disable NLA and Enable Smart Card Authentication"
    $Domain = (Get-ADDomain).DistinguishedName

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


    # Link the GPO to the domain (or specific OU)
    New-GPLink -Name $GPOName -Target "LDAP://$Domain" -LinkEnabled Yes
    Write-Host "GPO linked to the domain."

    # Force the GPO update on all machines in the domain (optional, can be run later)
    Invoke-GPUpdate -Force
    Write-Host "Group Policy update has been triggered."
    "Certificates and GPOs updated" | Out-File "C:\sdm.done"

}


</powershell>
<persist>true</persist>
#--------------------------------------------------------------
# ADCS/NDES Installation - Part 2: ADCS Configuration
#
# This script runs after domain join reboot and performs:
# 1. Install ADCS role (Certificate Authority)
# 2. Request and install subordinate CA certificate from root CA
# 3. Install NDES role with IIS
# 4. Create StrongDM certificate template (based on Smart Card Logon)
# 5. Configure NDES registry settings
# 6. Enable IIS Basic Authentication
# 7. Configure certificate template permissions
#--------------------------------------------------------------

# Logging function
$logFile = "C:\ADCSSetup.log"
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Add-Content -Path $logFile -Value $logMessage
}

Write-Log "=========================================="
Write-Log "Part 2: ADCS Installation Starting (Post-Reboot)"
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
Write-Log "  CA Common Name: $caCommonName"
Write-Log "  Template Name: $templateName"

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
    Write-Log "ERROR installing ADCS role: $_"
    exit 1
}

#--------------------------------------------------------------
# Step 4: Configure ADCS as Subordinate CA
#--------------------------------------------------------------
Write-Log "Step 4: Configuring ADCS as Enterprise Subordinate CA..."

try {
    # Configure as Enterprise Subordinate CA
    # Note: ValidityPeriod/ValidityPeriodUnits not used for subordinate CA - validity comes from parent CA
    Install-AdcsCertificationAuthority `
        -CAType EnterpriseSubordinateCA `
        -CACommonName "$caCommonName" `
        -CADistinguishedNameSuffix "DC=$domainName,DC=local" `
        -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
        -KeyLength 2048 `
        -HashAlgorithmName SHA256 `
        -Force `
        -ErrorAction Stop

    Write-Log "ADCS configured as subordinate CA successfully"
    Write-Log "CA Common Name: $caCommonName"

    # Wait for CA service to start
    Start-Sleep -Seconds 10

} catch {
    Write-Log "ERROR configuring ADCS: $_"
    exit 1
}

#--------------------------------------------------------------
# Step 5: Request Subordinate CA Certificate from Root CA
#--------------------------------------------------------------
Write-Log "Step 5: Requesting subordinate CA certificate from root CA..."

try {
    # Find the certificate request file - it could be in multiple locations with different naming patterns
    $requestFile = $null

    # Pattern 1: C:\<hostname>_<CA-Name>.req
    $pattern1 = "C:\*_$caCommonName.req"
    $reqFiles1 = Get-ChildItem -Path $pattern1 -ErrorAction SilentlyContinue

    # Pattern 2: C:\Windows\system32\CertSrv\CertEnroll\<CA-Name>.req
    $pattern2 = "C:\Windows\system32\CertSrv\CertEnroll\$caCommonName.req"

    # Pattern 3: Any .req file in CertEnroll directory
    $reqFiles3 = Get-ChildItem -Path "C:\Windows\system32\CertSrv\CertEnroll\*.req" -ErrorAction SilentlyContinue

    if ($reqFiles1 -and $reqFiles1.Count -gt 0) {
        $requestFile = $reqFiles1[0].FullName
        Write-Log "Certificate request file found (pattern 1): $requestFile"
    } elseif (Test-Path $pattern2) {
        $requestFile = $pattern2
        Write-Log "Certificate request file found (pattern 2): $requestFile"
    } elseif ($reqFiles3 -and $reqFiles3.Count -gt 0) {
        $requestFile = $reqFiles3[0].FullName
        Write-Log "Certificate request file found (pattern 3): $requestFile"
    }

    if ($requestFile) {
        $rootCAName = "$dcFQDN\$domainName-CA"
        Write-Log "Found certificate request file: $requestFile"

        # Use PowerShell Remoting (WinRM) to sign certificate on DC
        # This avoids RPC issues when CA service is not running on ADCS server
        Write-Log "Using PowerShell Remoting to submit and sign certificate on DC..."
        Write-Log "Root CA: $rootCAName"

        try {
            # Create credential object for domain admin
            $securePassword = ConvertTo-SecureString "$domainPassword" -AsPlainText -Force
            $domainCred = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", $securePassword)

            # Copy .req file to DC and sign it via PowerShell Remoting
            Write-Log "Copying certificate request to DC..."
            $session = New-PSSession -ComputerName "$dcFQDN" -Credential $domainCred
            Write-Log "Session created (Session ID: $($session.Id), State: $($session.State))"

            # Clean up any old certificate files on DC first
            Write-Log "Cleaning up old certificate files on DC..."
            Invoke-Command -Session $session -ScriptBlock {
                Remove-Item -Path "C:\temp-ca-request.req" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "C:\temp-ca-cert.crt" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "C:\temp-ca-cert.rsp" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "C:\temp-ca-cert.p7b" -Force -ErrorAction SilentlyContinue
            }

            # Copy the .req file to DC
            Copy-Item -Path "$requestFile" -Destination "C:\temp-ca-request.req" -ToSession $session
            Write-Log "Request file copied to DC"

            # Submit certificate request on DC
            # Note: certreq -submit may hang but still creates the certificate in the background
            Write-Log "Submitting certificate request on DC (running in background)..."
            Write-Log "Creating background job with separate session to avoid parent session invalidation..."

            # Start the submission job - use Start-Job with a scriptblock that creates its own session
            # This avoids the issue where Invoke-Command -AsJob invalidates the parent session
            $submitJob = Start-Job -ScriptBlock {
                param($dcFQDN, $domainFQDN, $domainAdmin, $domainPassword, $reqFilePath, $caName)

                # Create credential for job's own session
                $secPass = ConvertTo-SecureString $domainPassword -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", $secPass)

                Write-Output "Job: Creating session to $dcFQDN as $domainFQDN\$domainAdmin"
                $jobSession = New-PSSession -ComputerName $dcFQDN -Credential $cred -ErrorAction Stop
                Write-Output "Job: Session created (ID: $($jobSession.Id))"

                try {
                    Write-Output "Job: Submitting certificate request..."
                    Write-Output "Job: Request file: $reqFilePath"
                    Write-Output "Job: CA Name: $caName"

                    $result = Invoke-Command -Session $jobSession -ScriptBlock {
                        param($req, $ca)
                        Write-Output "Remote: Running certreq.exe -config `"$ca`" -submit `"$req`" C:\temp-ca-cert.crt"
                        certreq.exe -config "$ca" -submit "$req" "C:\temp-ca-cert.crt" 2>&1
                    } -ArgumentList $reqFilePath, $caName

                    Write-Output "Job: certreq result: $result"
                } catch {
                    Write-Output "Job ERROR: $_"
                    Write-Output "Job ERROR Details: $($_.Exception.Message)"
                } finally {
                    Write-Output "Job: Closing session"
                    Remove-PSSession -Session $jobSession -ErrorAction Continue
                }
            } -ArgumentList "$dcFQDN", "$domainFQDN", "$domainAdmin", "$domainPassword", "C:\temp-ca-request.req", $rootCAName

            Write-Log "Submission job started (Job ID: $($submitJob.Id), State: $($submitJob.State))"
            Write-Log "Polling for certificate file (checking every 5 seconds, max 60 seconds)..."

            # Poll for the certificate file instead of waiting for command output
            # Use the main session which remains intact since the job has its own session
            $maxWait = 60
            $waited = 0
            $certCreated = $false

            while ($waited -lt $maxWait -and -not $certCreated) {
                Start-Sleep -Seconds 5
                $waited += 5

                # Log any job output that's become available
                $jobOutput = Receive-Job -Job $submitJob -Keep -ErrorAction Continue
                if ($jobOutput) {
                    foreach ($line in $jobOutput) {
                        Write-Log "  [Job Output] $line"
                    }
                }

                # Check if certificate file exists on DC using the main session
                $certExists = Invoke-Command -Session $session -ScriptBlock {
                    Test-Path "C:\temp-ca-cert.crt"
                }

                if ($certExists) {
                    $certCreated = $true
                    Write-Log "SUCCESS: Certificate file detected on DC after $waited seconds"
                } else {
                    Write-Log "Waiting for certificate... ($waited seconds elapsed)"
                }
            }

            # Stop the job (it may still be hanging but cert is created)
            Stop-Job -Job $submitJob -ErrorAction SilentlyContinue
            Remove-Job -Job $submitJob -Force -ErrorAction SilentlyContinue

            $signResult = @{
                Success = $certCreated
                Output = if ($certCreated) { "Certificate created successfully" } else { "Certificate not created within timeout" }
            }

            Write-Log "Certificate signing result: Success=$($signResult.Success)"
            Write-Log "$($signResult.Output)"

            if ($signResult.Success) {
                # Copy the signed certificate back from DC
                Write-Log "Copying signed certificate from DC..."
                $certFile = "C:\$caCommonName.crt"
                Copy-Item -Path "C:\temp-ca-cert.crt" -Destination $certFile -FromSession $session
                Write-Log "Certificate copied from DC to $certFile"

                # Clean up temp files on DC
                Invoke-Command -Session $session -ScriptBlock {
                    Remove-Item -Path "C:\temp-ca-request.req" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "C:\temp-ca-cert.crt" -Force -ErrorAction SilentlyContinue
                }

                # Install the certificate locally using domain admin credentials
                # This requires AD rights to publish the CA certificate to Active Directory
                if (Test-Path $certFile) {
                    Write-Log "Installing subordinate CA certificate with domain admin credentials..."
                    Write-Log "Note: certutil -installcert requires domain admin to publish to AD"

                    # Use scheduled task to run certutil with domain admin credentials
                    # This is more reliable than PSRemoting to localhost
                    $taskName = "InstallCACert"
                    $taskAction = "certutil.exe -installcert `"$certFile`""

                    try {
                        Write-Log "Creating scheduled task with domain admin credentials..."

                        # Create scheduled task
                        schtasks.exe /create `
                            /tn $taskName `
                            /tr $taskAction `
                            /sc once `
                            /st 00:00 `
                            /ru "$domainFQDN\$domainAdmin" `
                            /rp "$domainPassword" `
                            /rl HIGHEST `
                            /f 2>&1 | ForEach-Object { Write-Log "  $_" }

                        if ($LASTEXITCODE -ne 0) {
                            throw "Failed to create scheduled task (exit code: $LASTEXITCODE)"
                        }

                        Write-Log "Running scheduled task..."
                        schtasks.exe /run /tn $taskName

                        # Wait for task to complete
                        Start-Sleep -Seconds 15

                        # Check task status
                        $taskInfo = schtasks.exe /query /tn $taskName /fo csv /v | ConvertFrom-Csv
                        $lastResult = $taskInfo.'Last Result'
                        Write-Log "Task completed with result: $lastResult"

                        # Clean up task
                        Write-Log "Deleting scheduled task..."
                        schtasks.exe /delete /tn $taskName /f 2>&1 | Out-Null

                        if ($lastResult -eq '0') {
                            Write-Log "Subordinate CA certificate installed successfully"
                        } else {
                            throw "Certificate installation failed with code: $lastResult"
                        }

                        # Start CA service
                        Start-Service -Name CertSvc -ErrorAction Stop
                        Write-Log "Certificate Authority service started"

                        # Verify CA service is running
                        Start-Sleep -Seconds 5
                        $caService = Get-Service -Name CertSvc
                        if ($caService.Status -eq "Running") {
                            Write-Log "CA service verified running"
                        } else {
                            Write-Log "WARNING: CA service status is $($caService.Status)"
                        }

                        # Verify CA is operational with certutil ping
                        $pingOutput = certutil -ping 2>&1
                        Write-Log "CA ping result: $pingOutput"

                        if ($pingOutput -like "*interface is alive*" -or $pingOutput -like "*Server*OK*") {
                            Write-Log "CA operational check: PASSED"
                        } else {
                            Write-Log "WARNING: CA operational check may have failed - review ping output above"
                        }

                    } catch {
                        Write-Log "ERROR installing certificate with scheduled task: $_"
                        Write-Log "Exception: $($_.Exception.Message)"
                        throw
                    }

                } else {
                    Write-Log "ERROR: Certificate file not found after copy from DC"
                }

                # Close the session
                Remove-PSSession -Session $session
            } else {
                Write-Log "ERROR: Failed to sign certificate on DC"
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "ERROR: Failed to use PowerShell Remoting for certificate signing: $_"
            Write-Log "Exception: $($_.Exception.Message)"
            Write-Log "Falling back to manual certificate installation"
            Write-Log "You may need to:"
            Write-Log "  1. Manually approve the request on the DC"
            Write-Log "  2. Export the signed certificate from the DC"
            Write-Log "  3. Copy it to the ADCS server and install with: certutil -installcert <file>"
        }
    } else {
        Write-Log "ERROR: No certificate request file found"
        Write-Log "Searched locations:"
        Write-Log "  - C:\*_$caCommonName.req"
        Write-Log "  - C:\Windows\system32\CertSrv\CertEnroll\$caCommonName.req"
        Write-Log "  - C:\Windows\system32\CertSrv\CertEnroll\*.req"
    }
} catch {
    Write-Log "ERROR requesting/installing CA certificate: $_"
    Write-Log "Exception details: $($_.Exception.Message)"
}

#--------------------------------------------------------------
# Step 6: Install NDES Role and IIS
#--------------------------------------------------------------
Write-Log "Step 6: Installing NDES role with IIS..."

try {
    # Install NDES and required IIS features
    Install-WindowsFeature -Name ADCS-Device-Enrollment -IncludeManagementTools -ErrorAction Stop
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop
    Install-WindowsFeature -Name Web-Basic-Auth -ErrorAction Stop

    Write-Log "NDES and IIS features installed successfully"

    # Add domain admin to IIS_IUSRS group (group is created when IIS is installed)
    Write-Log "Adding domain admin to IIS_IUSRS group..."
    $addUserResult = net localgroup IIS_IUSRS /add "$domainFQDN\$domainAdmin" 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Log "Added $domainFQDN\$domainAdmin to IIS_IUSRS group"
    } elseif ($addUserResult -match "already a member") {
        Write-Log "Domain admin already member of IIS_IUSRS group"
    } else {
        Write-Log "WARNING: Failed to add domain admin to IIS_IUSRS group: $addUserResult"
        Write-Log "NDES configuration may fail without this membership"
    }

} catch {
    Write-Log "ERROR installing NDES: $_"
}

#--------------------------------------------------------------
# Step 7: Configure NDES
#--------------------------------------------------------------
Write-Log "Step 7: Configuring NDES..."

try {
    # NDES configuration requires domain admin privileges
    # Create a PowerShell script to run with domain admin credentials via scheduled task
    $ndesConfigScript = @"
`$ErrorActionPreference = 'Stop'
`$logFile = 'C:\ADCSSetup.log'
function Write-Log {
    param([string]`$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    `$logMessage = "[`$timestamp] `$Message"
    Add-Content -Path `$logFile -Value `$logMessage
}

try {
    Write-Log "Running NDES configuration with domain admin credentials..."
    `$securePassword = ConvertTo-SecureString '$domainPassword' -AsPlainText -Force

    # NOTE: When ADCS CA is on the same server as NDES, do NOT specify -CAConfig
    # NDES will automatically use the local CA
    Install-AdcsNetworkDeviceEnrollmentService ``
        -ServiceAccountName '$domainFQDN\$domainAdmin' ``
        -ServiceAccountPassword `$securePassword ``
        -RAName 'StrongDM NDES RA' ``
        -RAEmail 'ndes@$domainFQDN' ``
        -RACompany 'StrongDM' ``
        -RADepartment 'IT' ``
        -RACity 'San Mateo' ``
        -RAState 'CA' ``
        -RACountry 'US' ``
        -SigningProviderName 'Microsoft Strong Cryptographic Provider' ``
        -SigningKeyLength 2048 ``
        -EncryptionProviderName 'Microsoft Strong Cryptographic Provider' ``
        -EncryptionKeyLength 2048 ``
        -Force ``
        -ErrorAction Stop

    Write-Log "NDES configured successfully"

    exit 0
} catch {
    Write-Log "ERROR configuring NDES: `$_"
    exit 1
}
"@

    $ndesScriptPath = "C:\ConfigureNDES.ps1"
    Set-Content -Path $ndesScriptPath -Value $ndesConfigScript

    Write-Log "Created NDES configuration script at $ndesScriptPath"

    # Create scheduled task to run NDES configuration with domain admin
    $taskName = "ConfigureNDES"
    $taskAction = "PowerShell.exe -ExecutionPolicy Bypass -File `"$ndesScriptPath`""

    schtasks.exe /create `
        /tn $taskName `
        /tr $taskAction `
        /sc once `
        /st 00:00 `
        /ru "$domainFQDN\$domainAdmin" `
        /rp "$domainPassword" `
        /rl HIGHEST `
        /f | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create scheduled task for NDES configuration"
    }

    Write-Log "Created scheduled task to configure NDES"

    # Run the task immediately
    schtasks.exe /run /tn $taskName | Out-Null
    Write-Log "Started NDES configuration task"

    # Wait for task to complete
    Start-Sleep -Seconds 30

    # Check task result
    $taskInfo = schtasks.exe /query /tn $taskName /fo csv /v | ConvertFrom-Csv
    $lastResult = $taskInfo.'Last Result'

    if ($lastResult -eq "0") {
        Write-Log "NDES configuration task completed successfully"
    } else {
        Write-Log "WARNING: NDES configuration task exit code: $lastResult"
    }

    # Clean up
    schtasks.exe /delete /tn $taskName /f | Out-Null
    Remove-Item -Path $ndesScriptPath -Force -ErrorAction SilentlyContinue

} catch {
    Write-Log "ERROR configuring NDES: $_"
}

#--------------------------------------------------------------
# Step 8: Trigger and Wait for Auto-Enrolled Certificate
#--------------------------------------------------------------
Write-Log "Step 8: Triggering certificate auto-enrollment..."

try {
    # Force Group Policy update to apply auto-enrollment GPO immediately
    Write-Log "Forcing Group Policy update to trigger auto-enrollment..."
    $gpResult = gpupdate /force /target:computer 2>&1 | Out-String
    Write-Log "Group Policy update completed"
    Write-Log "GPUpdate result: $($gpResult.Trim())"

    # Verify GPO is applied
    Write-Log "Verifying auto-enrollment GPO settings..."
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment"
    if (Test-Path $regPath) {
        $aePolicy = Get-ItemProperty -Path $regPath -Name "AEPolicy" -ErrorAction SilentlyContinue
        if ($aePolicy) {
            Write-Log "Auto-enrollment policy value: $($aePolicy.AEPolicy)"
        } else {
            Write-Log "WARNING: Auto-enrollment policy not found in registry"
        }
    } else {
        Write-Log "WARNING: Auto-enrollment registry path not found"
    }

    # Check available certificate templates
    Write-Log "Checking available certificate templates..."
    $templatesResult = certutil -TCAInfo 2>&1 | Out-String
    Write-Log "Available templates: $($templatesResult.Trim())"

    # Trigger certificate auto-enrollment with quiet flag for unattended operation
    Write-Log "Triggering certificate auto-enrollment (unattended)..."
    $autoenrollResult = certreq -autoenroll -machine -q 2>&1 | Out-String
    Write-Log "Auto-enrollment result: $($autoenrollResult.Trim())"

    # Wait for certificate to appear (auto-enrollment may take a moment)
    Write-Log "Waiting for auto-enrolled certificate to appear..."
    $maxWaitSeconds = 120
    $waitedSeconds = 0
    $cert = $null

    while ($waitedSeconds -lt $maxWaitSeconds -and -not $cert) {
        Start-Sleep -Seconds 10
        $waitedSeconds += 10

        # Look for certificate in LocalMachine\My store with Server Authentication EKU
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
            $_.Subject -like "CN=$computerName.$domainFQDN*" -and
            $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" -and
            $_.Issuer -like "*$domainName*"
        } | Select-Object -First 1

        if ($cert) {
            Write-Log "Auto-enrolled certificate found after $waitedSeconds seconds"
            Write-Log "  Subject: $($cert.Subject)"
            Write-Log "  Thumbprint: $($cert.Thumbprint)"
            Write-Log "  Expires: $($cert.NotAfter)"
            Write-Log "  Issuer: $($cert.Issuer)"
            break
        } else {
            Write-Log "Waiting for certificate... ($waitedSeconds seconds elapsed)"
        }
    }

    if (-not $cert) {
        Write-Log "WARNING: Auto-enrolled certificate did not appear within $maxWaitSeconds seconds"
        Write-Log "Certificate may enroll later via background auto-enrollment"
        Write-Log "NDES may not have HTTPS enabled immediately"
    }

} catch {
    Write-Log "ERROR during certificate auto-enrollment: $_"
    Write-Log "NDES will not have HTTPS enabled"
}

#--------------------------------------------------------------
# Step 9: Wait for Templates to be Published by DC
#--------------------------------------------------------------
Write-Log "Step 9: Waiting for certificate templates to be published by DC..."
Write-Log "NOTE: DC publishes templates to SubCA via background task"
Write-Log "Templates should appear within 5-30 minutes after DC provisioning"

# Note: The DC creates a scheduled task that waits for this SubCA to come online
# and then publishes StrongDM and ADCS-WebServer templates to it.
# We don't need to do anything here - just log that we're waiting.

try {
    # Check if templates are already available
    Import-Module ADCSAdministration -ErrorAction SilentlyContinue
    $templates = Get-CATemplate -ErrorAction SilentlyContinue

    if ($templates | Where-Object { $_.Name -eq "StrongDM" }) {
        Write-Log "StrongDM template is already published"
    } else {
        Write-Log "StrongDM template not yet published (will be published by DC)"
    }

    if ($templates | Where-Object { $_.Name -eq "ADCS-WebServer" }) {
        Write-Log "ADCS-WebServer template is already published"
    } else {
        Write-Log "ADCS-WebServer template not yet published (will be published by DC)"
    }
} catch {
    Write-Log "Could not check template status: $_"
}

#--------------------------------------------------------------
# Step 10: Configure NDES Registry Settings
#--------------------------------------------------------------
Write-Log "Step 10: Configuring NDES registry for StrongDM template..."

try {
    $mscepPath = "HKLM:\Software\Microsoft\Cryptography\MSCEP"

    if (Test-Path $mscepPath) {
        # Set all MSCEP registry values to use StrongDM template
        Set-ItemProperty -Path $mscepPath -Name "EncryptionTemplate" -Value "$templateName" -ErrorAction Stop
        Set-ItemProperty -Path $mscepPath -Name "GeneralPurposeTemplate" -Value "$templateName" -ErrorAction Stop
        Set-ItemProperty -Path $mscepPath -Name "SignatureTemplate" -Value "$templateName" -ErrorAction Stop

        Write-Log "NDES registry configured to use '$templateName' template"

        # Increase challenge password cache (for multiple gateways)
        Set-ItemProperty -Path $mscepPath -Name "MaxPendingRequests" -Value 50 -ErrorAction Stop
        Write-Log "Increased MaxPendingRequests to 50"

        # Restart IIS to apply changes
        iisreset
        Write-Log "IIS restarted to apply registry changes"
    } else {
        Write-Log "ERROR: MSCEP registry path not found"
    }
} catch {
    Write-Log "ERROR configuring NDES registry: $_"
}

#--------------------------------------------------------------
# Step 11: Enable IIS Basic Authentication
#--------------------------------------------------------------
Write-Log "Step 11: Enabling IIS Basic Authentication for NDES..."

try {
    Import-Module WebAdministration

    # Enable Basic Auth for CERTSRV mscep application
    Set-WebConfigurationProperty `
        -Filter "/system.webServer/security/authentication/basicAuthentication" `
        -Name "enabled" `
        -Value "True" `
        -PSPath "IIS:\" `
        -Location "Default Web Site/CertSrv/mscep" `
        -ErrorAction Stop

    Write-Log "Basic Authentication enabled for NDES SCEP endpoint"

    # Enable Basic Auth for CERTSRV mscep_admin application
    Set-WebConfigurationProperty `
        -Filter "/system.webServer/security/authentication/basicAuthentication" `
        -Name "enabled" `
        -Value "True" `
        -PSPath "IIS:\" `
        -Location "Default Web Site/CertSrv/mscep_admin" `
        -ErrorAction Stop

    Write-Log "Basic Authentication enabled for NDES SCEP admin endpoint"

    # Set Application Pool to Integrated mode (recommended)
    $appPool = Get-Item "IIS:\AppPools\SCEP"
    if ($appPool) {
        $appPool.managedPipelineMode = "Integrated"
        $appPool | Set-Item
        Write-Log "SCEP Application Pool set to Integrated mode"
    }

    # Configure HTTPS binding with machine certificate
    # Note: Web Server certificate is created on DC and retrieved from Parameter Store in Step 8
    Write-Log "Configuring HTTPS binding for NDES..."
    Write-Log "Looking for Web Server certificate..."

    # Find the certificate that was auto-enrolled in Step 8
    # Note: Auto-enrolled certificates may have Subject in SAN instead of Subject field
    $machineCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" -and
        $_.HasPrivateKey -eq $true -and
        (
            $_.Subject -like "CN=$computerName.$domainFQDN*" -or
            $_.Subject -eq "CN=$computerName.$domainFQDN" -or
            ($_.DnsNameList.Unicode -contains "$computerName.$domainFQDN")
        )
    } | Sort-Object NotAfter -Descending | Select-Object -First 1

    if (-not $machineCert) {
        Write-Log "Web Server certificate not found in LocalMachine\My store"

        # List available certificates for debugging
        $allCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
        if ($allCerts) {
            Write-Log "Available certificates in LocalMachine\My:"
            foreach ($cert in $allCerts) {
                Write-Log "  Subject: $($cert.Subject), Issuer: $($cert.Issuer)"
                if ($cert.EnhancedKeyUsageList) {
                    Write-Log "    EKU: $($cert.EnhancedKeyUsageList.FriendlyName -join ', ')"
                }
            }
        } else {
            Write-Log "No certificates found in LocalMachine\My store"
        }
    }

    if ($machineCert) {
        Write-Log "Machine certificate found: $($machineCert.Subject)"
        Write-Log "Certificate thumbprint: $($machineCert.Thumbprint)"

        # Add HTTPS binding to Default Web Site if it doesn't exist
        $existingBinding = Get-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -ErrorAction SilentlyContinue
        if (-not $existingBinding) {
            New-WebBinding -Name "Default Web Site" `
                -Protocol https `
                -Port 443 `
                -HostHeader "$computerName.$domainFQDN" `
                -SslFlags 0 `
                -ErrorAction Stop
            Write-Log "HTTPS binding created on port 443 with host header $computerName.$domainFQDN"
        } else {
            Write-Log "HTTPS binding already exists"
        }

        # Bind the certificate using the modern approach
        try {
            # Remove any existing SSL binding for 0.0.0.0:443
            if (Test-Path "IIS:\SslBindings\0.0.0.0!443") {
                Remove-Item -Path "IIS:\SslBindings\0.0.0.0!443" -Force
                Write-Log "Removed existing SSL binding"
            }

            # Create new SSL binding with certificate
            Get-Item -Path "Cert:\LocalMachine\My\$($machineCert.Thumbprint)" | `
                New-Item -Path "IIS:\SslBindings\0.0.0.0!443" -Force | Out-Null

            Write-Log "HTTPS binding configured with machine certificate"
        } catch {
            Write-Log "WARNING: Modern SSL binding method failed: $_"
            Write-Log "Attempting fallback method..."

            # Fallback to deprecated method if modern approach fails
            try {
                $binding = Get-WebBinding -Name "Default Web Site" -Protocol https -Port 443
                $binding.AddSslCertificate($machineCert.Thumbprint, "my")
                Write-Log "HTTPS binding configured using fallback method"
            } catch {
                Write-Log "ERROR: Both SSL binding methods failed: $_"
            }
        }
    } else {
        Write-Log "WARNING: Machine certificate not found for HTTPS binding"
        Write-Log "HTTPS will not be available - certificate may enroll after group policy refresh"
        Write-Log "Run 'gpupdate /force' and check Cert:\LocalMachine\My for machine certificates"
    }

    # Restart IIS
    iisreset
    Write-Log "IIS restarted"

} catch {
    Write-Log "ERROR configuring IIS: $_"
}

Write-Log "=========================================="
Write-Log "ADCS/NDES Installation Complete!"
Write-Log "=========================================="
Write-Log ""
Write-Log "NDES URL: http://$(hostname)/certsrv/mscep/mscep.dll"
Write-Log "Certificate Template: $templateName"
Write-Log "CA Common Name: $caCommonName"
Write-Log ""
Write-Log "For StrongDM Gateway configuration:"
Write-Log "  SDM_ADCS_USER=${domain_admin_user}@${domain_fqdn}"
Write-Log "  SDM_ADCS_PW=<use domain admin password>"
Write-Log ""

# Remove scheduled task
Unregister-ScheduledTask -TaskName "ADCSInstallPart2" -Confirm:$false -ErrorAction SilentlyContinue

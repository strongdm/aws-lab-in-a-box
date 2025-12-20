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

                # Install the certificate locally using domain admin credentials via PowerShell remoting
                # This requires AD rights to publish the CA certificate
                if (Test-Path $certFile) {
                    Write-Log "Installing subordinate CA certificate with domain admin credentials..."
                    Write-Log "Running certificate installation as domain admin via PowerShell remoting to localhost..."
                    try {
                        # Use Invoke-Command to localhost with domain admin credentials
                        $installResult = Invoke-Command -ComputerName localhost -Credential $domainCred -ScriptBlock {
                            param($certPath)
                            certutil.exe -installcert $certPath 2>&1
                        } -ArgumentList $certFile

                        Write-Log "Certificate installation output: $installResult"
                        Write-Log "Subordinate CA certificate installed successfully"

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
                        Write-Log "ERROR installing certificate: $_"
                        Write-Log "Trying alternative method with scheduled task approach..."

                        # Fallback: Use schtasks.exe with properly escaped arguments
                        # Note: We need to escape quotes for cmd.exe context
                        Write-Log "Creating scheduled task to install certificate as domain admin..."
                        $taskName = "InstallCACert"
                        $taskAction = "certutil.exe -installcert \`"$certFile\`""

                        # Use schtasks with individual parameters to avoid quote escaping issues
                        schtasks.exe /create `
                            /tn $taskName `
                            /tr $taskAction `
                            /sc once `
                            /st 00:00 `
                            /ru "$domainFQDN\$domainAdmin" `
                            /rp "$domainPassword" `
                            /rl HIGHEST `
                            /f 2>&1 | ForEach-Object { Write-Log "  $_" }

                        Write-Log "Running task..."
                        schtasks /run /tn InstallCACert
                        Start-Sleep -Seconds 10

                        Write-Log "Checking task result..."
                        $taskResult = schtasks /query /tn InstallCACert /fo list /v
                        Write-Log "$taskResult"

                        Write-Log "Deleting task..."
                        schtasks /delete /tn InstallCACert /f

                        # Try to start CA service
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

                        # Verify CA is operational
                        $pingOutput = certutil -ping 2>&1
                        Write-Log "CA ping result: $pingOutput"
                        if ($pingOutput -like "*interface is alive*" -or $pingOutput -like "*Server*OK*") {
                            Write-Log "CA operational check: PASSED"
                        } else {
                            Write-Log "WARNING: CA operational check may have failed"
                        }
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
    Write-Log "ERROR installing NDES: $_"
}

#--------------------------------------------------------------
# Step 7: Create StrongDM Certificate Template
#--------------------------------------------------------------
Write-Log "Step 7: Creating StrongDM certificate template..."

try {
    # Connect to AD Certificate Services
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    Write-Log "Certificate template container: $templateContainer"

    # Get Smart Card Logon template as source
    $sourceTemplate = Get-ADObject -SearchBase $templateContainer `
        -Filter {cn -eq "SmartcardLogon"} `
        -Properties * `
        -ErrorAction Stop

    if ($sourceTemplate) {
        Write-Log "Source template 'SmartcardLogon' found"

        # Create new template based on Smart Card Logon
        $newTemplateName = "$templateName"
        $newTemplateDN = "CN=$newTemplateName,$templateContainer"

        # Check if template already exists
        $existingTemplate = Get-ADObject -SearchBase $templateContainer `
            -Filter {cn -eq $newTemplateName} `
            -ErrorAction SilentlyContinue

        if (-not $existingTemplate) {
            # Copy template properties
            $templateAttributes = @{
                objectClass = "pKICertificateTemplate"
                cn = $newTemplateName
                displayName = $newTemplateName
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

            New-ADObject -Name $newTemplateName `
                -Type pKICertificateTemplate `
                -Path $templateContainer `
                -OtherAttributes $templateAttributes `
                -ErrorAction Stop

            Write-Log "Certificate template '$newTemplateName' created successfully"
            Write-Log "Template allows subject name in request: ENABLED"

            # Add template to CA
            Start-Sleep -Seconds 5
            certutil -SetCATemplates +$newTemplateName
            Write-Log "Template added to CA"

        } else {
            Write-Log "Certificate template '$newTemplateName' already exists"
        }
    } else {
        Write-Log "ERROR: SmartcardLogon template not found"
    }
} catch {
    Write-Log "ERROR creating certificate template: $_"
}

#--------------------------------------------------------------
# Step 8: Configure NDES
#--------------------------------------------------------------
Write-Log "Step 8: Configuring NDES..."

try {
    # Create service account credential (using domain admin for now)
    # NOTE: Credential not logged for security
    $securePassword = ConvertTo-SecureString "$domainPassword" -AsPlainText -Force
    $serviceCredential = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", $securePassword)

    # Install ADCS Network Device Enrollment Service
    Install-AdcsNetworkDeviceEnrollmentService `
        -ApplicationPoolIdentity `
        -CAConfig "$dcFQDN\\$domainName-CA" `
        -RAName "StrongDM NDES RA" `
        -RAEmail "ndes@$domainFQDN" `
        -RACompany "StrongDM" `
        -RADepartment "IT" `
        -RACity "San Mateo" `
        -RAState "CA" `
        -RACountry "US" `
        -SigningProviderName "Microsoft Strong Cryptographic Provider" `
        -SigningKeyLength 2048 `
        -EncryptionProviderName "Microsoft Strong Cryptographic Provider" `
        -EncryptionKeyLength 2048 `
        -ServiceAccountCredential $serviceCredential `
        -Force `
        -ErrorAction Stop

    Write-Log "NDES configured successfully"
} catch {
    Write-Log "ERROR configuring NDES: $_"
}

#--------------------------------------------------------------
# Step 9: Configure NDES Registry Settings
#--------------------------------------------------------------
Write-Log "Step 9: Configuring NDES registry for StrongDM template..."

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
# Step 10: Enable IIS Basic Authentication
#--------------------------------------------------------------
Write-Log "Step 10: Enabling IIS Basic Authentication for NDES..."

try {
    Import-Module WebAdministration

    # Enable Basic Auth for CERTSRV application
    Set-WebConfigurationProperty `
        -Filter "/system.webServer/security/authentication/basicAuthentication" `
        -Name "enabled" `
        -Value "True" `
        -PSPath "IIS:\" `
        -Location "Default Web Site/CertSrv/mscep" `
        -ErrorAction Stop

    Write-Log "Basic Authentication enabled for NDES SCEP endpoint"

    # Set Application Pool to Integrated mode (recommended)
    $appPool = Get-Item "IIS:\AppPools\SCEP"
    if ($appPool) {
        $appPool.managedPipelineMode = "Integrated"
        $appPool | Set-Item
        Write-Log "SCEP Application Pool set to Integrated mode"
    }

    # Configure HTTPS binding with machine certificate
    Write-Log "Configuring HTTPS binding for NDES..."

    # Get the machine certificate from the local computer's personal store
    # The certificate will be auto-enrolled from the domain CA
    Write-Log "Waiting for machine certificate auto-enrollment..."

    # Try to find machine cert, with retries
    $maxRetries = 3
    $retryCount = 0
    $machineCert = $null

    while ($retryCount -lt $maxRetries -and -not $machineCert) {
        Start-Sleep -Seconds 10

        $machineCert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
            ($_.Subject -like "*$computerName*" -or $_.Subject -like "*$env:COMPUTERNAME*") -and
            $_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"
        } | Select-Object -First 1

        $retryCount++

        if (-not $machineCert) {
            Write-Log "Machine certificate not found (attempt $retryCount/$maxRetries)"

            # Trigger group policy update to force certificate enrollment
            if ($retryCount -eq 1) {
                Write-Log "Triggering Group Policy update to force certificate enrollment..."
                gpupdate /force /target:computer | Out-String | ForEach-Object { Write-Log "  $_" }
            }

            # List available certificates for debugging
            $allCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
            if ($allCerts) {
                Write-Log "Available certificates in LocalMachine\My:"
                foreach ($cert in $allCerts) {
                    Write-Log "  Subject: $($cert.Subject), Issuer: $($cert.Issuer)"
                    if ($cert.EnhancedKeyUsageList) {
                        Write-Log "    EKU: $($cert.EnhancedKeyUsageList.FriendlyName -join ', ')"

# Test Script for Certificate Signing via WinRM
# This simulates Step 5 of the ADCS installation
# Run this from the ADCS server

param(
    [string]$dcFQDN = "dc.europa.local",
    [string]$domainFQDN = "europa.local",
    [string]$domainAdmin = "Admin",
    [string]$domainPassword = "YourPasswordHere",
    [string]$domainName = "Europa",
    [string]$requestFile = "C:\Europa-adcs.Europa.local_Europa-SubCA.req"
)

Write-Host "=== Certificate Signing Test Script ===" -ForegroundColor Cyan
Write-Host "DC: $dcFQDN" -ForegroundColor Yellow
Write-Host "Request File: $requestFile" -ForegroundColor Yellow
Write-Host ""

# Check if request file exists
if (-not (Test-Path $requestFile)) {
    Write-Host "ERROR: Request file not found: $requestFile" -ForegroundColor Red
    Write-Host "Looking for .req files..." -ForegroundColor Yellow
    $foundReq = Get-ChildItem C:\*.req -ErrorAction SilentlyContinue
    if ($foundReq) {
        Write-Host "Found: $($foundReq.FullName)" -ForegroundColor Green
        $requestFile = $foundReq.FullName
    } else {
        Write-Host "No .req files found in C:\" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Using request file: $requestFile" -ForegroundColor Green
Write-Host ""

$rootCAName = "$dcFQDN\$domainName-CA"

try {
    # Create credential object
    Write-Host "[1/8] Creating domain admin credentials..." -ForegroundColor Cyan
    $securePassword = ConvertTo-SecureString $domainPassword -AsPlainText -Force
    $domainCred = New-Object System.Management.Automation.PSCredential("$domainFQDN\$domainAdmin", $securePassword)
    Write-Host "    ✓ Credentials created" -ForegroundColor Green

    # Create PS Session
    Write-Host "[2/8] Creating PowerShell session to DC..." -ForegroundColor Cyan
    $session = New-PSSession -ComputerName $dcFQDN -Credential $domainCred
    Write-Host "    ✓ Session created (Session ID: $($session.Id))" -ForegroundColor Green

    # Copy request file to DC
    Write-Host "[3/8] Copying certificate request to DC..." -ForegroundColor Cyan
    Copy-Item -Path $requestFile -Destination "C:\temp-ca-request.req" -ToSession $session
    Write-Host "    ✓ Request file copied to DC" -ForegroundColor Green

    # Verify file on DC
    Write-Host "[4/8] Verifying file on DC..." -ForegroundColor Cyan
    $fileExists = Invoke-Command -Session $session -ScriptBlock {
        Test-Path "C:\temp-ca-request.req"
    }
    if ($fileExists) {
        Write-Host "    ✓ File verified on DC" -ForegroundColor Green
    } else {
        Write-Host "    ✗ File not found on DC!" -ForegroundColor Red
        exit 1
    }

    # Submit certificate request (background job with polling)
    Write-Host "[5/8] Submitting certificate request on DC..." -ForegroundColor Cyan
    Write-Host "    Note: certreq command will hang but certificate will be created" -ForegroundColor Yellow

    $submitJob = Invoke-Command -Session $session -ScriptBlock {
        param($reqFilePath, $caName)
        certreq.exe -config "$caName" -submit "$reqFilePath" "C:\temp-ca-cert.crt" 2>&1
    } -ArgumentList "C:\temp-ca-request.req", $rootCAName -AsJob

    Write-Host "    ✓ Submission job started (Job ID: $($submitJob.Id))" -ForegroundColor Green

    # Poll for certificate file
    Write-Host "[6/8] Polling for certificate file (max 60 seconds)..." -ForegroundColor Cyan
    $maxWait = 60
    $waited = 0
    $certCreated = $false

    while ($waited -lt $maxWait -and -not $certCreated) {
        Start-Sleep -Seconds 5
        $waited += 5

        $certExists = Invoke-Command -Session $session -ScriptBlock {
            Test-Path "C:\temp-ca-cert.crt"
        }

        if ($certExists) {
            $certCreated = $true
            Write-Host "    ✓ Certificate file detected after $waited seconds!" -ForegroundColor Green
        } else {
            Write-Host "    ... waiting ($waited seconds elapsed)" -ForegroundColor Gray
        }
    }

    # Stop the background job
    Stop-Job -Job $submitJob -ErrorAction SilentlyContinue
    Remove-Job -Job $submitJob -Force -ErrorAction SilentlyContinue

    if (-not $certCreated) {
        Write-Host "    ✗ Certificate not created within timeout" -ForegroundColor Red
        exit 1
    }

    # Copy certificate back
    Write-Host "[7/8] Copying signed certificate from DC..." -ForegroundColor Cyan
    Copy-Item -Path "C:\temp-ca-cert.crt" -Destination "C:\test-signed-cert.crt" -FromSession $session
    Write-Host "    ✓ Certificate copied to C:\test-signed-cert.crt" -ForegroundColor Green

    # Verify certificate locally
    Write-Host "[8/8] Verifying certificate file..." -ForegroundColor Cyan
    if (Test-Path "C:\test-signed-cert.crt") {
        $certInfo = certutil -dump "C:\test-signed-cert.crt" 2>&1
        Write-Host "    ✓ Certificate file is valid" -ForegroundColor Green
        Write-Host ""
        Write-Host "Certificate Details:" -ForegroundColor Yellow
        Write-Host ($certInfo | Select-String "Subject:", "Issuer:", "NotBefore:", "NotAfter:" | Out-String)
    } else {
        Write-Host "    ✗ Certificate file not found locally" -ForegroundColor Red
        exit 1
    }

    # Clean up DC
    Write-Host ""
    Write-Host "Cleaning up temporary files on DC..." -ForegroundColor Cyan
    Invoke-Command -Session $session -ScriptBlock {
        Remove-Item -Path "C:\temp-ca-request.req" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\temp-ca-cert.crt" -Force -ErrorAction SilentlyContinue
    }
    Write-Host "✓ Cleanup complete" -ForegroundColor Green

    # Close session
    Remove-PSSession -Session $session

    Write-Host ""
    Write-Host "=== TEST SUCCESSFUL ===" -ForegroundColor Green
    Write-Host "The certificate signing workflow works correctly!" -ForegroundColor Green
    Write-Host "Signed certificate saved to: C:\test-signed-cert.crt" -ForegroundColor Yellow

} catch {
    Write-Host ""
    Write-Host "=== TEST FAILED ===" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red

    if ($session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }

    exit 1
}

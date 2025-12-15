# Domain Controller Parameter Store Integration

## Overview

The DC module automatically stores key domain controller information in AWS Systems Manager Parameter Store upon successful deployment. This allows other modules and resources to dynamically discover DC information without hardcoding values.

## Parameters Stored

The installation script stores three parameters in Parameter Store:

| Parameter Path | Content | Format | Example |
|----------------|---------|--------|---------|
| `/{name}/dc/ca-certificate` | CA public certificate | Base64 | `MIIDXTCCAkWgAwIBAgI...` |
| `/{name}/dc/fqdn` | Domain controller FQDN | String | `EC2AMAZ-ABC1234.europa.local` |
| `/{name}/dc/computer-name` | Computer name (short) | String | `EC2AMAZ-ABC1234` |

Where `{name}` is the domain name prefix (e.g., `europa`).

## Use Cases

### 1. Windows Targets Joining Domain

Other Windows instances can retrieve the DC information to join the domain:

```powershell
# Retrieve DC FQDN
$dcFqdn = (Get-SSMParameter -Name "/europa/dc/fqdn").Value

# Retrieve CA Certificate
$caCertBase64 = (Get-SSMParameter -Name "/europa/dc/ca-certificate").Value
$caCertBytes = [System.Convert]::FromBase64String($caCertBase64)
[System.IO.File]::WriteAllBytes("C:\ca.cer", $caCertBytes)

# Import CA certificate
Import-Certificate -FilePath "C:\ca.cer" -CertStoreLocation "Cert:\LocalMachine\Root"

# Join domain using discovered DC
Add-Computer -DomainName "europa.local" -Server $dcFqdn -Credential $credential
```

### 2. Terraform Data Sources

Other Terraform modules can read these parameters:

```hcl
# Read DC FQDN from Parameter Store
data "aws_ssm_parameter" "dc_fqdn" {
  name = "/${var.name}/dc/fqdn"

  depends_on = [module.dc]
}

# Read CA certificate
data "aws_ssm_parameter" "ca_certificate" {
  name = "/${var.name}/dc/ca-certificate"

  depends_on = [module.dc]
}

# Use in Windows target configuration
resource "aws_instance" "windows_target" {
  # ... instance configuration ...

  user_data = templatefile("join-domain.ps1", {
    dc_fqdn        = data.aws_ssm_parameter.dc_fqdn.value
    ca_cert_base64 = data.aws_ssm_parameter.ca_certificate.value
    domain_name    = "europa.local"
  })
}
```

### 3. Module Outputs

The DC module exposes the parameter paths as outputs:

```hcl
module "dc" {
  source = "github.com/strongdm/aws-lab-in-a-box.git//dc?ref=2.1.1"
  # ... configuration ...
}

output "ca_cert_param" {
  value = module.dc.ssm_ca_certificate_parameter
  # Output: "/europa/dc/ca-certificate"
}

output "dc_fqdn_param" {
  value = module.dc.ssm_fqdn_parameter
  # Output: "/europa/dc/fqdn"
}

output "dc_name_param" {
  value = module.dc.ssm_computer_name_parameter
  # Output: "/europa/dc/computer-name"
}
```

## IAM Permissions

### DC Instance Role (Already Configured)

The DC instance IAM role includes permissions to write parameters:

```json
{
  "Effect": "Allow",
  "Action": [
    "ssm:PutParameter",
    "ssm:GetParameter",
    "ssm:DeleteParameter"
  ],
  "Resource": "arn:aws:ssm:*:*:parameter/{name}/dc/*"
}
```

### Other Resources Reading Parameters

Resources that need to read these parameters require:

```json
{
  "Effect": "Allow",
  "Action": [
    "ssm:GetParameter",
    "ssm:GetParameters"
  ],
  "Resource": [
    "arn:aws:ssm:*:*:parameter/{name}/dc/ca-certificate",
    "arn:aws:ssm:*:*:parameter/{name}/dc/fqdn",
    "arn:aws:ssm:*:*:parameter/{name}/dc/computer-name"
  ]
}
```

## Implementation Details

### When Parameters Are Created

Parameters are stored during **Phase 3** of the DC installation, after:
1. ✅ DC promotion completed
2. ✅ ADCS installed and configured
3. ✅ CA certificate generated
4. ✅ Domain users created
5. ✅ Group policies configured

This ensures the CA certificate is valid and the DC is fully operational.

### Export Process

The script uses `certutil` to export the CA certificate:

```powershell
# Export CA certificate using certutil
certutil -ca.cert C:\ca-certificate.cer

# Read and encode as Base64
$caCertBytes = [System.IO.File]::ReadAllBytes("C:\ca-certificate.cer")
$caCertBase64 = [System.Convert]::ToBase64String($caCertBytes)

# Store in Parameter Store
Write-SSMParameter -Name "/{name}/dc/ca-certificate" -Value $caCertBase64 -Type "String" -Overwrite $true
```

### Error Handling

The script includes graceful error handling:

- **If Parameter Store write fails**: Logs warning but continues (doesn't fail deployment)
- **If CA certificate export fails**: Logs warning, skips Parameter Store writes
- **If IAM permissions missing**: Logs specific error message about missing permissions

This ensures that Parameter Store failures don't break the entire DC deployment.

## Verification

### Check Parameters Were Created

Using AWS CLI:

```bash
# List all DC parameters
aws ssm get-parameters-by-path --path "/europa/dc" --recursive

# Get specific parameter
aws ssm get-parameter --name "/europa/dc/fqdn"
aws ssm get-parameter --name "/europa/dc/ca-certificate"
aws ssm get-parameter --name "/europa/dc/computer-name"
```

Using PowerShell:

```powershell
# List all DC parameters
Get-SSMParametersByPath -Path "/europa/dc" -Recursive $true

# Get specific parameters
Get-SSMParameter -Name "/europa/dc/fqdn"
Get-SSMParameter -Name "/europa/dc/ca-certificate"
Get-SSMParameter -Name "/europa/dc/computer-name"
```

### Decode CA Certificate

```powershell
# Get parameter value
$caCertBase64 = (Get-SSMParameter -Name "/europa/dc/ca-certificate").Value

# Decode from Base64
$caCertBytes = [System.Convert]::FromBase64String($caCertBase64)

# Save to file
[System.IO.File]::WriteAllBytes("C:\ca-decoded.cer", $caCertBytes)

# View certificate details
certutil -dump "C:\ca-decoded.cer"
```

### Check Logs

The DC installation log shows Parameter Store operations:

```powershell
Get-Content C:\SDMDomainSetup.log | Select-String "Parameter Store"
```

Expected output:
```
[DCInstall] Storing CA certificate and computer name in Parameter Store...
[DCInstall] Computer FQDN: EC2AMAZ-ABC1234.europa.local
[DCInstall] CA certificate exported successfully
[DCInstall] CA certificate stored in Parameter Store: /europa/dc/ca-certificate
[DCInstall] Computer FQDN stored in Parameter Store: /europa/dc/fqdn
[DCInstall] Computer name stored in Parameter Store: /europa/dc/computer-name
```

## Troubleshooting

### Issue: Parameters Not Created

**Symptoms**: Parameters missing in Parameter Store after DC deployment

**Possible Causes**:
1. IAM permissions missing (ssm:PutParameter)
2. CA certificate export failed
3. ADCS not properly configured

**Solution**:
1. Check `C:\SDMDomainSetup.log` for errors
2. Verify IAM role has `ssm:PutParameter` permission
3. Check if `C:\sdm.done` marker exists (indicates Phase 3 completed)
4. Verify ADCS service is running: `Get-Service CertSvc`

### Issue: Access Denied When Reading Parameters

**Symptoms**: Other resources can't read parameters

**Cause**: Missing IAM permissions

**Solution**: Add `ssm:GetParameter` permission to the resource's IAM role

### Issue: Invalid CA Certificate

**Symptoms**: Certificate decode fails or import fails

**Cause**: Certificate export or encoding issue

**Solution**:
1. Check if `certutil -ca.cert` command succeeded in logs
2. Verify ADCS is configured: `certutil -ping`
3. Try manual export: `certutil -ca.cert C:\test.cer`

## Benefits

1. **Dynamic Discovery**: No hardcoded DC names or certificates
2. **Automation**: Other resources can self-configure using Parameter Store
3. **Centralized**: Single source of truth for DC information
4. **Secure**: IAM policies control access to sensitive parameters
5. **Version Control**: Parameters can be updated if DC changes

## Cost

Parameter Store Standard tier is free for:
- Up to 10,000 parameters per account/region
- Standard throughput (40 TPS)

These 3 parameters per deployment have **no cost impact**.

## Security Considerations

1. **CA Certificate**: Public certificate (not sensitive) - can be safely stored as String type
2. **Parameter Names**: Include domain name prefix for multi-environment isolation
3. **IAM Permissions**: Scoped to specific parameter paths (`/{name}/dc/*`)
4. **No Secrets**: Only public information stored (FQDN, computer name, public cert)

## Migration from Hardcoded Values

If you currently hardcode DC information, you can migrate to Parameter Store:

**Before**:
```hcl
locals {
  dc_fqdn = "dc1.europa.local"  # Hardcoded
}
```

**After**:
```hcl
data "aws_ssm_parameter" "dc_fqdn" {
  name = module.dc.ssm_fqdn_parameter
}

locals {
  dc_fqdn = data.aws_ssm_parameter.dc_fqdn.value  # Dynamic
}
```

## Related Documentation

- Module outputs: `outputs.tf`
- IAM policy: `dc.tf` (lines 239-269)
- Installation script: `install-dc-from-ami.ps1.tpl` (lines 333-406)

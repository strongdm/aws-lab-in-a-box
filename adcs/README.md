# ADCS/NDES Module

This module deploys a Windows Server 2019 instance configured with Active Directory Certificate Services (ADCS) and Network Device Enrollment Service (NDES) as an intermediate Certificate Authority for StrongDM certificate-based authentication.

## Overview

The ADCS/NDES server provides automated certificate issuance for StrongDM gateways and relays using the SCEP (Simple Certificate Enrollment Protocol) protocol. This enables certificate-based authentication without manual certificate management.

### Architecture

The module uses an S3 bucket to store and deliver the PowerShell installation script to avoid AWS's 16KB user_data size limit:

1. **S3 Bucket**: Created to store the full installation script
2. **IAM Role**: EC2 instance profile with S3 read permissions
3. **Bootstrap Script**: Minimal user_data that downloads and executes the full script from S3
4. **Installation Script**: Complete ADCS/NDES configuration stored as S3 object

This approach ensures the module can handle large, complex installation scripts without hitting platform limitations.

### What Gets Configured

1. **Domain Join**: Server joins the Active Directory domain
2. **ADCS Installation**: Installed as Enterprise Subordinate CA
3. **CA Certificate Chain**: Subordinate CA certificate requested and installed from root CA on DC
4. **NDES Installation**: Configured with IIS and Basic Authentication
5. **Certificate Template**: Custom "StrongDM" template created (based on Smart Card Logon)
6. **Registry Configuration**: MSCEP registry keys set to use StrongDM template
7. **IIS Configuration**: Basic Authentication enabled, SCEP Application Pool set to Integrated mode
8. **Template Permissions**: Certificate template configured with appropriate permissions

## Requirements

### Prerequisites

- Existing Active Directory domain with root CA (typically on Domain Controller)
- Domain administrator credentials
- VPC with appropriate subnets and security groups
- Windows Server 2019 AMI

### Security Group Requirements

The ADCS server security group must allow:

- **Inbound**:
  - Port 443 (HTTPS) from StrongDM gateways/relays for secure SCEP enrollment
  - Port 80 (HTTP) optional, if not using HTTPS
  - Port 445 (SMB) from DC for certificate request submission
  - Port 3389 (RDP) for administrative access
  - Standard AD ports for domain membership (see domain controller module)

- **Outbound**:
  - Port 443 (HTTPS) to AWS S3 endpoints for downloading installation scripts
  - All traffic (for Windows Updates, domain communication, etc.)

### IAM Requirements

The module automatically creates:
- **IAM Role**: Allows EC2 instance to assume role
- **IAM Policy**: Grants S3 read access to the scripts bucket
- **Instance Profile**: Attaches the role to the EC2 instance

## Usage

```hcl
module "adcs" {
  source = "github.com/strongdm/aws-lab-in-a-box.git//adcs?ref=<version>"

  # Network configuration
  subnet_id = module.network.relay_subnet
  sg        = module.network.private_sg

  # Resource identification
  tagset = {
    environment = "Demo"
    customer    = "MyCompany"
    sdm-owner   = "admin@mycompany.com"
  }
  name = "Europa"

  # Windows Server
  ami      = data.aws_ami.windows_2019.id
  key_name = aws_key_pair.main.key_name

  # Active Directory integration
  domain_name       = "Europa"
  dc_ip             = module.dc.target_ip
  dc_fqdn           = data.aws_ssm_parameter.dc_fqdn.value
  domain_admin_user = "Administrator"
  domain_password   = module.dc.admin_password

  # ADCS configuration (optional overrides)
  ca_common_name            = "Europa-SubCA"
  certificate_template_name = "StrongDM"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| subnet_id | Subnet ID for ADCS server deployment | string | - | yes |
| sg | Security group ID for ADCS server | string | - | yes |
| tagset | Map of tags to apply to all resources | map(string) | - | yes |
| name | Name prefix for resources | string | - | yes |
| ami | Windows Server 2019 AMI ID | string | - | yes |
| instance_type | EC2 instance type | string | `"t3.medium"` | no |
| key_name | EC2 key pair name for password retrieval | string | - | yes |
| domain_name | AD domain name (without .local) | string | - | yes |
| dc_ip | Domain Controller IP address | string | - | yes |
| dc_fqdn | Domain Controller FQDN | string | - | yes |
| domain_admin_user | Domain administrator username | string | `"Administrator"` | no |
| domain_password | Domain administrator password | string (sensitive) | - | yes |
| ca_common_name | CA certificate Common Name | string | `"<name>-SubCA"` | no |
| certificate_template_name | Certificate template name | string | `"StrongDM"` | no |
| ndes_service_account | NDES service account name | string | `"NDESService"` | no |

## Outputs

| Name | Description |
|------|-------------|
| adcs_instance_id | EC2 instance ID of the ADCS server |
| adcs_private_ip | Private IP address of the ADCS server |
| adcs_hostname | Hostname of the ADCS server |
| ndes_url | NDES enrollment URL for StrongDM configuration |
| ca_common_name | Common Name of the intermediate CA |
| certificate_template_name | Name of the StrongDM certificate template |
| domain_admin_user | Domain admin username for SDM_ADCS_USER |
| tagset | Tags applied to resources |

## StrongDM Gateway Configuration

After the ADCS/NDES server is deployed, configure StrongDM gateways and relays to use it for certificate-based authentication:

### Linux Gateways

Gateways and relays deployed in the domain automatically trust the domain CA and use AD DNS for name resolution. No manual certificate installation is required.

**Configure gateway environment variables**:
```bash
# Edit /etc/sysconfig/sdm-proxy
SDM_ADCS_URL=https://Europa-adcs.europa.local/certsrv/mscep/mscep.dll
SDM_ADCS_USER=Administrator@europa.local
SDM_ADCS_PW=<domain-admin-password>
```

**Note**: The NDES URL uses HTTPS with the server's FQDN. The gateway resolves this via AD DNS and trusts the certificate issued by the domain's root CA.

**Restart gateway**:
```bash
sudo systemctl restart sdm-proxy
```

### Verification

Check gateway logs for successful certificate enrollment:
```bash
sudo journalctl -u sdm-proxy -f | grep -i cert
```

Successful enrollment will show:
```
Certificate enrolled successfully via SCEP
Certificate issued by: Europa-SubCA
```

## Certificate Template Details

The `StrongDM` certificate template is configured with:

- **Based on**: Smart Card Logon template
- **Key Features**:
  - Allows subject name in certificate request (required for StrongDM)
  - Application policies: Smart Card Logon + Client Authentication
  - Key usage: Digital signature + Key encipherment
  - Key size: 2048-bit minimum
  - Validity: 1 year (default)
  - Exportable private keys
- **OIDs**:
  - `1.3.6.1.4.1.311.20.2.2` - Smart Card Logon
  - `1.3.6.1.5.5.7.3.2` - Client Authentication

## Deployment Timeline

The ADCS/NDES installation process involves two stages due to the domain join requirement:

1. **Initial Boot** (~5 minutes):
   - DNS configuration
   - Domain join
   - Scheduled task creation
   - Reboot

2. **Post-Reboot Installation** (~15-20 minutes):
   - ADCS role installation
   - Subordinate CA configuration
   - CA certificate request/installation
   - NDES installation and configuration
   - Certificate template creation
   - Registry and IIS configuration

**Total deployment time: ~20-25 minutes**

## Troubleshooting

### Check Installation Progress

```bash
# View installation logs on the ADCS server
Get-Content C:\ADCSSetup.log -Tail 50
```

### Common Issues

**1. Certificate request fails**
- Verify DC FQDN is correct
- Check network connectivity to DC
- Ensure root CA is online: `certutil -ping`

**2. NDES not accessible**
- Check IIS is running: `iisreset /status`
- Verify Basic Auth is enabled in IIS Manager
- Check Windows Firewall rules

**3. StrongDM gateway can't enroll**
- Verify NDES URL is correct
- Check gateway can reach ADCS server (HTTP port 80)
- Verify credentials (SDM_ADCS_USER/PW) are correct
- Ensure gateway trusts the CA certificate chain

**4. Template not found**
- Check template exists: `certutil -template StrongDM`
- Verify template was added to CA: `certutil -CATemplates`
- Restart CA service: `Restart-Service CertSvc`

### Useful Commands

```powershell
# Check CA status
certutil -ping

# List available templates
certutil -CATemplates

# View template details
certutil -v -template StrongDM

# Check NDES configuration
Get-ItemProperty "HKLM:\Software\Microsoft\Cryptography\MSCEP"

# Test SCEP endpoint
Invoke-WebRequest -Uri "http://localhost/certsrv/mscep/mscep.dll" -UseBasicParsing

# View CA issued certificates
certutil -view -restrict "Disposition=20" -out "Request.RequestID,CommonName,NotAfter"
```

## Security Considerations

1. **Service Account**: Currently uses domain admin for NDES. For production, create a dedicated service account with minimal permissions.

2. **Authentication**: Basic Authentication is used for SCEP. Consider enabling HTTPS for production deployments.

3. **Certificate Lifetime**: Default is 1 year. AD CS has a 1-hour minimum lifetime constraint.

4. **Challenge Password Cache**: Increased to 50 unredeemed passwords to support multiple gateways.

5. **Network Isolation**: Deploy ADCS in private subnet with restricted security group rules.

## Architecture Integration

This module is designed to work with:

- **DC Module**: Provides root CA and Active Directory domain
- **Network Module**: Provides VPC, subnets, and security groups
- **Gateway Module**: Consumes NDES URL for certificate enrollment
- **Relay Module**: Consumes NDES URL for certificate enrollment

## References

- [StrongDM ADCS Documentation](https://docs.strongdm.com/admin/secrets/certificate-authorities/adcs-ca)
- [Microsoft NDES Documentation](https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-network-device-enrollment-service)
- [SCEP Protocol RFC 8894](https://datatracker.ietf.org/doc/html/rfc8894)

## License

This module is part of the aws-lab-in-a-box project.

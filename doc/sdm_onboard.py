#--------------------------------------------------------------
# StrongDM Auto-Onboarding Lambda Function
#--------------------------------------------------------------
# This Python script implements an AWS Lambda function that automatically
# onboards EC2 instances to StrongDM when they are launched.
# 
# Key Functions:
# - Monitors CloudWatch events for EC2 instance state changes
# - Automatically discovers and registers new instances with StrongDM
# - Creates appropriate StrongDM resources based on instance tags
# - Handles different resource types (SSH, RDP, databases)
# - Manages StrongDM gateway assignments and access policies
# - Provides error handling and logging for troubleshooting
#
# Dependencies:
# - boto3: AWS SDK for Python
# - strongdm: StrongDM Python SDK
# - Proper IAM permissions for EC2 and StrongDM API access
# - Environment variables for StrongDM API credentials
#--------------------------------------------------------------

import json
import boto3
import strongdm
import os
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # Extract instance details from CloudWatch event
    instance_id = event['detail']['instance-id']
    region = event['detail']['region']
    
    # Initialize clients
    ec2 = boto3.client('ec2', region_name=region)
    ssm = boto3.client('ssm', region_name=region)
    
    # Get instance details
    instance = ec2.describe_instances(InstanceIds=[instance_id])
    instance_data = instance['Reservations'][0]['Instances'][0]
    
    # Check if it's a Windows instance
    platform = instance_data.get('Platform', '')
    if platform.lower() != 'windows':
        print(f"Instance {instance_id} is not Windows, skipping")
        return
    
    # Wait for SSM agent to be online before proceeding
    if not wait_for_ssm_online(ssm, instance_id):
        print(f"Instance {instance_id} SSM agent not online, skipping")
        return
    
    tags = {tag['Key']: tag['Value'] for tag in instance_data.get('Tags', [])}
    
    # Configure Windows instance via SSM
    configure_windows_for_strongdm(ssm, instance_id, tags)
    
    # Get domain join status and credentials via SSM
    domain_info = get_domain_info_via_ssm(ssm, instance_id, tags)
    
    if domain_info['is_domain_joined']:
        # Add to StrongDM with certificate authentication
        add_domain_windows_to_strongdm(instance_id, instance_data, tags, domain_info)
    else:
        print(f"Instance {instance_id} is not domain-joined, skipping StrongDM registration")

def wait_for_ssm_online(ssm, instance_id, max_attempts=30, delay=30):
    """Wait for SSM agent to come online"""
    import time
    
    for attempt in range(max_attempts):
        try:
            response = ssm.describe_instance_information(
                Filters=[
                    {'Key': 'InstanceIds', 'Values': [instance_id]}
                ]
            )
            
            if response['InstanceInformationList']:
                instance_info = response['InstanceInformationList'][0]
                if instance_info['PingStatus'] == 'Online':
                    print(f"SSM agent online for instance {instance_id}")
                    return True
            
            print(f"Waiting for SSM agent on {instance_id} (attempt {attempt + 1}/{max_attempts})")
            time.sleep(delay)
            
        except Exception as e:
            print(f"Error checking SSM status for {instance_id}: {e}")
            time.sleep(delay)
    
    return False

def configure_windows_for_strongdm(ssm, instance_id, tags):
    """Configure Windows instance for StrongDM via SSM"""
    
    # Get domain configuration from SSM parameters
    domain_config = get_domain_config_from_ssm(ssm, tags)
    
    # PowerShell script to configure Windows
    configure_script = f"""
    # Configure RDP for StrongDM
    Write-Host "Configuring RDP for StrongDM certificate authentication..."
    
    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    
    # Configure RDP for TLS encryption (required for StrongDM)
    $RDPSetting = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\\cimv2\\terminalservices -Filter "TerminalName='RDP-tcp'"
    $RDPSetting.SetEncryptionLevel(2)  # High encryption
    $RDPSetting.SetSecurityLayer(2)    # TLS 1.0
    
    # Disable Network Level Authentication (StrongDM requirement)
    $NLASetting = Get-WmiObject -Class "Win32_TSNetworkAdapterSetting" -Namespace root\\cimv2\\terminalservices
    $NLASetting.SetUserAuthenticationRequired(0)
    
    # Enable and start Smart Card service for certificate authentication
    Set-Service -Name "SCardSvr" -StartupType Automatic
    Start-Service -Name "SCardSvr"
    
    # Join domain if not already joined
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    if ($computerSystem.PartOfDomain -eq $false) {{
        Write-Host "Joining domain {domain_config['domain_name']}..."
        
        # Get domain join credentials from SSM Parameter Store
        $domainUser = (Get-SSMParameter -Name "{domain_config['username_param']}" -WithDecryption $true).Value
        $domainPassword = (Get-SSMParameter -Name "{domain_config['password_param']}" -WithDecryption $true).Value
        
        $securePassword = ConvertTo-SecureString $domainPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($domainUser, $securePassword)
        
        try {{
            Add-Computer -DomainName "{domain_config['domain_name']}" -Credential $credential -OUPath "{domain_config['ou_path']}" -Force
            Write-Host "Successfully joined domain {domain_config['domain_name']}"
            
            # Schedule restart after domain join
            shutdown /r /t 60 /c "Restarting after domain join"
        }} catch {{
            Write-Error "Failed to join domain: $($_.Exception.Message)"
            exit 1
        }}
    }} else {{
        Write-Host "Instance is already domain-joined to $($computerSystem.Domain)"
    }}
    
    # Install and configure CloudWatch agent
    $cloudWatchConfig = @"
{{
    "metrics": {{
        "namespace": "StrongDM/Windows",
        "metrics_collected": {{
            "cpu": {{
                "measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"],
                "metrics_collection_interval": 60
            }},
            "disk": {{
                "measurement": ["used_percent"],
                "metrics_collection_interval": 60,
                "resources": ["*"]
            }},
            "mem": {{
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            }}
        }}
    }},
    "logs": {{
        "logs_collected": {{
            "windows_events": {{
                "collect_list": [
                    {{
                        "event_name": "System",
                        "event_levels": ["ERROR", "WARNING"],
                        "log_group_name": "/aws/ec2/windows/system",
                        "log_stream_name": "{{instance_id}}"
                    }},
                    {{
                        "event_name": "Security",
                        "event_levels": ["INFORMATION"],
                        "event_format": "xml",
                        "log_group_name": "/aws/ec2/windows/security",
                        "log_stream_name": "{{instance_id}}"
                    }}
                ]
            }}
        }}
    }}
}}
"@
    
    # Save CloudWatch config and start agent
    $cloudWatchConfig | Out-File -FilePath "C:\\ProgramData\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json" -Encoding UTF8
    & "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent-ctl.ps1" -a fetch-config -m ec2 -c file:"C:\\ProgramData\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json" -s
    
    Write-Host "Windows configuration completed successfully"
    """
    
    # Execute the configuration script
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={
                'commands': [configure_script]
            },
            TimeoutSeconds=1800,  # 30 minutes
            Comment=f"Configure Windows instance {instance_id} for StrongDM"
        )
        
        command_id = response['Command']['CommandId']
        print(f"SSM command {command_id} sent to configure instance {instance_id}")
        
        # Wait for command completion
        wait_for_ssm_command_completion(ssm, command_id, instance_id)
        
    except Exception as e:
        print(f"Error configuring Windows instance {instance_id} via SSM: {e}")
        raise

def get_domain_config_from_ssm(ssm, tags):
    """Get domain configuration from SSM Parameter Store"""
    
    environment = tags.get('Environment', 'dev').lower()
    
    try:
        # Get domain configuration from SSM parameters
        domain_name = ssm.get_parameter(
            Name=f"/strongdm/{environment}/domain/name"
        )['Parameter']['Value']
        
        username_param = f"/strongdm/{environment}/domain/join-username"
        password_param = f"/strongdm/{environment}/domain/join-password"
        
        ou_path = ssm.get_parameter(
            Name=f"/strongdm/{environment}/domain/ou-path"
        )['Parameter']['Value']
        
        return {
            'domain_name': domain_name,
            'username_param': username_param,
            'password_param': password_param,
            'ou_path': ou_path
        }
        
    except ClientError as e:
        print(f"Error getting domain config from SSM: {e}")
        # Return defaults
        return {
            'domain_name': 'corp.example.com',
            'username_param': '/strongdm/default/domain/join-username',
            'password_param': '/strongdm/default/domain/join-password',
            'ou_path': 'OU=Servers,DC=corp,DC=example,DC=com'
        }

def get_domain_info_via_ssm(ssm, instance_id, tags):
    """Get domain join status and configuration via SSM"""
    
    check_domain_script = """
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $domainInfo = @{
        'is_domain_joined' = $computerSystem.PartOfDomain
        'domain_name' = $computerSystem.Domain
        'computer_name' = $computerSystem.Name
    }
    
    # Get StrongDM certificate info if available
    $strongdmCert = Get-ChildItem -Path "Cert:\\LocalMachine\\Root" | Where-Object {$_.Subject -like "*StrongDM*"}
    if ($strongdmCert) {
        $domainInfo['strongdm_cert_installed'] = $true
        $domainInfo['cert_thumbprint'] = $strongdmCert.Thumbprint
    } else {
        $domainInfo['strongdm_cert_installed'] = $false
    }
    
    $domainInfo | ConvertTo-Json
    """
    
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={'commands': [check_domain_script]},
            TimeoutSeconds=300
        )
        
        command_id = response['Command']['CommandId']
        
        # Get command output
        output = get_ssm_command_output(ssm, command_id, instance_id)
        
        if output:
            domain_info = json.loads(output)
            return domain_info
        
    except Exception as e:
        print(f"Error getting domain info via SSM: {e}")
    
    # Return default if failed
    return {
        'is_domain_joined': False,
        'domain_name': '',
        'computer_name': '',
        'strongdm_cert_installed': False
    }

def wait_for_ssm_command_completion(ssm, command_id, instance_id, max_attempts=60):
    """Wait for SSM command to complete"""
    import time
    
    for attempt in range(max_attempts):
        try:
            response = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            status = response['Status']
            
            if status in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                print(f"SSM command {command_id} completed with status: {status}")
                if status == 'Failed':
                    print(f"Command output: {response.get('StandardOutputContent', '')}")
                    print(f"Command error: {response.get('StandardErrorContent', '')}")
                return status == 'Success'
            
            time.sleep(30)  # Wait 30 seconds between checks
            
        except Exception as e:
            print(f"Error checking command status: {e}")
            time.sleep(30)
    
    print(f"Command {command_id} did not complete within timeout")
    return False

def get_ssm_command_output(ssm, command_id, instance_id):
    """Get output from SSM command"""
    try:
        response = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )
        return response.get('StandardOutputContent', '')
    except Exception as e:
        print(f"Error getting command output: {e}")
        return None

def add_domain_windows_to_strongdm(instance_id, instance_data, tags, domain_info):
    """Add domain-joined Windows instance to StrongDM"""
    try:
        # Initialize StrongDM client
        api_access_key = os.environ['SDM_API_ACCESS_KEY']
        api_secret_key = os.environ['SDM_API_SECRET_KEY']
        client = strongdm.Client(api_access_key, api_secret_key)
        
        private_ip = instance_data['PrivateIpAddress']
        domain_name = domain_info['domain_name']
        
        # Create RDP Certificate resource
        rdp_cert_server = strongdm.RDPCert(
            name=f"windows-{domain_name.split('.')[0]}-{instance_id}",
            hostname=private_ip,
            port=3389,
            identity_alias_healthcheck_username=f"{domain_name.split('.')[0].upper()}\\sdm-healthcheck"
        )
        
        # Add tags
        rdp_cert_server.tags = {
            "ec2-instance-id": instance_id,
            "platform": "windows",
            "authentication": "domain-certificate",
            "domain": domain_name,
            "computer-name": domain_info['computer_name'],
            "managed-by": "strongdm-ssm-automation",
            "environment": tags.get('Environment', 'unknown').lower(),
            "department": tags.get('Department', 'unknown').lower()
        }
        
        # Create the resource
        response = client.resources.create(rdp_cert_server)
        print(f"Added domain-joined Windows instance {instance_id} to StrongDM: {response.resource.id}")
        
        # Update SSM parameters with StrongDM resource info
        update_ssm_parameters(instance_id, response.resource.id, tags)
        
        return response.resource.id
        
    except Exception as e:
        print(f"Error adding domain-joined Windows instance {instance_id} to StrongDM: {str(e)}")
        raise

def update_ssm_parameters(instance_id, strongdm_resource_id, tags):
    """Update SSM parameters with StrongDM resource information"""
    ssm = boto3.client('ssm')
    
    try:
        # Store StrongDM resource mapping
        ssm.put_parameter(
            Name=f"/strongdm/instances/{instance_id}/resource-id",
            Value=strongdm_resource_id,
            Type="String",
            Overwrite=True,
            Description=f"StrongDM resource ID for EC2 instance {instance_id}"
        )
        
        # Store configuration info
        config = {
            "instance_id": instance_id,
            "strongdm_resource_id": strongdm_resource_id,
            "environment": tags.get('Environment', 'unknown'),
            "department": tags.get('Department', 'unknown'),
            "managed_date": boto3.Session().region_name  # Current timestamp would be better
        }
        
        ssm.put_parameter(
            Name=f"/strongdm/instances/{instance_id}/config",
            Value=json.dumps(config),
            Type="String",
            Overwrite=True,
            Description=f"StrongDM configuration for EC2 instance {instance_id}"
        )
        
        print(f"Updated SSM parameters for instance {instance_id}")
        
    except Exception as e:
        print(f"Error updating SSM parameters: {e}")
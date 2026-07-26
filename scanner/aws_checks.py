import boto3
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

class AWSScanner:
    def __init__(self, region_name="us-east-1"):
        self.region = region_name
        self.s3_client = boto3.client('s3', region_name=self.region)
        self.iam_client = boto3.client('iam', region_name=self.region)
        self.ec2_client = boto3.client('ec2', region_name=self.region)
        self.findings = []

    def scan_s3_buckets(self):
        print("[*] Scanning S3 Buckets for public access...")
        try:
            response = self.s3_client.list_buckets()
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                try:
                    pa_config = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pa_config.get('PublicAccessBlockConfiguration', {})
                    if not all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'), 
                                config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                        self.findings.append({
                            "Category": "S3",
                            "Resource": bucket_name,
                            "Issue": "Bucket lacks complete Public Access Block configurations."
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlock':
                        self.findings.append({
                            "Category": "S3",
                            "Resource": bucket_name,
                            "Issue": "Bucket has NO Public Access Block configured (High Risk)."
                        })
        except Exception as e:
            print(f"[!] Error scanning S3 (Live API): {e}")

    def scan_iam_roles(self):
        print("[*] Scanning IAM Roles for AdministratorAccess...")
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for response in paginator.paginate():
                for role in response.get('Roles', []):
                    role_name = role['RoleName']
                    attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies.get('AttachedPolicies', []):
                        if policy['PolicyName'] == 'AdministratorAccess':
                            self.findings.append({
                                "Category": "IAM",
                                "Resource": role_name,
                                "Issue": "Role has AWS managed 'AdministratorAccess' policy attached."
                            })
        except Exception as e:
            print(f"[!] Error scanning IAM (Live API): {e}")

    def scan_privilege_escalation(self):
        print("[*] Scanning IAM Policies/Roles for Privilege Escalation vectors...")
        try:
            paginator = self.iam_client.get_paginator('list_policies')
            for response in paginator.paginate(Scope='Local'):
                for policy in response.get('Policies', []):
                    policy_arn = policy['Arn']
                    policy_name = policy['PolicyName']
                    default_version_id = policy['DefaultVersionId']
                    
                    version_resp = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version_id
                    )
                    document = version_resp.get('PolicyVersion', {}).get('Document', {})
                    
                    for statement in document.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            dangerous_perms = ['iam:CreateAccessKey', 'iam:UpdateAssumeRolePolicy', 'sts:AssumeRole', '*']
                            for perm in dangerous_perms:
                                if perm in actions or any(a.endswith('*') and ('iam' in a or 'sts' in a) for a in actions):
                                    self.findings.append({
                                        "Category": "IAM-PrivEsc",
                                        "Resource": policy_name,
                                        "Issue": f"Custom policy contains potential privilege escalation vector ({perm})."
                                    })
        except Exception as e:
            print(f"[!] Error scanning Privilege Escalation (Live API): {e}")

    def scan_ec2_instances(self):
        print("[*] Scanning EC2 Instances for public IPs and IMDSv1 configurations...")
        try:
            response = self.ec2_client.describe_instances()
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    public_ip = instance.get('PublicIpAddress')
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', 'optional') # optional = IMDSv1 enabled
                    
                    # Flag if instance is public AND has vulnerable metadata options (IMDSv1)
                    if public_ip and http_tokens == 'optional':
                        self.findings.append({
                            "Category": "EC2-Compute",
                            "Resource": instance_id,
                            "Issue": "Public EC2 instance allows IMDSv1 (Metadata Service v1), vulnerable to SSRF credential theft."
                        })
        except Exception as e:
            print(f"[!] Error scanning EC2 Instances (Live API): {e}")

    def scan_security_groups(self):
        print("[*] Scanning EC2 Security Groups for exposed ports (SSH/RDP)...")
        try:
            response = self.ec2_client.describe_security_groups()
            for sg in response.get('SecurityGroups', []):
                sg_name = sg['GroupName']
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                                self.findings.append({
                                    "Category": "EC2/Network",
                                    "Resource": sg_name,
                                    "Issue": f"Security Group allows global access (0.0.0.0/0) to sensitive ports (SSH/RDP)."
                                })
        except Exception as e:
            print(f"[!] Error scanning Security Groups (Live API): {e}")

    def run_demo_scan(self):
        print("[*] Running in OFFLINE DEMO mode with mock data...")
        self.findings = [
            {"Category": "S3", "Resource": "company-backup-logs-2026", "Issue": "Bucket has NO Public Access Block configured (High Risk)."},
            {"Category": "IAM", "Resource": "DevOps-Automation-Role", "Issue": "Role has AWS managed 'AdministratorAccess' policy attached."},
            {"Category": "IAM-PrivEsc", "Resource": "CI-CD-Deployer-Policy", "Issue": "Custom policy contains potential privilege escalation vector (iam:UpdateAssumeRolePolicy)."},
            {"Category": "EC2-Compute", "Resource": "i-0abcd1234ef567890", "Issue": "Public EC2 instance allows IMDSv1 (Metadata Service v1), vulnerable to SSRF credential theft."},
            {"Category": "EC2/Network", "Resource": "legacy-jumpbox-sg", "Issue": "Security Group allows global access (0.0.0.0/0) to sensitive ports (SSH/RDP)."},
            {"Category": "S3", "Resource": "internal-hr-documents-prod", "Issue": "Bucket lacks complete Public Access Block configurations."}
        ]
        return self.findings

    def run_all_scans(self):
        self.scan_s3_buckets()
        self.scan_iam_roles()
        self.scan_privilege_escalation()
        self.scan_ec2_instances()
        self.scan_security_groups()
        return self.findings

def run_aws_scans(demo_mode=False, region="us-east-1"):
    """Orchestrates the scanner and standardizes findings for reporters."""
    scanner = AWSScanner(region_name=region)
    
    if demo_mode:
        raw_findings = scanner.run_demo_scan()
    else:
        raw_findings = scanner.run_all_scans()
        
    standardized_findings = []
    for f in raw_findings:
        category = f.get("Category", "General")
        issue = f.get("Issue", "")
        
        if "High Risk" in issue or "AdministratorAccess" in issue or "Privilege Escalation" in issue or "IMDSv1" in issue:
            severity = "HIGH"
            remediation = "Enforce IMDSv2 (require tokens), remove unnecessary public IPs, and restrict risky permissions."
        elif "0.0.0.0/0" in issue:
            severity = "HIGH"
            remediation = "Restrict security group inbound rules to trusted IP ranges (VPN/Bastion)."
        else:
            severity = "MEDIUM"
            remediation = "Review resource configuration policies to enforce strict compliance."

        standardized_findings.append({
            "check": f"{category} Misconfiguration Audit",
            "category": category,
            "resource": f.get("Resource", "Unknown"),
            "description": issue,
            "severity": severity,
            "remediation": remediation
        })
        
    return standardized_findings


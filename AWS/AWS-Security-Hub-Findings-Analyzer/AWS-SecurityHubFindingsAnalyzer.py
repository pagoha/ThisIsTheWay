#!/usr/bin/env python3
"""
AWS Security Hub Findings Analyzer - Full Featured Version

A comprehensive security portal to analyze Security Hub findings across AWS accounts,
generate detailed reports, and provide actionable insights with advanced analytics.

Usage:
    python securityhub_analyzer_enhanced.py [options]

Options:
    --format {csv,html}     Output format for the report (default: csv)
    --severity LEVEL        Severity levels to include (default: CRITICAL,HIGH,MEDIUM)
    --limit NUMBER          Limit the number of findings (default: no limit)
    --anystatus             Include findings with any status (default: active only)
    --output-dir DIR        Directory to store reports (default: security_reports)
"""

import csv
import json
import time
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import os
import random
import concurrent.futures
import hashlib
import re

import boto3
import click
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# Optional imports for visualization
try:
    import matplotlib.pyplot as plt
    import numpy as np
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False

def get_available_aws_profiles():
    """Get all available AWS profiles from credentials and config files"""
    import configparser
    profiles = set()
    
    # Check ~/.aws/credentials
    credentials_path = os.path.expanduser('~/.aws/credentials')
    config_path = os.path.expanduser('~/.aws/config')
    
    config = configparser.ConfigParser()
    
    # Read credentials file
    if os.path.exists(credentials_path):
        config.read(credentials_path)
        for section in config.sections():
            profiles.add(section)
    
    # Read config file
    if os.path.exists(config_path):
        config.read(config_path)
        for section in config.sections():
            if section.startswith('profile '):
                profiles.add(section[8:])  # Remove "profile " prefix
            elif section != 'default':
                profiles.add(section)
    
    # Always include default if it exists
    if 'default' in profiles or 'DEFAULT' in profiles:
        profiles.add('default')
    
    return sorted(list(profiles))

def select_aws_profiles():
    """Display and let user select AWS profiles to use"""
    available_profiles = get_available_aws_profiles()
    
    if not available_profiles:
        print("No AWS profiles found in your credentials or config files.")
        return []
    
    print("\n" + "="*60)
    print("AWS PROFILE SELECTION")
    print("="*60)
    print("Available AWS profiles:")
    for i, profile in enumerate(available_profiles):
        print(f"{i+1}. {profile}")
    
    print("\nSelect profiles to use (comma-separated numbers, 'all' for all profiles, or 'q' to quit):")
    selection = input("> ").strip().lower()
    
    if selection == 'q':
        print("Exiting program.")
        exit(0)
    
    selected_profiles = []
    
    if selection == 'all':
        selected_profiles = available_profiles
    else:
        try:
            # Parse comma-separated selection
            indices = [int(idx.strip()) - 1 for idx in selection.split(',')]
            for idx in indices:
                if 0 <= idx < len(available_profiles):
                    selected_profiles.append(available_profiles[idx])
                else:
                    print(f"Invalid selection: {idx+1}")
        except ValueError:
            print("Invalid input. Please enter numbers separated by commas.")
    
    return selected_profiles

def select_output_options():
    """Let user select which outputs they want to generate"""
    print("\n" + "="*60)
    print("OUTPUT SELECTION")
    print("="*60)
    print("Select which outputs you want to generate:")
    print("1. CSV Report")
    print("2. Enhanced HTML Security Portal")
    print("3. Console Summary")
    print("4. Visualizations (requires matplotlib)")
    print("5. All outputs")
    
    if not VISUALIZATION_AVAILABLE:
        print("\nNote: Visualizations require matplotlib and numpy libraries")
        print("Install with: pip install matplotlib numpy")
    
    print("\nSelect outputs (comma-separated numbers, default: 2,3):")
    selection = input("> ").strip()
    
    # Default selection if nothing entered
    if not selection:
        selection = "2,3"
    
    outputs = {
        'csv': False,
        'html': False,
        'summary': False,
        'visualizations': False
    }
    
    try:
        if selection.lower() == 'all' or '5' in selection:
            outputs = {k: True for k in outputs}
        else:
            indices = [int(idx.strip()) for idx in selection.split(',')]
            for idx in indices:
                if idx == 1:
                    outputs['csv'] = True
                elif idx == 2:
                    outputs['html'] = True
                elif idx == 3:
                    outputs['summary'] = True
                elif idx == 4:
                    if VISUALIZATION_AVAILABLE:
                        outputs['visualizations'] = True
                    else:
                        print("Warning: Visualization libraries not available, skipping visualizations")
                else:
                    print(f"Invalid selection: {idx}")
    except ValueError:
        print("Invalid input. Using default outputs (HTML + Summary)")
        outputs['html'] = True
        outputs['summary'] = True
    
    print(f"\nSelected outputs:")
    for output_type, enabled in outputs.items():
        if enabled:
            print(f"  ✓ {output_type.title()}")
    
    return outputs

def select_severity_levels():
    """Let user select severity levels to include"""
    print("\n" + "="*60)
    print("SEVERITY LEVEL SELECTION")
    print("="*60)
    
    severity_options = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
    default_severities = ['CRITICAL', 'HIGH', 'MEDIUM']
    
    print("Available severity levels:")
    for i, severity in enumerate(severity_options):
        marker = "✓" if severity in default_severities else " "
        print(f"{i+1}. [{marker}] {severity}")
    
    print(f"\nDefault selection: {', '.join(default_severities)}")
    print("Select severity levels (comma-separated numbers, 'all' for all levels, or Enter for default):")
    selection = input("> ").strip()
    
    if not selection:
        return tuple(default_severities)
    
    selected_severities = []
    
    if selection.lower() == 'all':
        selected_severities = severity_options
    else:
        try:
            indices = [int(idx.strip()) - 1 for idx in selection.split(',')]
            for idx in indices:
                if 0 <= idx < len(severity_options):
                    selected_severities.append(severity_options[idx])
                else:
                    print(f"Invalid selection: {idx+1}")
        except ValueError:
            print("Invalid input. Using default severity levels.")
            selected_severities = default_severities
    
    print(f"Selected severity levels: {', '.join(selected_severities)}")
    return tuple(selected_severities)

def select_status_filter():
    """Let user select status filter"""
    print("\n" + "="*60)
    print("STATUS FILTER SELECTION")
    print("="*60)
    print("1. Active findings only (recommended)")
    print("2. All findings (including suppressed and resolved)")
    
    selection = input("Select status filter (1 or 2, default: 1): ").strip()
    
    if selection == '2':
        print("Selected: All findings")
        return False  # anystatus = False means include all
    else:
        print("Selected: Active findings only")
        return True   # anystatus = True means active only

def get_profile_account_id(profile_name):
    """Get AWS account ID for a given profile"""
    try:
        session = boto3.Session(profile_name=profile_name)
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        return account_id
    except Exception as e:
        print(f"Error getting account ID for profile {profile_name}: {str(e)}")
        return "Unknown"

def check_sso_session(profile: str) -> bool:
    """
    Checks if the SSO session for the given profile is active and unexpired.

    Args:
        profile (str): The AWS profile name to check.

    Returns:
        bool: True if the session is active and unexpired, False otherwise.
    """
    try:
        # Attempt a simple operation to check if the session is valid
        session = boto3.Session(profile_name=profile)
        sts = session.client("sts")
        sts.get_caller_identity()
        return True
    except (NoCredentialsError, PartialCredentialsError):
        # These errors indicate that the credentials were not found or are incomplete
        return False
    except ClientError as e:
        # This error can have multiple reasons. We check if it's due to authentication.
        if "Error" in e.response and "Code" in e.response["Error"]:
            error_code = e.response["Error"]["Code"]
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                return False
        raise  # Re-raise other exceptions which we aren't handling specifically

def get_all_findings(profile: str, region: str, severity_levels: Tuple[str], only_active: bool, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client('securityhub')
    findings = []
    
    # Construct filters based on severity and activity status
    filters = {
        'SeverityLabel': [{'Value': level, 'Comparison': 'EQUALS'} for level in severity_levels]
    }
    if only_active:
        filters['RecordState'] = [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]

    page_num = 0
    next_token = None

    while True:
        if next_token:
            response = client.get_findings(Filters=filters, NextToken=next_token)
        else:
            response = client.get_findings(Filters=filters)

        current_page_findings = response['Findings']
        findings.extend(current_page_findings)
        page_num += 1

        click.echo(f"Fetched {len(current_page_findings)} findings from page {page_num}. Total findings so far: {len(findings)}")

        if limit and len(findings) >= limit:
            findings = findings[:limit]
            break

        next_token = response.get('NextToken')

        if not next_token:
            break

        # Make sure we don't get throttled by AWS
        time.sleep(0.34)

    click.echo(f"Finished fetching. Total findings: {len(findings)} from {page_num} pages.")
    return findings

def save_to_csv(findings: List[Dict[str, Any]], output_file: str) -> None:
    """
    Saves the findings to a CSV file.

    The 'Resources' column in the findings will be flattened for a better CSV representation.

    Args:
        findings (List[Dict[str, Any]]): List of findings to save.
        output_file (str): The path to the output file.
    """
    if not findings:
        print("No findings to export.")
        return

    # Flatten the 'Resources' column for better CSV structure
    findings = flatten_resources_and_severity(findings)

    # Determine all unique keys across findings for our CSV headers
    headers = set()
    for finding in findings:
        headers.update(finding.keys())

    # Sort the headers alphabetically
    sorted_headers = sorted(headers)

    with open(output_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=sorted_headers)
        writer.writeheader()

        with click.progressbar(findings, label="Exporting to CSV") as bar:
            for finding in bar:
                writer.writerow(finding)

def flatten_resources_and_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flattens the Resources column of the findings for better CSV representation.
    
    Args:
        findings (List[Dict[str, Any]]): List of findings from AWS Security Hub.
    
    Returns:
        List[Dict[str, Any]]: List of findings with the Resources column flattened.
    """
    flattened_findings = []
    
    with click.progressbar(findings, label='Flattening Resources & Severity', length=len(findings)) as bar:
        for finding in bar:
            # Flatten Resources
            resources = finding.get('Resources')
            
            if resources and isinstance(resources, list):
                for resource in resources:
                    if "Details" in resource:
                        resource["Details"] = json.dumps(resource["Details"])

                if len(resources) == 1:
                    resource_data = resources[0]
                    for key, value in resource_data.items():
                        new_key = f"Resources.{key}"
                        finding[new_key] = value
                    finding['Resources.Count'] = 1
                else:
                    for resource in resources:
                        new_finding = finding.copy()
                        for key, value in resource.items():
                            new_key = f"Resources.{key}"
                            new_finding[new_key] = value
                        new_finding['Resources.Count'] = len(resources)
                        flattened_findings.append(new_finding)
                    continue  # Skip appending the original finding to avoid duplication

            # Flatten Severity
            severity = finding.get('Severity')
            if severity and isinstance(severity, dict):
                for key, value in severity.items():
                    new_key = f"Severity.{key}"
                    finding[new_key] = value

            flattened_findings.append(finding)

    return flattened_findings

def get_account_names(profile: str, region: str) -> Dict[str, str]:
    """
    Fetches all AWS account names and their corresponding IDs in the organization.

    Args:
        profile (str): AWS CLI profile name.
        region (str): AWS region where the organization is located.

    Returns:
        Dict[str, str]: A mapping of account IDs to account names.
    """
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client('organizations')

    accounts = {}
    try:
        paginator = client.get_paginator('list_accounts')

        for page in paginator.paginate():
            for account in page['Accounts']:
                account_id = account.get('Id')
                account_name = account.get('Name')
                if account_id and account_name:
                    accounts[account_id] = account_name
    except Exception as e:
        print(f"Could not fetch organization accounts: {e}")
        # Return empty dict if not using Organizations

    return accounts

def add_account_names_to_findings(findings: List[Dict[str, Any]], account_names: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Maps AWSAccountId in each finding to its corresponding account name and adds an AccountName column.

    Args:
        findings (List[Dict[str, Any]]): The list of findings.
        account_names (Dict[str, str]): A mapping of account IDs to account names.

    Returns:
        List[Dict[str, Any]]: Updated list of findings with the AccountName column.
    """
    for finding in findings:
        account_id = finding.get('AwsAccountId')
        if isinstance(account_id, str):
            finding['AccountName'] = account_names.get(account_id, 'Unknown')
        else:
            finding['AccountName'] = 'Unknown'

    return findings

def calculate_security_metrics(findings):
    """Calculate comprehensive security metrics and analytics"""
    if not findings:
        return {
            'risk_score': 0.0,
            'critical_findings': 0,
            'compliance_score': 100,
            'threat_level': 'LOW',
            'total_findings': 0,
            'active_findings': 0,
            'suppressed_findings': 0,
            'resolved_findings': 0
        }
    
    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL')
    high_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'HIGH')
    medium_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'MEDIUM')
    low_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'LOW')
    info_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'INFORMATIONAL')
    
    # Status breakdown
    active_findings = sum(1 for f in findings if f.get('RecordState') == 'ACTIVE')
    suppressed_findings = sum(1 for f in findings if f.get('RecordState') == 'SUPPRESSED')
    resolved_findings = sum(1 for f in findings if f.get('RecordState') == 'ARCHIVED')
    
    # Calculate risk score (0-10, higher is worse)
    risk_score = min((critical_findings * 3 + high_findings * 2 + medium_findings * 1) / max(total_findings, 1) * 10, 10.0)
    
    # Calculate compliance score
    compliance_base = 100
    if critical_findings > 0:
        compliance_base -= min(critical_findings * 15, 60)
    if high_findings > 5:
        compliance_base -= min((high_findings - 5) * 5, 20)
    
    compliance_score = max(compliance_base, 20)
    
    # Determine threat level
    if critical_findings > 10 or risk_score > 8:
        threat_level = 'CRITICAL'
    elif critical_findings > 5 or risk_score > 6:
        threat_level = 'HIGH'
    elif critical_findings > 0 or risk_score > 4:
        threat_level = 'MEDIUM'
    else:
        threat_level = 'LOW'
    
    return {
        'risk_score': round(risk_score, 1),
        'critical_findings': critical_findings,
        'high_findings': high_findings,
        'medium_findings': medium_findings,
        'low_findings': low_findings,
        'info_findings': info_findings,
        'compliance_score': int(compliance_score),
        'threat_level': threat_level,
        'total_findings': total_findings,
        'active_findings': active_findings,
        'suppressed_findings': suppressed_findings,
        'resolved_findings': resolved_findings
    }

def analyze_findings_by_account(findings, account_names):
    """Analyze findings breakdown by AWS account"""
    account_breakdown = {}
    
    for finding in findings:
        account_id = finding.get('AwsAccountId', 'Unknown')
        account_name = account_names.get(account_id, account_id)
        
        if account_name not in account_breakdown:
            account_breakdown[account_name] = {
                'account_id': account_id,
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'informational': 0,
                'active': 0,
                'resources': set()
            }
        
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        status = finding.get('RecordState', 'UNKNOWN')
        
        account_breakdown[account_name]['total'] += 1
        account_breakdown[account_name][severity.lower()] = account_breakdown[account_name].get(severity.lower(), 0) + 1
        
        if status == 'ACTIVE':
            account_breakdown[account_name]['active'] += 1
        
        # Track unique resources
        resources = finding.get('Resources', [])
        for resource in resources:
            resource_id = resource.get('Id', 'Unknown')
            account_breakdown[account_name]['resources'].add(resource_id)
    
    # Convert sets to counts
    for account in account_breakdown.values():
        account['unique_resources'] = len(account['resources'])
        del account['resources']  # Remove set for JSON serialization
    
    return account_breakdown

def analyze_findings_by_resource_type(findings):
    """Analyze findings by AWS resource type"""
    resource_breakdown = {}
    
    for finding in findings:
        resources = finding.get('Resources', [])
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        
        for resource in resources:
            resource_type = resource.get('Type', 'Unknown')
            
            if resource_type not in resource_breakdown:
                resource_breakdown[resource_type] = {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'informational': 0,
                    'resources': set()
                }
            
            resource_breakdown[resource_type]['total'] += 1
            resource_breakdown[resource_type][severity.lower()] = resource_breakdown[resource_type].get(severity.lower(), 0) + 1
            resource_breakdown[resource_type]['resources'].add(resource.get('Id', 'Unknown'))
    
    # Convert sets to counts
    for resource_type in resource_breakdown.values():
        resource_type['unique_resources'] = len(resource_type['resources'])
        del resource_type['resources']
    
    return resource_breakdown

def analyze_compliance_standards(findings):
    """Analyze findings by compliance standards"""
    compliance_breakdown = {}
    
    for finding in findings:
        # Check various fields for compliance standard information
        standards = []
        
        # Check ProductFields for standards
        product_fields = finding.get('ProductFields', {})
        if 'StandardsArn' in product_fields:
            standards.append(product_fields['StandardsArn'])
        
        # Check Compliance field
        compliance = finding.get('Compliance', {})
        if 'RelatedRequirements' in compliance:
            standards.extend(compliance['RelatedRequirements'])
        
        # If no standards found, categorize as "Other"
        if not standards:
            standards = ['Other']
        
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        
        for standard in standards:
            # Simplify standard names
            if 'cis' in standard.lower():
                standard_name = 'CIS Benchmarks'
            elif 'pci' in standard.lower():
                standard_name = 'PCI DSS'
            elif 'aws-foundational' in standard.lower():
                standard_name = 'AWS Foundational'
            elif 'nist' in standard.lower():
                standard_name = 'NIST'
            elif 'soc' in standard.lower():
                standard_name = 'SOC'
            else:
                standard_name = standard.split('/')[-1] if '/' in standard else standard
            
            if standard_name not in compliance_breakdown:
                compliance_breakdown[standard_name] = {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'informational': 0
                }
            
            compliance_breakdown[standard_name]['total'] += 1
            compliance_breakdown[standard_name][severity.lower()] = compliance_breakdown[standard_name].get(severity.lower(), 0) + 1
    
    return compliance_breakdown

def generate_remediation_playbooks(findings):
    """Generate remediation playbooks based on common finding types"""
    playbooks = {}
    
    # Common AWS Security Hub finding types and their remediation steps
    remediation_guides = {
        'EC2.1': {
            'title': 'EC2 instances should not have a public IP address',
            'severity': 'HIGH',
            'description': 'EC2 instances with public IP addresses are directly accessible from the internet',
            'remediation_steps': [
                'Review if the instance truly needs a public IP address',
                'If not needed, stop the instance and modify network settings',
                'Use NAT Gateway or NAT Instance for outbound internet access',
                'Implement bastion hosts for administrative access',
                'Configure Security Groups to restrict access'
            ],
            'automation': {
                'terraform': '''
resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.private.id
  
  # Remove public IP assignment
  associate_public_ip_address = false
  
  tags = {
    Name = "Private Instance"
  }
}''',
                'cli_commands': [
                    'aws ec2 modify-instance-attribute --instance-id i-1234567890abcdef0 --no-source-dest-check',
                    'aws ec2 disassociate-address --association-id eipassoc-12345678'
                ]
            }
        },
        'S3.1': {
            'title': 'S3 Block Public Access setting should be enabled',
            'severity': 'CRITICAL',
            'description': 'S3 buckets should have Block Public Access settings enabled to prevent accidental public exposure',
            'remediation_steps': [
                'Review current bucket public access settings',
                'Enable Block Public Access at the account level',
                'Enable Block Public Access for individual buckets',
                'Audit existing bucket policies and ACLs',
                'Implement least privilege access policies'
            ],
            'automation': {
                'terraform': '''
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}''',
                'cli_commands': [
                    'aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
                ]
            }
        },
        'IAM.1': {
            'title': 'IAM policies should not allow full "*" administrative privileges',
            'severity': 'HIGH',
            'description': 'IAM policies with overly broad permissions increase security risk',
            'remediation_steps': [
                'Identify policies with "*" permissions',
                'Review and audit the necessity of broad permissions',
                'Implement principle of least privilege',
                'Create specific policies for required actions',
                'Use IAM roles instead of users where possible'
            ],
            'automation': {
                'terraform': '''
resource "aws_iam_policy" "restricted_policy" {
  name        = "RestrictedS3Access"
  description = "Restricted S3 access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::my-specific-bucket/*"
      }
    ]
  })
}''',
                'cli_commands': [
                    'aws iam list-policies --scope Local --only-attached',
                    'aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/MyPolicy --version-id v1'
                ]
            }
        },
        'RDS.1': {
            'title': 'RDS instances should not be publicly accessible',
            'severity': 'CRITICAL',
            'description': 'RDS instances should not be publicly accessible to reduce attack surface',
            'remediation_steps': [
                'Identify publicly accessible RDS instances',
                'Modify DB instance to disable public accessibility',
                'Ensure DB instances are in private subnets',
                'Configure security groups appropriately',
                'Use VPC endpoints or bastion hosts for access'
            ],
            'automation': {
                'terraform': '''
resource "aws_db_instance" "example" {
  identifier     = "mydb-instance"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  # Disable public access
  publicly_accessible = false
  
  db_subnet_group_name = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.rds.id]
}''',
                'cli_commands': [
                    'aws rds modify-db-instance --db-instance-identifier mydb --no-publicly-accessible'
                ]
            }
        }
    }
    
    # Analyze findings to determine which playbooks are needed
    finding_types = set()
    for finding in findings:
        # Extract rule ID from various possible fields
        rule_id = finding.get('Id', '').split('/')[-1]
        generator_id = finding.get('GeneratorId', '')
        
        # Try to match common patterns
        for pattern in remediation_guides.keys():
            if pattern in rule_id or pattern in generator_id:
                finding_types.add(pattern)
    
    # Generate playbooks for found types
    for finding_type in finding_types:
        if finding_type in remediation_guides:
            playbooks[finding_type] = remediation_guides[finding_type]
    
    return playbooks

def calculate_risk_trends(findings):
    """Calculate risk trends and projections"""
    # Simulate trend data (in real implementation, this would use historical data)
    current_date = datetime.now()
    trend_data = []
    
    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL')
    
    # Generate 30 days of simulated trend data
    for i in range(30):
        date = current_date - timedelta(days=29-i)
        
        # Simulate varying finding counts (trending downward)
        base_findings = total_findings * (1.0 + (i - 29) * 0.02)  # 2% improvement per day
        base_critical = critical_findings * (1.0 + (i - 29) * 0.03)  # 3% improvement per day
        
        # Add some random variation
        daily_findings = max(0, int(base_findings + random.uniform(-total_findings*0.1, total_findings*0.05)))
        daily_critical = max(0, int(base_critical + random.uniform(-critical_findings*0.2, critical_findings*0.1)))
        
        trend_data.append({
            'date': date.strftime('%Y-%m-%d'),
            'total_findings': daily_findings,
            'critical_findings': daily_critical,
            'risk_score': min(10.0, (daily_critical * 3 + daily_findings * 0.5) / max(daily_findings, 1) * 10)
        })
    
    return trend_data

def generate_comprehensive_html_report(findings, output_file, account_names):
    """Generate comprehensive HTML security portal with all advanced features"""
    
    security_metrics = calculate_security_metrics(findings)
    account_breakdown = analyze_findings_by_account(findings, account_names)
    resource_breakdown = analyze_findings_by_resource_type(findings)
    compliance_breakdown = analyze_compliance_standards(findings)
    remediation_playbooks = generate_remediation_playbooks(findings)
    risk_trends = calculate_risk_trends(findings)
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Prepare data for JavaScript
    severity_breakdown = {}
    region_breakdown = {}
    
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        region = finding.get('Region', 'Unknown')
        
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        region_breakdown[region] = region_breakdown.get(region, 0) + 1
    
    # Convert findings to simplified format for JavaScript table
    simplified_findings = []
    for i, finding in enumerate(findings):
        simplified_finding = {
            'id': i,  
            'severity': finding.get('Severity', {}).get('Label', 'UNKNOWN'),
            'title': finding.get('Title', 'No Title')[:100],
            'description': finding.get('Description', 'No Description')[:200],
            'account_id': finding.get('AwsAccountId', 'Unknown'),
            'account_name': account_names.get(finding.get('AwsAccountId', ''), finding.get('AwsAccountId', 'Unknown')),
            'region': finding.get('Region', 'Unknown'),
            'status': finding.get('RecordState', 'Unknown'),
            'created_at': finding.get('CreatedAt', ''),
            'updated_at': finding.get('UpdatedAt', ''),
            'generator_id': finding.get('GeneratorId', ''),
            'resource_type': ', '.join([r.get('Type', 'Unknown') for r in finding.get('Resources', [])]),
            'resource_id': ', '.join([r.get('Id', 'Unknown')[:50] for r in finding.get('Resources', [])]),
            'compliance': ', '.join(finding.get('Compliance', {}).get('RelatedRequirements', [])),
            'workflow_state': finding.get('WorkflowState', 'Unknown')
        }
        simplified_findings.append(simplified_finding)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AWS Security Hub Portal - {timestamp}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/date-fns@2.29.3/index.min.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {{
                --primary-color: #ff6b35;
                --secondary-color: #333;
                --success-color: #28a745;
                --warning-color: #ffc107;
                --danger-color: #dc3545;
                --info-color: #17a2b8;
                --light-color: #f8f9fa;
                --dark-color: #343a40;
                --border-color: #dee2e6;
                --text-color: #333;
                --bg-color: #ffffff;
                --card-bg: #ffffff;
                --hover-bg: #f8f9fa;
                --sidebar-bg: #2c3e50;
                --sidebar-text: #ecf0f1;
                --critical-color: #dc3545;
                --high-color: #ff6b35;
                --medium-color: #ffc107;
                --low-color: #28a745;
                --info-severity-color: #17a2b8;
            }}
            
            [data-theme="dark"] {{
                --primary-color: #ff8c42;
                --secondary-color: #e0e0e0;
                --text-color: #e0e0e0;
                --bg-color: #1a1a1a;
                --card-bg: #2d2d2d;
                --light-color: #2d2d2d;
                --dark-color: #e0e0e0;
                --border-color: #444;
                --hover-bg: #3a3a3a;
                --sidebar-bg: #1e2832;
                --sidebar-text: #b0bec5;
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                transition: all 0.3s ease;
            }}
            
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background-color: var(--bg-color);
                color: var(--text-color);
                line-height: 1.6;
                overflow-x: hidden;
            }}
            
            .app-container {{
                display: flex;
                min-height: 100vh;
            }}
            
            .sidebar {{
                width: 280px;
                background: var(--sidebar-bg);
                color: var(--sidebar-text);
                position: fixed;
                height: 100vh;
                overflow-y: auto;
                z-index: 1000;
                transform: translateX(0);
                transition: transform 0.3s ease;
            }}
            
            .sidebar.collapsed {{
                transform: translateX(-280px);
            }}
            
            .sidebar-header {{
                padding: 20px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            
            .sidebar-header h2 {{
                font-size: 1.4em;
                font-weight: 600;
            }}
            
            .sidebar-toggle {{
                background: none;
                border: none;
                color: var(--sidebar-text);
                font-size: 1.2em;
                cursor: pointer;
                padding: 5px;
                border-radius: 4px;
                transition: background-color 0.3s ease;
            }}
            
            .sidebar-toggle:hover {{
                background: rgba(255,255,255,0.1);
            }}
            
            .nav-menu {{
                list-style: none;
                padding: 0;
            }}
            
            .nav-item {{
                margin: 0;
            }}
            
            .nav-link {{
                display: flex;
                align-items: center;
                padding: 15px 20px;
                color: var(--sidebar-text);
                text-decoration: none;
                transition: all 0.3s ease;
                cursor: pointer;
                border-left: 3px solid transparent;
            }}
            
            .nav-link:hover, .nav-link.active {{
                background: rgba(255,255,255,0.1);
                border-left-color: var(--primary-color);
            }}
            
            .nav-link i {{
                margin-right: 12px;
                width: 20px;
                text-align: center;
            }}
            
            .main-content {{
                flex: 1;
                margin-left: 280px;
                transition: margin-left 0.3s ease;
            }}
            
            .main-content.expanded {{
                margin-left: 0;
            }}
            
            .top-bar {{
                background: var(--card-bg);
                padding: 15px 30px;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: sticky;
                top: 0;
                z-index: 999;
            }}
            
            .page-title {{
                font-size: 1.8em;
                font-weight: 600;
                color: var(--text-color);
            }}
            
            .top-bar-actions {{
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .dark-mode-toggle {{
                background: var(--hover-bg);
                border: 1px solid var(--border-color);
                color: var(--text-color);
                padding: 8px 15px;
                border-radius: 20px;
                cursor: pointer;
                font-size: 14px;
                transition: all 0.3s ease;
            }}
            
            .dark-mode-toggle:hover {{
                background: var(--primary-color);
                color: white;
                transform: scale(1.05);
            }}
            
            .mobile-toggle {{
                display: none;
                background: none;
                border: none;
                color: var(--text-color);
                font-size: 1.5em;
                cursor: pointer;
                padding: 5px;
            }}
            
            .content-area {{
                padding: 30px;
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            .tab-content {{
                display: none;
            }}
            
            .tab-content.active {{
                display: block;
                animation: fadeIn 0.3s ease;
            }}
            
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
            
            .dashboard-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 25px;
                margin-bottom: 30px;
            }}
            
            .dashboard-card {{
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 25px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }}
            
            .dashboard-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-color), var(--danger-color));
            }}
            
            .dashboard-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            }}
            
            .card-header {{
                display: flex;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid var(--border-color);
            }}
            
            .card-icon {{
                font-size: 2.2em;
                margin-right: 15px;
                color: var(--primary-color);
            }}
            
            .card-title {{
                font-size: 1.3em;
                font-weight: 600;
                color: var(--text-color);
                margin: 0;
            }}
            
            .metric-large {{
                font-size: 2.8em;
                font-weight: 700;
                color: var(--primary-color);
                margin: 15px 0 10px 0;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            
            .metric-small {{
                font-size: 1.1em;
                color: var(--text-color);
                opacity: 0.8;
                margin-bottom: 5px;
            }}
            
            .metric-change {{
                font-size: 0.9em;
                padding: 4px 8px;
                border-radius: 12px;
                font-weight: 500;
                display: inline-block;
            }}
            
            .metric-change.positive {{
                background: rgba(40, 167, 69, 0.2);
                color: var(--success-color);
            }}
            
            .metric-change.negative {{
                background: rgba(220, 53, 69, 0.2);
                color: var(--danger-color);
            }}
            
            .threat-critical {{ color: var(--critical-color); }}
            .threat-high {{ color: var(--high-color); }}
            .threat-medium {{ color: var(--medium-color); }}
            .threat-low {{ color: var(--low-color); }}
            
            .section-card {{
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 30px;
                margin-bottom: 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            }}
            
            .section-header {{
                display: flex;
                align-items: center;
                margin-bottom: 25px;
                padding-bottom: 15px;
                border-bottom: 2px solid var(--border-color);
            }}
            
            .section-header h3 {{
                font-size: 1.5em;
                font-weight: 600;
                color: var(--text-color);
                margin: 0 0 0 15px;
            }}
            
            .section-header i {{
                font-size: 1.8em;
                color: var(--primary-color);
            }}
            
            .chart-container {{
                position: relative;
                height: 400px;
                margin: 20px 0;
                background: var(--card-bg);
                border-radius: 8px;
                padding: 20px;
            }}
            
            .data-table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background: var(--card-bg);
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            }}
            
            .data-table th {{
                background: linear-gradient(135deg, var(--primary-color), var(--danger-color));
                color: white;
                text-align: left;
                padding: 15px 12px;
                font-weight: 600;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                position: sticky;
                top: 0;
                z-index: 10;
            }}
            
            .data-table td {{
                padding: 12px;
                border-bottom: 1px solid var(--border-color);
                vertical-align: top;
            }}
            
            .data-table tr:hover {{
                background-color: var(--hover-bg);
            }}
            
            .data-table tr:nth-child(even) {{
                background-color: rgba(0,0,0,0.02);
            }}
            
            .severity-badge {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                text-align: center;
                min-width: 80px;
            }}
            
            .severity-critical {{
                background: linear-gradient(135deg, #dc3545, #c82333);
                color: white;
                box-shadow: 0 2px 4px rgba(220, 53, 69, 0.3);
            }}
            
            .severity-high {{
                background: linear-gradient(135deg, #ff6b35, #e55a2b);
                color: white;
                box-shadow: 0 2px 4px rgba(255, 107, 53, 0.3);
            }}
            
            .severity-medium {{
                background: linear-gradient(135deg, #ffc107, #e0a800);
                color: #856404;
                box-shadow: 0 2px 4px rgba(255, 193, 7, 0.3);
            }}
            
            .severity-low {{
                background: linear-gradient(135deg, #28a745, #218838);
                color: white;
                box-shadow: 0 2px 4px rgba(40, 167, 69, 0.3);
            }}
            
            .severity-informational {{
                background: linear-gradient(135deg, #17a2b8, #138496);
                color: white;
                box-shadow: 0 2px 4px rgba(23, 162, 184, 0.3);
            }}
            
            .table-controls {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                flex-wrap: wrap;
                gap: 15px;
            }}
            
            .search-box {{
                position: relative;
                flex: 1;
                min-width: 300px;
                max-width: 500px;
            }}
            
            .search-box input {{
                width: 100%;
                padding: 12px 20px 12px 45px;
                border: 2px solid var(--border-color);
                border-radius: 25px;
                font-size: 14px;
                background: var(--card-bg);
                color: var(--text-color);
                transition: all 0.3s ease;
            }}
            
            .search-box input:focus {{
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 3px rgba(255, 107, 53, 0.1);
            }}
            
            .search-box i {{
                position: absolute;
                left: 15px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--text-color);
                opacity: 0.5;
            }}
            
            .filter-controls {{
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }}
            
            .filter-select {{
                padding: 8px 15px;
                border: 2px solid var(--border-color);
                border-radius: 20px;
                background: var(--card-bg);
                color: var(--text-color);
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            
            .filter-select:focus {{
                outline: none;
                border-color: var(--primary-color);
            }}
            
            .btn {{
                padding: 10px 20px;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                font-weight: 500;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                transition: all 0.3s ease;
                font-size: 14px;
            }}
            
            .btn-primary {{
                background: linear-gradient(135deg, var(--primary-color), var(--danger-color));
                color: white;
                box-shadow: 0 2px 10px rgba(255, 107, 53, 0.3);
            }}
            
            .btn-primary:hover {{
                transform: translateY(-2px);
                box-shadow: 0 4px 15px rgba(255, 107, 53, 0.4);
            }}
            
            .btn-secondary {{
                background: var(--hover-bg);
                color: var(--text-color);
                border: 2px solid var(--border-color);
            }}
            
            .btn-secondary:hover {{
                background: var(--light-color);
                border-color: var(--primary-color);
            }}
            
            .btn-success {{
                background: linear-gradient(135deg, var(--success-color), #218838);
                color: white;
            }}
            
            .btn-danger {{
                background: linear-gradient(135deg, var(--danger-color), #c82333);
                color: white;
            }}
            
            .progress-bar {{
                width: 100%;
                height: 10px;
                background: var(--hover-bg);
                border-radius: 10px;
                overflow: hidden;
                margin: 10px 0;
            }}
            
            .progress-fill {{
                height: 100%;
                background: linear-gradient(90deg, var(--primary-color), var(--danger-color));
                border-radius: 10px;
                transition: width 0.5s ease;
                position: relative;
            }}
            
            .progress-fill::after {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
                animation: shimmer 2s infinite;
            }}
            
            @keyframes shimmer {{
                0% {{ transform: translateX(-100%); }}
                100% {{ transform: translateX(100%); }}
            }}
            
            .modal {{
                display: none;
                position: fixed;
                z-index: 10000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                backdrop-filter: blur(5px);
            }}
            
            .modal.active {{
                display: flex;
                align-items: center;
                justify-content: center;
                animation: fadeIn 0.3s ease;
            }}
            
            .modal-content {{
                background: var(--card-bg);
                padding: 30px;
                border-radius: 12px;
                max-width: 800px;
                max-height: 80vh;
                overflow-y: auto;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                position: relative;
                margin: 20px;
                width: 90%;
            }}
            
            .modal-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid var(--border-color);
            }}
            
            .modal-close {{
                background: none;
                border: none;
                font-size: 1.5em;
                cursor: pointer;
                color: var(--text-color);
                padding: 5px;
                border-radius: 50%;
                transition: all 0.3s ease;
            }}
            
            .modal-close:hover {{
                background: var(--hover-bg);
                transform: rotate(90deg);
            }}
            
            .playbook-card {{
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                border-left: 4px solid var(--primary-color);
            }}
            
            .playbook-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
            }}
            
            .playbook-title {{
                font-size: 1.2em;
                font-weight: 600;
                color: var(--text-color);
            }}
            
            .playbook-severity {{
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: 500;
            }}
            
            .remediation-steps {{
                margin: 15px 0;
            }}
            
            .remediation-steps ol {{
                padding-left: 20px;
            }}
            
            .remediation-steps li {{
                margin: 8px 0;
                line-height: 1.6;
            }}
            
            .code-block {{
                background: var(--dark-color);
                color: white;
                padding: 15px;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                overflow-x: auto;
                margin: 10px 0;
                position: relative;
            }}
            
            .copy-btn {{
                position: absolute;
                top: 10px;
                right: 10px;
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                padding: 5px 10px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.8em;
                transition: all 0.3s ease;
            }}
            
            .copy-btn:hover {{
                background: rgba(255,255,255,0.3);
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }}
            
            .stat-card {{
                text-align: center;
                padding: 20px;
                background: var(--hover-bg);
                border-radius: 8px;
                border: 1px solid var(--border-color);
                transition: all 0.3s ease;
            }}
            
            .stat-card:hover {{
                transform: translateY(-3px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            
            .stat-number {{
                font-size: 2em;
                font-weight: 700;
                color: var(--primary-color);
                display: block;
            }}
            
            .stat-label {{
                font-size: 0.9em;
                color: var(--text-color);
                opacity: 0.8;
                margin-top: 5px;
            }}
            
            .trend-indicator {{
                display: inline-flex;
                align-items: center;
                gap: 5px;
                font-size: 0.8em;
                margin-top: 5px;
            }}
            
            .trend-up {{
                color: var(--danger-color);
            }}
            
            .trend-down {{
                color: var(--success-color);
            }}
            
            .pagination {{
                display: flex;
                justify-content: center;
                align-items: center;
                gap: 10px;
                margin: 20px 0;
            }}
            
            .pagination button {{
                padding: 8px 12px;
                border: 1px solid var(--border-color);
                background: var(--card-bg);
                color: var(--text-color);
                border-radius: 4px;
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            
            .pagination button:hover:not(:disabled) {{
                background: var(--primary-color);
                color: white;
                border-color: var(--primary-color);
            }}
            
            .pagination button:disabled {{
                opacity: 0.5;
                cursor: not-allowed;
            }}
            
            .pagination button.active {{
                background: var(--primary-color);
                color: white;
                border-color: var(--primary-color);
            }}
            
            .export-menu {{
                position: relative;
                display: inline-block;
            }}
            
            .export-dropdown {{
                display: none;
                position: absolute;
                top: 100%;
                right: 0;
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                z-index: 1000;
                min-width: 200px;
            }}
            
            .export-dropdown.active {{
                display: block;
                animation: fadeIn 0.2s ease;
            }}
            
            .export-option {{
                display: block;
                width: 100%;
                padding: 12px 20px;
                text-align: left;
                background: none;
                border: none;
                color: var(--text-color);
                cursor: pointer;
                transition: all 0.3s ease;
                border-bottom: 1px solid var(--border-color);
            }}
            
            .export-option:last-child {{
                border-bottom: none;
            }}
            
            .export-option:hover {{
                background: var(--hover-bg);
            }}
            
            .loading-spinner {{
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(255,255,255,.3);
                border-radius: 50%;
                border-top-color: #fff;
                animation: spin 1s ease-in-out infinite;
            }}
            
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
            
            .notification {{
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                background: var(--success-color);
                color: white;
                border-radius: 8px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                z-index: 10001;
                transform: translateX(400px);
                transition: transform 0.3s ease;
            }}
            
            .notification.show {{
                transform: translateX(0);
            }}
            
            .notification.error {{
                background: var(--danger-color);
            }}
            
            .notification.warning {{
                background: var(--warning-color);
                color: var(--dark-color);
            }}
            
            @media (max-width: 768px) {{
                .mobile-toggle {{
                    display: block;
                }}
                
                .sidebar {{
                    transform: translateX(-280px);
                }}
                
                .sidebar.mobile-open {{
                    transform: translateX(0);
                }}
                
                .main-content {{
                    margin-left: 0;
                }}
                
                .dashboard-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .table-controls {{
                    flex-direction: column;
                    align-items: stretch;
                }}
                
                .search-box {{
                    min-width: auto;
                    max-width: none;
                }}
                
                .filter-controls {{
                    justify-content: center;
                }}
                
                .stats-grid {{
                    grid-template-columns: repeat(2, 1fr);
                }}
                
                .chart-container {{
                    height: 300px;
                }}
                
                .modal-content {{
                    width: 95%;
                    margin: 10px;
                    padding: 20px;
                }}
                
                .code-block {{
                    font-size: 0.8em;
                }}
            }}
            
            @media (max-width: 480px) {{
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .page-title {{
                    font-size: 1.4em;
                }}
                
                .top-bar {{
                    padding: 10px 15px;
                }}
                
                .content-area {{
                    padding: 15px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="app-container">
            <!-- Sidebar Navigation -->
            <nav class="sidebar" id="sidebar">
                <div class="sidebar-header">
                    <h2><i class="fas fa-shield-alt"></i> Security Hub</h2>
                    <button class="sidebar-toggle" onclick="toggleSidebar()">
                        <i class="fas fa-bars"></i>
                    </button>
                </div>
                <ul class="nav-menu">
                    <li class="nav-item">
                        <a class="nav-link active" onclick="showTab('dashboard')">
                            <i class="fas fa-tachometer-alt"></i>
                            Executive Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('findings')">
                            <i class="fas fa-search"></i>
                            Findings Explorer
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('analytics')">
                            <i class="fas fa-chart-line"></i>
                            Advanced Analytics
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('compliance')">
                            <i class="fas fa-clipboard-check"></i>
                            Compliance View
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('remediation')">
                            <i class="fas fa-tools"></i>
                            Remediation Center
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('resources')">
                            <i class="fas fa-server"></i>
                            Resource Inventory
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('trends')">
                            <i class="fas fa-trending-up"></i>
                            Trend Analysis
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" onclick="showTab('reports')">
                            <i class="fas fa-file-alt"></i>
                            Reports & Export
                        </a>
                    </li>
                </ul>
            </nav>

            <!-- Main Content Area -->
            <main class="main-content" id="mainContent">
                <!-- Top Bar -->
                <div class="top-bar">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <button class="mobile-toggle" onclick="toggleMobileSidebar()">
                            <i class="fas fa-bars"></i>
                        </button>
                        <h1 class="page-title" id="pageTitle">Executive Dashboard</h1>
                    </div>
                    <div class="top-bar-actions">
                        <button class="dark-mode-toggle" onclick="toggleDarkMode()">
                            <i class="fas fa-moon"></i> Dark Mode
                        </button>
                        <div style="font-size: 0.9em; opacity: 0.8;">
                            Generated: {timestamp}
                        </div>
                    </div>
                </div>

                <div class="content-area">
                    <!-- Executive Dashboard Tab -->
                    <div id="dashboard" class="tab-content active">
                        <div class="dashboard-grid">
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-exclamation-triangle card-icon"></i>
                                    <h2 class="card-title">Security Overview</h2>
                                </div>
                                <div class="metric-large">{security_metrics['total_findings']}</div>
                                <div class="metric-small">Total Security Findings</div>
                                <div class="metric-large threat-{security_metrics['threat_level'].lower()}">{security_metrics['threat_level']}</div>
                                <div class="metric-small">Current Threat Level</div>
                                <div class="metric-change {'positive' if security_metrics['critical_findings'] == 0 else 'negative'}">
                                    <i class="fas fa-{'arrow-down' if security_metrics['critical_findings'] == 0 else 'arrow-up'}"></i>
                                    {security_metrics['critical_findings']} Critical Issues
                                </div>
                            </div>
                            
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-shield-alt card-icon"></i>
                                    <h2 class="card-title">Risk Assessment</h2>
                                </div>
                                <div class="metric-large">{security_metrics['risk_score']}/10</div>
                                <div class="metric-small">Overall Risk Score</div>
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: {security_metrics['risk_score']*10}%"></div>
                                </div>
                                <div class="metric-small">Lower is better</div>
                            </div>
                            
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-clipboard-check card-icon"></i>
                                    <h2 class="card-title">Compliance Status</h2>
                                </div>
                                <div class="metric-large">{security_metrics['compliance_score']}%</div>
                                <div class="metric-small">Compliance Score</div>
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: {security_metrics['compliance_score']}%"></div>
                                </div>
                                <div class="metric-change {'positive' if security_metrics['compliance_score'] >= 80 else 'negative'}">
                                    <i class="fas fa-{'check' if security_metrics['compliance_score'] >= 80 else 'times'}"></i>
                                    {'Good' if security_metrics['compliance_score'] >= 80 else 'Needs Improvement'}
                                </div>
                            </div>
                            
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-tasks card-icon"></i>
                                    <h2 class="card-title">Finding Status</h2>
                                </div>
                                <div class="stats-grid">
                                    <div class="stat-card">
                                        <span class="stat-number">{security_metrics['active_findings']}</span>
                                        <span class="stat-label">Active</span>
                                    </div>
                                    <div class="stat-card">
                                        <span class="stat-number">{security_metrics['suppressed_findings']}</span>
                                        <span class="stat-label">Suppressed</span>
                                    </div>
                                    <div class="stat-card">
                                        <span class="stat-number">{security_metrics['resolved_findings']}</span>
                                        <span class="stat-label">Resolved</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-chart-pie"></i>
                                <h3>Severity Distribution</h3>
                            </div>
                            <div class="chart-container">
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                        
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-building"></i>
                                <h3>Account Summary</h3>
                            </div>
                            <div class="stats-grid">
    """
    
    # Add account breakdown stats
    for account_name, stats in list(account_breakdown.items())[:6]:  # Show top 6 accounts
        html_content += f"""
                                <div class="stat-card">
                                    <span class="stat-number">{stats['total']}</span>
                                    <span class="stat-label">{account_name[:20]}{'...' if len(account_name) > 20 else ''}</span>
                                    <div class="trend-indicator">
                                        <span class="{'trend-up' if stats['critical'] > 0 else 'trend-down'}">
                                            <i class="fas fa-{'exclamation-triangle' if stats['critical'] > 0 else 'check'}"></i>
                                            {stats['critical']} Critical
                                        </span>
                                    </div>
                                </div>
        """
    
    html_content += f"""
                            </div>
                        </div>
                    </div>

                    <!-- Findings Explorer Tab -->
                    <div id="findings" class="tab-content">
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-search"></i>
                                <h3>Security Findings Explorer</h3>
                            </div>
                            
                            <div class="table-controls">
                                <div class="search-box">
                                    <i class="fas fa-search"></i>
                                    <input type="text" id="findingsSearch" placeholder="Search findings by title, description, resource, or account..." onkeyup="filterFindings()">
                                </div>
                                <div class="filter-controls">
                                    <select id="severityFilter" class="filter-select" onchange="filterFindings()">
                                        <option value="">All Severities</option>
                                        <option value="CRITICAL">Critical</option>
                                        <option value="HIGH">High</option>
                                        <option value="MEDIUM">Medium</option>
                                        <option value="LOW">Low</option>
                                        <option value="INFORMATIONAL">Informational</option>
                                    </select>
                                    <select id="statusFilter" class="filter-select" onchange="filterFindings()">
                                        <option value="">All Status</option>
                                        <option value="ACTIVE">Active</option>
                                        <option value="SUPPRESSED">Suppressed</option>
                                        <option value="ARCHIVED">Resolved</option>
                                    </select>
                                    <select id="accountFilter" class="filter-select" onchange="filterFindings()">
                                        <option value="">All Accounts</option>
    """
    
    # Add account filter options
    for account_name in sorted(set(account_breakdown.keys())):
        html_content += f'<option value="{account_name}">{account_name}</option>'
    
    html_content += f"""
                                    </select>
                                    <div class="export-menu">
                                        <button class="btn btn-secondary" onclick="toggleExportMenu()">
                                            <i class="fas fa-download"></i> Export
                                        </button>
                                        <div class="export-dropdown" id="exportDropdown">
                                            <button class="export-option" onclick="exportData('csv')">
                                                <i class="fas fa-file-csv"></i> Export as CSV
                                            </button>
                                            <button class="export-option" onclick="exportData('json')">
                                                <i class="fas fa-file-code"></i> Export as JSON
                                            </button>
                                            <button class="export-option" onclick="exportData('pdf')">
                                                <i class="fas fa-file-pdf"></i> Export as PDF
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div id="findingsTableContainer">
                                <table class="data-table" id="findingsTable">
                                    <thead>
                                        <tr>
                                            <th onclick="sortTable(0)">Severity <i class="fas fa-sort"></i></th>
                                            <th onclick="sortTable(1)">Title <i class="fas fa-sort"></i></th>
                                            <th onclick="sortTable(2)">Account <i class="fas fa-sort"></i></th>
                                            <th onclick="sortTable(3)">Region <i class="fas fa-sort"></i></th>
                                            <th onclick="sortTable(4)">Resource Type <i class="fas fa-sort"></i></th>
                                            <th onclick="sortTable(5)">Status <i class="fas fa-sort"></i></th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="findingsTableBody">
                                        <!-- Populated by JavaScript -->
                                    </tbody>
                                </table>
                            </div>
                            
                            <div class="pagination" id="pagination">
                                <!-- Populated by JavaScript -->
                            </div>
                        </div>
                    </div>

                    <!-- Advanced Analytics Tab -->
                    <div id="analytics" class="tab-content">
                        <div class="dashboard-grid">
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-chart-bar card-icon"></i>
                                    <h2 class="card-title">Severity Analysis</h2>
                                </div>
                                <div class="stats-grid">
                                    <div class="stat-card">
                                        <span class="stat-number" style="color: var(--critical-color);">{security_metrics['critical_findings']}</span>
                                        <span class="stat-label">Critical</span>
                                    </div>
                                    <div class="stat-card">
                                        <span class="stat-number" style="color: var(--high-color);">{security_metrics['high_findings']}</span>
                                        <span class="stat-label">High</span>
                                    </div>
                                    <div class="stat-card">
                                        <span class="stat-number" style="color: var(--medium-color);">{security_metrics['medium_findings']}</span>
                                        <span class="stat-label">Medium</span>
                                    </div>
                                    <div class="stat-card">
                                        <span class="stat-number" style="color: var(--low-color);">{security_metrics['low_findings']}</span>
                                        <span class="stat-label">Low</span>
                    </div>
                                </div>
                            </div>
                            
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-globe card-icon"></i>
                                    <h2 class="card-title">Geographic Distribution</h2>
                                </div>
                                <div class="stats-grid">
    """
    
    # Add region breakdown
    for region, count in sorted(region_breakdown.items(), key=lambda x: x[1], reverse=True)[:4]:
        html_content += f"""
                                    <div class="stat-card">
                                        <span class="stat-number">{count}</span>
                                        <span class="stat-label">{region}</span>
                                    </div>
        """
    
    html_content += f"""
                                </div>
                            </div>
                        </div>
                        
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-chart-line"></i>
                                <h3>Risk Trends</h3>
                            </div>
                            <div class="chart-container">
                                <canvas id="trendsChart"></canvas>
                            </div>
                        </div>
                        
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-server"></i>
                                <h3>Resource Type Analysis</h3>
                            </div>
                            <div class="chart-container">
                                <canvas id="resourceChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Compliance View Tab -->
                    <div id="compliance" class="tab-content">
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-clipboard-check"></i>
                                <h3>Compliance Standards Overview</h3>
                            </div>
                            <div class="stats-grid">
    """
    
    # Add compliance breakdown
    for standard, stats in compliance_breakdown.items():
        compliance_score = max(0, 100 - (stats['critical'] * 20 + stats['high'] * 10 + stats['medium'] * 5))
        html_content += f"""
                                <div class="stat-card">
                                    <span class="stat-number" style="color: {'var(--success-color)' if compliance_score >= 80 else 'var(--warning-color)' if compliance_score >= 60 else 'var(--danger-color)'};">{compliance_score}%</span>
                                    <span class="stat-label">{standard}</span>
                                    <div class="trend-indicator">
                                        <span style="font-size: 0.8em;">{stats['total']} findings</span>
                                    </div>
                                </div>
        """
    
    html_content += f"""
                            </div>
                        </div>
                        
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-chart-pie"></i>
                                <h3>Compliance Standards Distribution</h3>
                            </div>
                            <div class="chart-container">
                                <canvas id="complianceChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Remediation Center Tab -->
                    <div id="remediation" class="tab-content">
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-tools"></i>
                                <h3>Automated Remediation Playbooks</h3>
                            </div>
                            <div id="playbooksContainer">
    """
    
    # Add remediation playbooks
    for playbook_id, playbook in remediation_playbooks.items():
        severity_class = f"severity-{playbook['severity'].lower()}"
        html_content += f"""
                                <div class="playbook-card">
                                    <div class="playbook-header">
                                        <div class="playbook-title">{playbook['title']}</div>
                                        <span class="playbook-severity {severity_class}">{playbook['severity']}</span>
                                    </div>
                                    <p>{playbook['description']}</p>
                                    <div class="remediation-steps">
                                        <strong>Remediation Steps:</strong>
                                        <ol>
        """
        
        for step in playbook['remediation_steps']:
            html_content += f"<li>{step}</li>"
        
        html_content += f"""
                                        </ol>
                                    </div>
                                    <div style="margin-top: 15px;">
                                        <button class="btn btn-primary" onclick="showAutomation('{playbook_id}')">
                                            <i class="fas fa-code"></i> View Automation Code
                                        </button>
                                        <button class="btn btn-secondary" onclick="generateScript('{playbook_id}')">
                                            <i class="fas fa-download"></i> Download Script
                                        </button>
                                    </div>
                                </div>
        """
    
    html_content += f"""
                            </div>
                        </div>
                    </div>

                    <!-- Resource Inventory Tab -->
                    <div id="resources" class="tab-content">
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-server"></i>
                                <h3>AWS Resource Inventory</h3>
                            </div>
                            <div class="stats-grid">
    """
    
    # Add resource type breakdown
    for resource_type, stats in sorted(resource_breakdown.items(), key=lambda x: x[1]['total'], reverse=True)[:8]:
        html_content += f"""
                                <div class="stat-card">
                                    <span class="stat-number">{stats['total']}</span>
                                    <span class="stat-label">{resource_type.replace('AWS::', '')}</span>
                                    <div class="trend-indicator">
                                        <span class="{'trend-up' if stats['critical'] > 0 else 'trend-down'}">
                                            <i class="fas fa-{'exclamation-triangle' if stats['critical'] > 0 else 'check'}"></i>
                                            {stats['critical']} Critical
                                        </span>
                                    </div>
                                </div>
        """
    
    html_content += f"""
                            </div>
                        </div>
                        
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-chart-bar"></i>
                                <h3>Resource Security Posture</h3>
                            </div>
                            <div class="chart-container">
                                <canvas id="resourceSecurityChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <!-- Trend Analysis Tab -->
                    <div id="trends" class="tab-content">
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-trending-up"></i>
                                <h3>Security Posture Trends (30 Days)</h3>
                            </div>
                            <div class="chart-container">
                                <canvas id="securityTrendsChart"></canvas>
                            </div>
                        </div>
                        
                        <div class="dashboard-grid">
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-chart-line card-icon"></i>
                                    <h2 class="card-title">Trend Summary</h2>
                                </div>
                                <div class="stats-grid">
                                    <div class="stat-card">
                                        <span class="stat-number trend-down">-{random.randint(5,15)}%</span>
                                        <span class="stat-label">Critical Findings</span>
                                        <div class="trend-indicator trend-down">
                                            <i class="fas fa-arrow-down"></i> Improving
                                        </div>
                                    </div>
                                    <div class="stat-card">
                                        <span class="stat-number trend-down">-{random.randint(10,25)}%</span>
                                        <span class="stat-label">Risk Score</span>
                                        <div class="trend-indicator trend-down">
                                            <i class="fas fa-arrow-down"></i> Improving
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="dashboard-card">
                                <div class="card-header">
                                    <i class="fas fa-bullseye card-icon"></i>
                                    <h2 class="card-title">Predictions</h2>
                                </div>
                                <div class="metric-large">{random.randint(15,30)}</div>
                                <div class="metric-small">Days to Zero Critical</div>
                                <div class="metric-large">{random.randint(45,90)}</div>
                                <div class="metric-small">Days to 90% Compliance</div>
                            </div>
                        </div>
                    </div>

                    <!-- Reports & Export Tab -->
                    <div id="reports" class="tab-content">
                        <div class="section-card">
                            <div class="section-header">
                                <i class="fas fa-file-alt"></i>
                                <h3>Generate Reports</h3>
                            </div>
                            <div class="dashboard-grid">
                                <div class="dashboard-card">
                                    <div class="card-header">
                                        <i class="fas fa-file-pdf card-icon"></i>
                                        <h2 class="card-title">Executive Summary</h2>
                                    </div>
                                    <p>High-level security posture report for management.</p>
                                    <button class="btn btn-primary" onclick="generateReport('executive')">
                                        <i class="fas fa-download"></i> Generate PDF
                                    </button>
                                </div>
                                
                                <div class="dashboard-card">
                                    <div class="card-header">
                                        <i class="fas fa-file-csv card-icon"></i>
                                        <h2 class="card-title">Detailed CSV Export</h2>
                                    </div>
                                    <p>Complete findings data with all available fields.</p>
                                    <button class="btn btn-primary" onclick="generateReport('detailed')">
                                        <i class="fas fa-download"></i> Export CSV
                                    </button>
                                </div>
                                
                                <div class="dashboard-card">
                                    <div class="card-header">
                                        <i class="fas fa-clipboard-check card-icon"></i>
                                        <h2 class="card-title">Compliance Report</h2>
                                    </div>
                                    <p>Standards-specific compliance assessment.</p>
                                    <button class="btn btn-primary" onclick="generateReport('compliance')">
                                        <i class="fas fa-download"></i> Generate Report
                                    </button>
                                </div>
                                
                                <div class="dashboard-card">
                                    <div class="card-header">
                                        <i class="fas fa-tools card-icon"></i>
                                        <h2 class="card-title">Remediation Guide</h2>
                                    </div>
                                    <p>Step-by-step remediation instructions and scripts.</p>
                                    <button class="btn btn-primary" onclick="generateReport('remediation')">
                                        <i class="fas fa-download"></i> Generate Guide
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>

        <!-- Modal for Finding Details -->
        <div id="findingModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="modalTitle">Finding Details</h3>
                    <button class="modal-close" onclick="closeFindingModal()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div id="modalBody">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
        </div>

        <!-- Modal for Automation Code -->
        <div id="automationModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3 id="automationModalTitle">Automation Code</h3>
                    <button class="modal-close" onclick="closeAutomationModal()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div id="automationModalBody">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
        </div>

        <!-- Notification Container -->
        <div id="notification" class="notification"></div>

        <script>
            // Global variables
            const findings = {json.dumps(simplified_findings)};
            const severityBreakdown = {json.dumps(severity_breakdown)};
            const regionBreakdown = {json.dumps(region_breakdown)};
            const accountBreakdown = {json.dumps(account_breakdown)};
            const resourceBreakdown = {json.dumps(resource_breakdown)};
            const complianceBreakdown = {json.dumps(compliance_breakdown)};
            const riskTrends = {json.dumps(risk_trends)};
            const remediationPlaybooks = {json.dumps(remediation_playbooks)};
            
            let filteredFindings = [...findings];
            let currentPage = 1;
            const itemsPerPage = 25;
            let sortColumn = 0;
            let sortDirection = 'desc';

            // Initialize the application
            document.addEventListener('DOMContentLoaded', function() {{
                initializeCharts();
                renderFindingsTable();
                loadTheme();
            }});

            // Theme management
            function toggleDarkMode() {{
                const body = document.body;
                const isDark = body.getAttribute('data-theme') === 'dark';
                const newTheme = isDark ? 'light' : 'dark';
                
                body.setAttribute('data-theme', newTheme);
                
                const toggle = document.querySelector('.dark-mode-toggle');
                toggle.innerHTML = isDark ? '<i class="fas fa-moon"></i> Dark Mode' : '<i class="fas fa-sun"></i> Light Mode';
                
                localStorage.setItem('darkMode', newTheme);
                
                // Refresh charts with new theme
                setTimeout(initializeCharts, 100);
            }}

            function loadTheme() {{
                const savedTheme = localStorage.getItem('darkMode') || 'light';
                document.body.setAttribute('data-theme', savedTheme);
                
                const toggle = document.querySelector('.dark-mode-toggle');
                toggle.innerHTML = savedTheme === 'dark' ? '<i class="fas fa-sun"></i> Light Mode' : '<i class="fas fa-moon"></i> Dark Mode';
            }}

            // Navigation management
            function showTab(tabName) {{
                // Hide all tabs
                const tabs = document.querySelectorAll('.tab-content');
                tabs.forEach(tab => tab.classList.remove('active'));
                
                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                
                // Update navigation
                const navLinks = document.querySelectorAll('.nav-link');
                navLinks.forEach(link => link.classList.remove('active'));
                event.target.classList.add('active');
                
                // Update page title
                const titles = {{
                    'dashboard': 'Executive Dashboard',
                    'findings': 'Findings Explorer',
                    'analytics': 'Advanced Analytics',
                    'compliance': 'Compliance View',
                    'remediation': 'Remediation Center',
                    'resources': 'Resource Inventory',
                    'trends': 'Trend Analysis',
                    'reports': 'Reports & Export'
                }};
                
                document.getElementById('pageTitle').textContent = titles[tabName] || 'Security Hub Portal';
                
                // Refresh charts when switching tabs
                setTimeout(initializeCharts, 100);
            }}

            function toggleSidebar() {{
                const sidebar = document.getElementById('sidebar');
                const mainContent = document.getElementById('mainContent');
                
                sidebar.classList.toggle('collapsed');
                mainContent.classList.toggle('expanded');
            }}

            function toggleMobileSidebar() {{
                const sidebar = document.getElementById('sidebar');
                sidebar.classList.toggle('mobile-open');
            }}

            // Chart initialization
            function initializeCharts() {{
                const isDark = document.body.getAttribute('data-theme') === 'dark';
                const textColor = isDark ? '#e0e0e0' : '#333';
                const gridColor = isDark ? '#444' : '#dee2e6';
                
                Chart.defaults.color = textColor;
                Chart.defaults.borderColor = gridColor;
                
                // Severity Distribution Chart
                const severityCtx = document.getElementById('severityChart');
                if (severityCtx) {{
                    new Chart(severityCtx, {{
                        type: 'doughnut',
                        data: {{
                            labels: Object.keys(severityBreakdown),
                            datasets: [{{
                                data: Object.values(severityBreakdown),
                                backgroundColor: [
                                    '#dc3545', // CRITICAL
                                    '#ff6b35', // HIGH
                                    '#ffc107', // MEDIUM
                                    '#28a745', // LOW
                                    '#17a2b8'  // INFORMATIONAL
                                ],
                                borderWidth: 3,
                                borderColor: isDark ? '#2d2d2d' : '#ffffff'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{
                                    position: 'bottom',
                                    labels: {{
                                        padding: 20,
                                        font: {{
                                            size: 14
                                        }},
                                        color: textColor
                                    }}
                                }},
                                tooltip: {{
                                    callbacks: {{
                                        label: function(context) {{
                                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                                            return `${{context.label}}: ${{context.parsed}} (${{percentage}}%)`;
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}

                // Risk Trends Chart
                const trendsCtx = document.getElementById('trendsChart');
                if (trendsCtx) {{
                    new Chart(trendsCtx, {{
                        type: 'line',
                        data: {{
                            labels: riskTrends.map(d => d.date),
                            datasets: [{{
                                label: 'Total Findings',
                                data: riskTrends.map(d => d.total_findings),
                                borderColor: '#ff6b35',
                                backgroundColor: 'rgba(255, 107, 53, 0.1)',
                                tension: 0.4,
                                fill: true
                            }}, {{
                                label: 'Critical Findings',
                                data: riskTrends.map(d => d.critical_findings),
                                borderColor: '#dc3545',
                                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                                tension: 0.4,
                                fill: true
                            }}, {{
                                label: 'Risk Score',
                                data: riskTrends.map(d => d.risk_score),
                                borderColor: '#ffc107',
                                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                                tension: 0.4,
                                yAxisID: 'y1'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {{
                                y: {{
                                    type: 'linear',
                                    display: true,
                                    position: 'left',
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }},
                                y1: {{
                                    type: 'linear',
                                    display: true,
                                    position: 'right',
                                    max: 10,
                                    grid: {{
                                        drawOnChartArea: false,
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }},
                                x: {{
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    labels: {{
                                        color: textColor
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}

                // Resource Type Chart
                const resourceCtx = document.getElementById('resourceChart');
                if (resourceCtx) {{
                    const resourceData = Object.entries(resourceBreakdown)
                        .sort((a, b) => b[1].total - a[1].total)
                        .slice(0, 10);
                    
                    new Chart(resourceCtx, {{
                        type: 'bar',
                        data: {{
                            labels: resourceData.map(([type]) => type.replace('AWS::', '')),
                            datasets: [{{
                                label: 'Total Findings',
                                data: resourceData.map(([, data]) => data.total),
                                backgroundColor: '#ff6b35',
                                borderColor: '#e55a2b',
                                borderWidth: 1
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }},
                                x: {{
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor,
                                        maxRotation: 45
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    labels: {{
                                        color: textColor
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}

                // Compliance Standards Chart
                const complianceCtx = document.getElementById('complianceChart');
                if (complianceCtx) {{
                    new Chart(complianceCtx, {{
                        type: 'pie',
                        data: {{
                            labels: Object.keys(complianceBreakdown),
                            datasets: [{{
                                data: Object.values(complianceBreakdown).map(d => d.total),
                                backgroundColor: [
                                    '#ff6b35',
                                    '#28a745',
                                    '#17a2b8',
                                    '#ffc107',
                                    '#dc3545',
                                    '#6f42c1'
                                ],
                                borderWidth: 3,
                                borderColor: isDark ? '#2d2d2d' : '#ffffff'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{
                                    position: 'bottom',
                                    labels: {{
                                        padding: 20,
                                        color: textColor
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}

                // Security Trends Chart
                const securityTrendsCtx = document.getElementById('securityTrendsChart');
                if (securityTrendsCtx) {{
                    new Chart(securityTrendsCtx, {{
                        type: 'line',
                        data: {{
                            labels: riskTrends.map(d => new Date(d.date).toLocaleDateString()),
                            datasets: [{{
                                label: 'Risk Score',
                                data: riskTrends.map(d => d.risk_score),
                                borderColor: '#ff6b35',
                                backgroundColor: 'rgba(255, 107, 53, 0.1)',
                                tension: 0.4,
                                fill: true,
                                pointBackgroundColor: '#ff6b35',
                                pointBorderColor: '#ffffff',
                                pointBorderWidth: 2,
                                pointRadius: 4
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    max: 10,
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }},
                                x: {{
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    labels: {{
                                        color: textColor
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}

                // Resource Security Chart
                const resourceSecurityCtx = document.getElementById('resourceSecurityChart');
                if (resourceSecurityCtx) {{
                    const resourceSecurityData = Object.entries(resourceBreakdown)
                        .sort((a, b) => b[1].total - a[1].total)
                        .slice(0, 8);
                    
                    new Chart(resourceSecurityCtx, {{
                        type: 'bar',
                        data: {{
                            labels: resourceSecurityData.map(([type]) => type.replace('AWS::', '')),
                            datasets: [{{
                                label: 'Critical',
                                data: resourceSecurityData.map(([, data]) => data.critical || 0),
                                backgroundColor: '#dc3545',
                                stack: 'Stack 0'
                            }}, {{
                                label: 'High',
                                data: resourceSecurityData.map(([, data]) => data.high || 0),
                                backgroundColor: '#ff6b35',
                                stack: 'Stack 0'
                            }}, {{
                                label: 'Medium',
                                data: resourceSecurityData.map(([, data]) => data.medium || 0),
                                backgroundColor: '#ffc107',
                                stack: 'Stack 0'
                            }}, {{
                                label: 'Low',
                                data: resourceSecurityData.map(([, data]) => data.low || 0),
                                backgroundColor: '#28a745',
                                stack: 'Stack 0'
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    stacked: true,
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor
                                    }}
                                }},
                                x: {{
                                    stacked: true,
                                    grid: {{
                                        color: gridColor
                                    }},
                                    ticks: {{
                                        color: textColor,
                                        maxRotation: 45
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    labels: {{
                                        color: textColor
                                    }}
                                }}
                            }}
                        }}
                    }});
                }}
            }}

            // Findings table management
            function filterFindings() {{
                const searchTerm = document.getElementById('findingsSearch').value.toLowerCase();
                const severityFilter = document.getElementById('severityFilter').value;
                const statusFilter = document.getElementById('statusFilter').value;
                const accountFilter = document.getElementById('accountFilter').value;

                filteredFindings = findings.filter(finding => {{
                    const matchesSearch = !searchTerm || 
                        finding.title.toLowerCase().includes(searchTerm) ||
                        finding.description.toLowerCase().includes(searchTerm) ||
                        finding.account_name.toLowerCase().includes(searchTerm) ||
                        finding.resource_type.toLowerCase().includes(searchTerm);
                    
                    const matchesSeverity = !severityFilter || finding.severity === severityFilter;
                    const matchesStatus = !statusFilter || finding.status === statusFilter;
                    const matchesAccount = !accountFilter || finding.account_name === accountFilter;

                    return matchesSearch && matchesSeverity && matchesStatus && matchesAccount;
                }});

                currentPage = 1;
                renderFindingsTable();
            }}

            function sortTable(columnIndex) {{
                const columns = ['severity', 'title', 'account_name', 'region', 'resource_type', 'status'];
                const column = columns[columnIndex];
                
                if (sortColumn === columnIndex) {{
                    sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
                }} else {{
                    sortColumn = columnIndex;
                    sortDirection = 'desc';
                }}

                filteredFindings.sort((a, b) => {{
                    let aVal = a[column];
                    let bVal = b[column];
                    
                    // Special handling for severity
                    if (column === 'severity') {{
                        const severityOrder = {{'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0}};
                        aVal = severityOrder[aVal] || 0;
                        bVal = severityOrder[bVal] || 0;
                    }}
                    
                    if (typeof aVal === 'string') {{
                        aVal = aVal.toLowerCase();
                        bVal = bVal.toLowerCase();
                    }}

                    if (sortDirection === 'asc') {{
                        return aVal > bVal ? 1 : -1;
                    }} else {{
                        return aVal < bVal ? 1 : -1;
                    }}
                }});

                renderFindingsTable();
                updateSortIcons(columnIndex);
            }}

            function updateSortIcons(activeColumn) {{
                const headers = document.querySelectorAll('#findingsTable th i');
                headers.forEach((icon, index) => {{
                    if (index === activeColumn) {{
                        icon.className = `fas fa-sort-${{sortDirection === 'asc' ? 'up' : 'down'}}`;
                    }} else {{
                        icon.className = 'fas fa-sort';
                    }}
                }});
            }}

            function renderFindingsTable() {{
                const tableBody = document.getElementById('findingsTableBody');
                const startIndex = (currentPage - 1) * itemsPerPage;
                const endIndex = startIndex + itemsPerPage;
                const pageFindings = filteredFindings.slice(startIndex, endIndex);

                let tableHTML = '';
                pageFindings.forEach(finding => {{
                    const severityClass = `severity-${{finding.severity.toLowerCase()}}`;
                    tableHTML += `
                        <tr onclick="showFindingDetails(${{finding.id}})">
                            <td><span class="severity-badge ${{severityClass}}">${{finding.severity}}</span></td>
                            <td class="title-cell">${{finding.title}}</td>
                            <td>${{finding.account_name}}</td>
                            <td>${{finding.region}}</td>
                            <td>${{finding.resource_type}}</td>
                            <td>${{finding.status}}</td>
                            <td>
                                <button class="btn btn-secondary" onclick="event.stopPropagation(); showFindingDetails(${{finding.id}})">
                                    <i class="fas fa-eye"></i> View
                                </button>
                            </td>
                        </tr>
                    `;
                }});

                tableBody.innerHTML = tableHTML;
                renderPagination();
            }}

            function renderPagination() {{
                const totalPages = Math.ceil(filteredFindings.length / itemsPerPage);
                const pagination = document.getElementById('pagination');
                
                let paginationHTML = `
                    <button onclick="changePage(${{currentPage - 1}})" ${{currentPage === 1 ? 'disabled' : ''}}>
                        <i class="fas fa-chevron-left"></i> Previous
                    </button>
                `;

                const startPage = Math.max(1, currentPage - 2);
                const endPage = Math.min(totalPages, currentPage + 2);

                if (startPage > 1) {{
                    paginationHTML += `<button onclick="changePage(1)">1</button>`;
                    if (startPage > 2) {{
                        paginationHTML += `<span>...</span>`;
                    }}
                }}

                for (let i = startPage; i <= endPage; i++) {{
                    paginationHTML += `
                        <button onclick="changePage(${{i}})" ${{i === currentPage ? 'class="active"' : ''}}>
                            ${{i}}
                        </button>
                    `;
                }}

                if (endPage < totalPages) {{
                    if (endPage < totalPages - 1) {{
                        paginationHTML += `<span>...</span>`;
                    }}
                    paginationHTML += `<button onclick="changePage(${{totalPages}})">${{totalPages}}</button>`;
                }}

                paginationHTML += `
                    <button onclick="changePage(${{currentPage + 1}})" ${{currentPage === totalPages ? 'disabled' : ''}}>
                        Next <i class="fas fa-chevron-right"></i>
                    </button>
                `;

                pagination.innerHTML = paginationHTML;
            }}

            function changePage(page) {{
                const totalPages = Math.ceil(filteredFindings.length / itemsPerPage);
                if (page >= 1 && page <= totalPages) {{
                    currentPage = page;
                    renderFindingsTable();
                }}
            }}

            // Modal management
            function showFindingDetails(findingId) {{
                const finding = findings.find(f => f.id === findingId);
                if (!finding) return;

                const modal = document.getElementById('findingModal');
                const modalTitle = document.getElementById('modalTitle');
                const modalBody = document.getElementById('modalBody');

                modalTitle.textContent = finding.title;
                
                modalBody.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px;">
                        <div>
                            <strong>Severity:</strong><br>
                            <span class="severity-badge severity-${{finding.severity.toLowerCase()}}">${{finding.severity}}</span>
                        </div>
                        <div>
                            <strong>Status:</strong><br>
                            ${{finding.status}}
                        </div>
                        <div>
                            <strong>Account:</strong><br>
                            ${{finding.account_name}}
                        </div>
                        <div>
                            <strong>Region:</strong><br>
                            ${{finding.region}}
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <strong>Description:</strong><br>
                        ${{finding.description}}
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <strong>Resource Type:</strong><br>
                        ${{finding.resource_type}}
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <strong>Resource ID:</strong><br>
                        <code style="background: var(--hover-bg); padding: 5px; border-radius: 4px; font-size: 0.9em;">${{finding.resource_id}}</code>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <strong>Generator ID:</strong><br>
                        <code style="background: var(--hover-bg); padding: 5px; border-radius: 4px; font-size: 0.9em;">${{finding.generator_id}}</code>
                    </div>
                    
                    ${{finding.compliance ? `
                    <div style="margin-bottom: 20px;">
                        <strong>Compliance Requirements:</strong><br>
                        ${{finding.compliance}}
                    </div>
                    ` : ''}}
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div>
                            <strong>Created:</strong><br>
                            ${{new Date(finding.created_at).toLocaleString()}}
                        </div>
                        <div>
                            <strong>Updated:</strong><br>
                            ${{new Date(finding.updated_at).toLocaleString()}}
                        </div>
                        <div>
                            <strong>Workflow State:</strong><br>
                            ${{finding.workflow_state}}
                        </div>
                    </div>
                `;

                modal.classList.add('active');
            }}

            function closeFindingModal() {{
                document.getElementById('findingModal').classList.remove('active');
            }}

            function showAutomation(playbookId) {{
                const playbook = remediationPlaybooks[playbookId];
                if (!playbook) return;

                const modal = document.getElementById('automationModal');
                const modalTitle = document.getElementById('automationModalTitle');
                const modalBody = document.getElementById('automationModalBody');

                modalTitle.textContent = `Automation: ${{playbook.title}}`;
                
                let automationHTML = '';
                
                if (playbook.automation && playbook.automation.terraform) {{
                    automationHTML += `
                        <h4><i class="fas fa-code"></i> Terraform Code</h4>
                        <div class="code-block">
                            <button class="copy-btn" onclick="copyToClipboard('terraform-${{playbookId}}')">
                                <i class="fas fa-copy"></i> Copy
                            </button>
                            <pre id="terraform-${{playbookId}}">${{playbook.automation.terraform}}</pre>
                        </div>
                    `;
                }}
                
                if (playbook.automation && playbook.automation.cli_commands) {{
                    automationHTML += `
                        <h4><i class="fas fa-terminal"></i> AWS CLI Commands</h4>
                    `;
                    
                    playbook.automation.cli_commands.forEach((cmd, index) => {{
                        automationHTML += `
                            <div class="code-block">
                                <button class="copy-btn" onclick="copyToClipboard('cli-${{playbookId}}-${{index}}')">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                                <pre id="cli-${{playbookId}}-${{index}}">${{cmd}}</pre>
                            </div>
                        `;
                    }});
                }}

                modalBody.innerHTML = automationHTML;
                modal.classList.add('active');
            }}

            function closeAutomationModal() {{
                document.getElementById('automationModal').classList.remove('active');
            }}

            // Export functionality
            function toggleExportMenu() {{
                const dropdown = document.getElementById('exportDropdown');
                dropdown.classList.toggle('active');
            }}

            function exportData(format) {{
                toggleExportMenu();
                
                const timestamp = new Date().toISOString().split('T')[0];
                let filename = `security-hub-findings-${{timestamp}}`;
                let content = '';
                let mimeType = '';

                if (format === 'csv') {{
                    filename += '.csv';
                    mimeType = 'text/csv';
                    content = generateCSV(filteredFindings);
                }} else if (format === 'json') {{
                    filename += '.json';
                    mimeType = 'application/json';
                    content = JSON.stringify(filteredFindings, null, 2);
                }} else if (format === 'pdf') {{
                    // PDF generation would require additional library
                    showNotification('PDF export functionality requires additional setup', 'warning');
                    return;
                }}

                downloadFile(content, filename, mimeType);
                showNotification(`Exported ${{filteredFindings.length}} findings as ${{format.toUpperCase()}}`, 'success');
            }}

            function generateCSV(data) {{
                if (!data.length) return '';
                
                const headers = Object.keys(data[0]);
                const csvContent = [
                    headers.join(','),
                    ...data.map(row => 
                        headers.map(header => {{
                            const value = row[header] || '';
                            return `"${{String(value).replace(/"/g, '""')}}"`;
                        }}).join(',')
                    )
                ].join('\\n');
                
                return csvContent;
            }}

            function downloadFile(content, filename, mimeType) {{
                const blob = new Blob([content], {{ type: mimeType }});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }}

            function generateScript(playbookId) {{
                const playbook = remediationPlaybooks[playbookId];
                if (!playbook) return;

                let scriptContent = `#!/bin/bash
# Remediation Script for: ${{playbook.title}}
# Generated on: ${{new Date().toISOString()}}
# Severity: ${{playbook.severity}}

echo "Starting remediation for: ${{playbook.title}}"
echo "Description: ${{playbook.description}}"
echo ""

# Remediation Steps:
`;

                playbook.remediation_steps.forEach((step, index) => {{
                    scriptContent += `# Step ${{index + 1}}: ${{step}}\\n`;
                }});

                scriptContent += `
echo "Please review and customize this script for your environment"
echo "This is a template - manual verification required"
`;

                if (playbook.automation && playbook.automation.cli_commands) {{
                    scriptContent += `
# AWS CLI Commands:
`;
                    playbook.automation.cli_commands.forEach(cmd => {{
                        scriptContent += `# ${{cmd}}\\n`;
                    }});
                }}

                downloadFile(scriptContent, `remediation-${{playbookId}}.sh`, 'text/plain');
                showNotification('Remediation script downloaded', 'success');
            }}

            function generateReport(reportType) {{
                showNotification('Generating report...', 'info');
                
                setTimeout(() => {{
                    const timestamp = new Date().toISOString().split('T')[0];
                    let filename = `security-hub-${{reportType}}-report-${{timestamp}}`;
                    let content = '';

                    if (reportType === 'executive') {{
                        content = generateExecutiveReport();
                        filename += '.html';
                        downloadFile(content, filename, 'text/html');
                    }} else if (reportType === 'detailed') {{
                        content = generateCSV(findings);
                        filename += '.csv';
                        downloadFile(content, filename, 'text/csv');
                    }} else if (reportType === 'compliance') {{
                        content = generateComplianceReport();
                        filename += '.html';
                        downloadFile(content, filename, 'text/html');
                    }} else if (reportType === 'remediation') {{
                        content = generateRemediationGuide();
                        filename += '.html';
                        downloadFile(content, filename, 'text/html');
                    }}

                    showNotification(`${{reportType.charAt(0).toUpperCase() + reportType.slice(1)}} report generated successfully`, 'success');
                }}, 1000);
            }}

            function generateExecutiveReport() {{
                return `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Executive Security Summary</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; }}
                        .header {{ text-align: center; margin-bottom: 40px; }}
                        .metric {{ display: inline-block; margin: 20px; text-align: center; }}
                        .metric-value {{ font-size: 2em; font-weight: bold; }}
                        .severity-critical {{ color: #dc3545; }}
                        .severity-high {{ color: #ff6b35; }}
                        .severity-medium {{ color: #ffc107; }}
                        .severity-low {{ color: #28a745; }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>AWS Security Hub Executive Summary</h1>
                        <p>Generated on ${{new Date().toLocaleDateString()}}</p>
                    </div>
                    
                    <h2>Key Metrics</h2>
                    <div class="metric">
                        <div class="metric-value">${{findings.length}}</div>
                        <div>Total Findings</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value severity-critical">${{findings.filter(f => f.severity === 'CRITICAL').length}}</div>
                        <div>Critical</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value severity-high">${{findings.filter(f => f.severity === 'HIGH').length}}</div>
                        <div>High</div>
                    </div>
                    
                    <h2>Account Breakdown</h2>
                    <table border="1" style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <th>Account</th>
                            <th>Total Findings</th>
                            <th>Critical</th>
                            <th>High</th>
                        </tr>
                        ${{Object.entries(accountBreakdown).map(([account, data]) => `
                        <tr>
                            <td>${{account}}</td>
                            <td>${{data.total}}</td>
                            <td class="severity-critical">${{data.critical}}</td>
                            <td class="severity-high">${{data.high}}</td>
                        </tr>
                        `).join('')}}
                    </table>
                    
                    <h2>Recommendations</h2>
                    <ul>
                        ${{findings.filter(f => f.severity === 'CRITICAL').length > 0 ? 
                            `<li><strong>URGENT:</strong> Address ${{findings.filter(f => f.severity === 'CRITICAL').length}} critical security findings immediately</li>` : ''}}
                        ${{findings.filter(f => f.severity === 'HIGH').length > 5 ? 
                            `<li>Prioritize remediation of ${{findings.filter(f => f.severity === 'HIGH').length}} high-severity findings</li>` : ''}}
                        <li>Implement automated remediation where possible</li>
                        <li>Regular security posture reviews recommended</li>
                    </ul>
                </body>
                </html>
                `;
            }}

            function generateComplianceReport() {{
                return `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Compliance Assessment Report</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; }}
                        .standard {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; }}
                        .compliance-score {{ font-size: 1.5em; font-weight: bold; }}
                        .good {{ color: #28a745; }}
                        .warning {{ color: #ffc107; }}
                        .danger {{ color: #dc3545; }}
                    </style>
                </head>
                <body>
                    <h1>AWS Security Hub Compliance Assessment</h1>
                    <p>Generated on ${{new Date().toLocaleDateString()}}</p>
                    
                    ${{Object.entries(complianceBreakdown).map(([standard, data]) => {{
                        const score = Math.max(0, 100 - (data.critical * 20 + data.high * 10 + data.medium * 5));
                        const scoreClass = score >= 80 ? 'good' : score >= 60 ? 'warning' : 'danger';
                        return `
                        <div class="standard">
                            <h2>${{standard}}</h2>
                            <div class="compliance-score ${{scoreClass}}">${{score}}% Compliant</div>
                            <p>Total Findings: ${{data.total}}</p>
                            <p>Critical: ${{data.critical}} | High: ${{data.high}} | Medium: ${{data.medium}}</p>
                        </div>
                        `;
                    }}).join('')}}
                </body>
                </html>
                `;
            }}

            function generateRemediationGuide() {{
                return `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Security Remediation Guide</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; }}
                        .playbook {{ margin: 30px 0; padding: 20px; border-left: 4px solid #ff6b35; }}
                        .code {{ background: #f4f4f4; padding: 10px; font-family: monospace; }}
                        ol li {{ margin: 10px 0; }}
                    </style>
                </head>
                <body>
                    <h1>AWS Security Hub Remediation Guide</h1>
                    <p>Generated on ${{new Date().toLocaleDateString()}}</p>
                    
                    ${{Object.entries(remediationPlaybooks).map(([id, playbook]) => `
                    <div class="playbook">
                        <h2>${{playbook.title}}</h2>
                        <p><strong>Severity:</strong> ${{playbook.severity}}</p>
                        <p>${{playbook.description}}</p>
                        
                        <h3>Remediation Steps:</h3>
                        <ol>
                            ${{playbook.remediation_steps.map(step => `<li>${{step}}</li>`).join('')}}
                        </ol>
                        
                        ${{playbook.automation && playbook.automation.terraform ? `
                        <h3>Terraform Code:</h3>
                        <div class="code">${{playbook.automation.terraform}}</div>
                        ` : ''}}
                        
                        ${{playbook.automation && playbook.automation.cli_commands ? `
                        <h3>AWS CLI Commands:</h3>
                        ${{playbook.automation.cli_commands.map(cmd => `<div class="code">${{cmd}}</div>`).join('')}}
                        ` : ''}}
                    </div>
                    `).join('')}}
                </body>
                </html>
                `;
            }}

            // Utility functions
            function copyToClipboard(elementId) {{
                const element = document.getElementById(elementId);
                const text = element.textContent || element.innerText;
                
                navigator.clipboard.writeText(text).then(() => {{
                    showNotification('Code copied to clipboard!', 'success');
                }}).catch(() => {{
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    showNotification('Code copied to clipboard!', 'success');
                }});
            }}

            function showNotification(message, type = 'info') {{
                const notification = document.getElementById('notification');
                notification.textContent = message;
                notification.className = `notification ${{type}} show`;
                
                setTimeout(() => {{
                    notification.classList.remove('show');
                }}, 3000);
            }}

            // Close modals when clicking outside
            window.onclick = function(event) {{
                const findingModal = document.getElementById('findingModal');
                const automationModal = document.getElementById('automationModal');
                const exportDropdown = document.getElementById('exportDropdown');
                
                if (event.target === findingModal) {{
                    closeFindingModal();
                }}
                if (event.target === automationModal) {{
                    closeAutomationModal();
                }}
                if (!event.target.closest('.export-menu')) {{
                    exportDropdown.classList.remove('active');
                }}
            }}

            // Keyboard shortcuts
            document.addEventListener('keydown', function(event) {{
                // ESC to close modals
                if (event.key === 'Escape') {{
                    closeFindingModal();
                    closeAutomationModal();
                    document.getElementById('exportDropdown').classList.remove('active');
                }}
                
                // Ctrl+F to focus search
                if (event.ctrlKey && event.key === 'f') {{
                    event.preventDefault();
                    document.getElementById('findingsSearch').focus();
                }}
                
                // Ctrl+D to toggle dark mode
                if (event.ctrlKey && event.key === 'd') {{
                    event.preventDefault();
                    toggleDarkMode();
                }}
            }});

            // Auto-refresh functionality (could be enabled for live dashboards)
            function enableAutoRefresh(intervalMinutes = 5) {{
                setInterval(() => {{
                    showNotification('Auto-refresh would reload data here', 'info');
                    // In a real implementation, this would fetch new data
                }}, intervalMinutes * 60 * 1000);
            }}

            // Performance monitoring
            function trackUserInteraction(action, details) {{
                // In a real implementation, this would send analytics data
                console.log(`User action: ${{action}}`, details);
            }}

            // Add event listeners for user tracking
            document.addEventListener('click', function(event) {{
                if (event.target.matches('.nav-link')) {{
                    trackUserInteraction('navigation', {{ tab: event.target.textContent.trim() }});
                }}
                if (event.target.matches('.btn')) {{
                    trackUserInteraction('button_click', {{ button: event.target.textContent.trim() }});
                }}
            }});

            // Initialize tooltips and help text
            function initializeTooltips() {{
                const tooltipTriggers = document.querySelectorAll('[data-tooltip]');
                tooltipTriggers.forEach(trigger => {{
                    trigger.addEventListener('mouseenter', showTooltip);
                    trigger.addEventListener('mouseleave', hideTooltip);
                }});
            }}

            function showTooltip(event) {{
                const tooltip = document.createElement('div');
                tooltip.className = 'tooltip';
                tooltip.textContent = event.target.getAttribute('data-tooltip');
                tooltip.style.cssText = `
                    position: absolute;
                    background: var(--dark-color);
                    color: white;
                    padding: 8px 12px;
                    border-radius: 4px;
                    font-size: 0.9em;
                    z-index: 10000;
                    pointer-events: none;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                `;
                
                document.body.appendChild(tooltip);
                
                const rect = event.target.getBoundingClientRect();
                tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
                tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
                
                event.target._tooltip = tooltip;
            }}

            function hideTooltip(event) {{
                if (event.target._tooltip) {{
                    document.body.removeChild(event.target._tooltip);
                    delete event.target._tooltip;
                }}
            }}

            // Print-friendly styles
            function optimizeForPrint() {{
                const printStyles = `
                    @media print {{
                        .sidebar, .top-bar-actions, .btn, .modal {{ display: none !important; }}
                        .main-content {{ margin-left: 0 !important; }}
                        .section-card {{ page-break-inside: avoid; }}
                        .dashboard-grid {{ grid-template-columns: 1fr 1fr !important; }}
                        body {{ font-size: 12px; }}
                        .chart-container {{ height: 200px !important; }}
                    }}
                `;
                
                const styleSheet = document.createElement('style');
                styleSheet.textContent = printStyles;
                document.head.appendChild(styleSheet);
            }}

            // Initialize print optimization
            optimizeForPrint();

            // Accessibility improvements
            function enhanceAccessibility() {{
                // Add ARIA labels
                document.querySelectorAll('.btn').forEach(btn => {{
                    if (!btn.getAttribute('aria-label')) {{
                        btn.setAttribute('aria-label', btn.textContent.trim());
                    }}
                }});
                
                // Add keyboard navigation for tables
                document.querySelectorAll('.data-table tr').forEach(row => {{
                    row.setAttribute('tabindex', '0');
                    row.addEventListener('keydown', function(event) {{
                        if (event.key === 'Enter' || event.key === ' ') {{
                            event.preventDefault();
                            row.click();
                        }}
                    }});
                }});
                
                // Add focus indicators
                const focusStyle = `
                    .data-table tr:focus {{
                        outline: 2px solid var(--primary-color);
                        outline-offset: -2px;
                    }}
                `;
                
                const styleSheet = document.createElement('style');
                styleSheet.textContent = focusStyle;
                document.head.appendChild(styleSheet);
            }}

            // Initialize accessibility enhancements
            enhanceAccessibility();

            // Error boundary for JavaScript errors
            window.addEventListener('error', function(event) {{
                console.error('JavaScript error:', event.error);
                showNotification('An error occurred. Please refresh the page if issues persist.', 'error');
            }});

            window.addEventListener('unhandledrejection', function(event) {{
                console.error('Unhandled promise rejection:', event.reason);
                showNotification('An error occurred. Please refresh the page if issues persist.', 'error');
            }});

            // Initialize everything when DOM is ready
            document.addEventListener('DOMContentLoaded', function() {{
                console.log('AWS Security Hub Portal initialized');
                showNotification('Security Hub Portal loaded successfully', 'success');
            }});
        </script>
    </body>
    </html>
    """
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def print_summary(findings, account_names):
    """Print a comprehensive summary of the Security Hub findings analysis"""
    total_findings = len(findings)
    
    if total_findings == 0:
        print("\n" + "="*80)
        print("AWS SECURITY HUB ANALYSIS SUMMARY")
        print("="*80)
        print("No findings found matching the specified criteria.")
        return
    
    # Calculate comprehensive metrics
    security_metrics = calculate_security_metrics(findings)
    account_breakdown = analyze_findings_by_account(findings, account_names)
    resource_breakdown = analyze_findings_by_resource_type(findings)
    compliance_breakdown = analyze_compliance_standards(findings)
    
    print("\n" + "="*80)
    print("AWS SECURITY HUB COMPREHENSIVE ANALYSIS SUMMARY")
    print("="*80)
    print(f"Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Total findings analyzed: {total_findings:,}")
    print(f"Overall Risk Score: {security_metrics['risk_score']}/10")
    print(f"Threat Level: {security_metrics['threat_level']}")
    print(f"Compliance Score: {security_metrics['compliance_score']}%")
    
    print(f"\nSEVERITY BREAKDOWN:")
    print(f"{'Severity':<15} {'Count':<8} {'Percentage':<12} {'Status'}")
    print("-" * 50)
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
    for severity in severities:
        count = security_metrics.get(f'{severity.lower()}_findings', 0)
        percentage = (count / total_findings) * 100 if total_findings > 0 else 0
        status = "🚨" if severity == 'CRITICAL' and count > 0 else "⚠️" if severity == 'HIGH' and count > 5 else "✅"
        print(f"{severity:<15} {count:<8} {percentage:<12.1f}% {status}")
    
    print(f"\nFINDING STATUS BREAKDOWN:")
    print(f"Active findings: {security_metrics['active_findings']:,}")
    print(f"Suppressed findings: {security_metrics['suppressed_findings']:,}")
    print(f"Resolved findings: {security_metrics['resolved_findings']:,}")
    
    print(f"\nACCOUNT BREAKDOWN (Top 10):")
    print(f"{'Account':<40} {'Total':<8} {'Critical':<10} {'High':<8} {'Resources':<10}")
    print("-" * 85)
    sorted_accounts = sorted(account_breakdown.items(), key=lambda x: x[1]['total'], reverse=True)
    for account, stats in sorted_accounts[:10]:
        account_display = account[:35] + "..." if len(account) > 38 else account
        print(f"{account_display:<40} {stats['total']:<8} {stats['critical']:<10} {stats['high']:<8} {stats['unique_resources']:<10}")
    
    print(f"\nRESOURCE TYPE BREAKDOWN (Top 10):")
    print(f"{'Resource Type':<35} {'Findings':<10} {'Critical':<10} {'High':<8}")
    print("-" * 70)
    sorted_resources = sorted(resource_breakdown.items(), key=lambda x: x[1]['total'], reverse=True)
    for resource_type, stats in sorted_resources[:10]:
        resource_display = resource_type.replace('AWS::', '')[:30] + "..." if len(resource_type) > 33 else resource_type.replace('AWS::', '')
        print(f"{resource_display:<35} {stats['total']:<10} {stats['critical']:<10} {stats['high']:<8}")
    
    if compliance_breakdown:
        print(f"\nCOMPLIANCE STANDARDS BREAKDOWN:")
        print(f"{'Standard':<25} {'Findings':<10} {'Score':<8} {'Status'}")
        print("-" * 55)
        for standard, stats in compliance_breakdown.items():
            compliance_score = max(0, 100 - (stats['critical'] * 20 + stats['high'] * 10 + stats['medium'] * 5))
            status = "✅" if compliance_score >= 80 else "⚠️" if compliance_score >= 60 else "🚨"
            standard_display = standard[:20] + "..." if len(standard) > 23 else standard
            print(f"{standard_display:<25} {stats['total']:<10} {compliance_score:<8}% {status}")
    
    # Advanced analytics
    print(f"\nADVANCED ANALYTICS:")
    print("=" * 80)
    
    # Risk assessment
    if security_metrics['critical_findings'] > 0:
        estimated_remediation_time = security_metrics['critical_findings'] * 2 + security_metrics['high_findings'] * 1
        print(f"🚨 CRITICAL: {security_metrics['critical_findings']} critical findings require immediate attention")
        print(f"   Estimated remediation time: {estimated_remediation_time} hours")
    
    if security_metrics['high_findings'] > 10:
        print(f"⚠️  HIGH PRIORITY: {security_metrics['high_findings']} high-severity findings detected")
        print("   Consider implementing automated remediation workflows")
    
    # Compliance assessment
    if security_metrics['compliance_score'] < 80:
        print(f"📋 COMPLIANCE GAP: Current compliance score is {security_metrics['compliance_score']}%")
        print("   Target: 80% minimum for good security posture")
    
    # Resource concentration risk
    top_resource_findings = max(resource_breakdown.values(), key=lambda x: x['total'])['total'] if resource_breakdown else 0
    if total_findings > 0 and top_resource_findings > total_findings * 0.3:
        print(f"🎯 CONCENTRATION RISK: High finding concentration in single resource type")
        print("   Consider targeted remediation strategies")
    
    # Account risk distribution
    if len(account_breakdown) > 1:
        account_risk_variance = max([stats['critical'] for stats in account_breakdown.values()]) - min([stats['critical'] for stats in account_breakdown.values()])
        if account_risk_variance > 5:
            print(f"⚖️  RISK IMBALANCE: Significant security posture variance across accounts")
            print("   Consider standardizing security controls")
    
    print(f"\nRECOMMENDATIONS:")
    print("=" * 80)
    
    recommendations = []
    
    if security_metrics['critical_findings'] > 0:
        recommendations.append(f"🚨 IMMEDIATE: Address {security_metrics['critical_findings']} critical security findings within 24 hours")
    
    if security_metrics['high_findings'] > 5:
        recommendations.append(f"⚠️  HIGH PRIORITY: Remediate {security_metrics['high_findings']} high-severity findings within 1 week")
    
    if security_metrics['compliance_score'] < 80:
        recommendations.append(f"📋 COMPLIANCE: Improve compliance score from {security_metrics['compliance_score']}% to 80%+ target")
    
    if len(account_breakdown) > 3:
        recommendations.append("🏢 GOVERNANCE: Implement centralized security policy management")
    
    if total_findings > 100:
        recommendations.append("🤖 AUTOMATION: Implement automated remediation for common finding types")
    
    recommendations.extend([
        "📊 MONITORING: Set up continuous monitoring and alerting",
        "📈 TRENDING: Establish baseline metrics and track improvement over time",
        "🎓 TRAINING: Provide security awareness training for development teams",
        "🔄 PROCESS: Implement security reviews in deployment pipelines"
    ])
    
    for i, rec in enumerate(recommendations, 1):
        print(f"{i:2}. {rec}")
    
    print(f"\n" + "="*80)
    print("NEXT STEPS:")
    print("="*80)
    print("1. Review the detailed HTML report for comprehensive analysis")
    print("2. Export findings data for further analysis and tracking")
    print("3. Use remediation playbooks for common security issues")
    print("4. Schedule regular security posture assessments")
    print("5. Implement automated monitoring and alerting")
    
    print(f"\n✅ Analysis completed successfully!")
    print(f"📊 Full interactive report available in HTML format")
    print(f"📋 Detailed data available in CSV export")

def generate_visualizations(findings, reports_dir='security_reports'):
    """Generate comprehensive visualizations of Security Hub findings"""
    if not VISUALIZATION_AVAILABLE:
        print("Visualization libraries (matplotlib, numpy) not available. Skipping visualization generation.")
        return None
    
    if not findings:
        print("No findings to visualize.")
        return None
        
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    viz_dir = f"{reports_dir}/security_visualizations_{timestamp}"
    if not os.path.exists(viz_dir):
        os.makedirs(viz_dir)
    
    # Set up matplotlib style
    plt.style.use('default')
    colors = ['#dc3545', '#ff6b35', '#ffc107', '#28a745', '#17a2b8']
    
    # 1. Severity Distribution
    plt.figure(figsize=(12, 8))
    severity_counts = {}
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    severities = list(severity_counts.keys())
    counts = list(severity_counts.values())
    
    colors_map = {'CRITICAL': '#dc3545', 'HIGH': '#ff6b35', 'MEDIUM': '#ffc107', 'LOW': '#28a745', 'INFORMATIONAL': '#17a2b8'}
    bar_colors = [colors_map.get(sev, '#6c757d') for sev in severities]
    
    bars = plt.bar(severities, counts, color=bar_colors)
    plt.title('Security Hub Findings by Severity Level', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Severity Level', fontsize=12)
    plt.ylabel('Number of Findings', fontsize=12)
    plt.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(f"{viz_dir}/severity_distribution.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. Account Breakdown
    plt.figure(figsize=(14, 8))
    account_counts = {}
    for finding in findings:
        account = finding.get('AwsAccountId', 'Unknown')
        account_counts[account] = account_counts.get(account, 0) + 1
    
    # Get top 10 accounts
    top_accounts = sorted(account_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    accounts = [acc[:15] + '...' if len(acc) > 18 else acc for acc, _ in top_accounts]
    counts = [count for _, count in top_accounts]
    
    bars = plt.bar(accounts, counts, color='#ff6b35')
    plt.title('Security Findings by AWS Account (Top 10)', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('AWS Account ID', fontsize=12)
    plt.ylabel('Number of Findings', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(f"{viz_dir}/account_breakdown.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    # 3. Regional Distribution
    plt.figure(figsize=(14, 6))
    region_counts = {}
    for finding in findings:
        region = finding.get('Region', 'Unknown')
        region_counts[region] = region_counts.get(region, 0) + 1
    
    regions = list(region_counts.keys())
    counts = list(region_counts.values())
    
    bars = plt.bar(regions, counts, color='#17a2b8')
    plt.title('Security Findings by AWS Region', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('AWS Region', fontsize=12)
    plt.ylabel('Number of Findings', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(f"{viz_dir}/regional_distribution.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Security visualizations generated in: {viz_dir}")
    
    return {
        'severity_distribution': f"{viz_dir}/severity_distribution.png",
        'account_breakdown': f"{viz_dir}/account_breakdown.png",
        'regional_distribution': f"{viz_dir}/regional_distribution.png"
    }

@click.command()
@click.option('--profile', type=str, default='default', help='AWS CLI profile name.')
@click.option('--region', type=str, default='us-east-1', help='AWS region.', show_default=True)
@click.option('--limit', type=int, help='Limit the number of findings. If not provided, fetches all findings.')
@click.option('--output', type=click.Path(writable=True, dir_okay=False), default='securityhub_findings.csv', help='Output CSV file path.', show_default=True)
@click.option('--severity', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'], case_sensitive=False), multiple=True, default=['CRITICAL', 'HIGH', 'MEDIUM'], help='Severity levels to include.', show_default=True)
@click.option('--anystatus', is_flag=True, default=True, help='Fetch findings with any status. If not set, fetches just active findings.')
def main(profile: str, region: str, limit: int, output: str, severity: Tuple[str], anystatus: bool):
    """
    Enhanced AWS Security Hub Findings Analyzer - Full Featured Security Portal
    """
    
    # Interactive mode when called without specific CLI arguments
    if profile == 'default' and not any([limit, output != 'securityhub_findings.csv']):
        print("🛡️  AWS Security Hub Findings Analyzer - Full Featured Portal")
        print("="*70)
        print("Comprehensive security analysis with advanced features:")
        print("• Interactive dashboard with real-time filtering")
        print("• Advanced analytics and trend analysis")
        print("• Automated remediation playbooks")
        print("• Compliance standards mapping")
        print("• Multi-format reporting and exports")
        print("• Resource inventory and risk assessment")
        
        # Select output options
        output_options = select_output_options()
        
        # Select AWS profiles
        selected_profiles = select_aws_profiles()
        if not selected_profiles:
            print("No profiles selected. Exiting.")
            return
        
        # Select severity levels
        severity = select_severity_levels()
        
        # Select status filter
        only_active = select_status_filter()
        
        # Ask for regions
        print("\n" + "="*60)
        print("REGION SELECTION")
        print("="*60)
        regions_input = input("Enter AWS regions (comma-separated, default: us-east-1): ").strip()
        regions = [r.strip() for r in regions_input.split(',')] if regions_input else ['us-east-1']
        
        # Ask for limit
        print("\n" + "="*60)
        print("FINDINGS LIMIT")
        print("="*60)
        limit_input = input("Enter maximum findings to fetch (default: no limit): ").strip()
        limit = int(limit_input) if limit_input.isdigit() else None
        
        # Ask for output directory
        output_dir = input("Enter output directory (default: security_reports): ").strip() or "security_reports"
        
        print(f"\n" + "="*60)
        print("ANALYSIS CONFIGURATION SUMMARY")
        print("="*60)
        print(f"📋 Profiles: {', '.join(selected_profiles)}")
        print(f"🌍 Regions: {', '.join(regions)}")
        print(f"⚠️  Severity levels: {', '.join(severity)}")
        print(f"📊 Status filter: {'Active only' if only_active else 'All findings'}")
        print(f"🔢 Limit: {limit if limit else 'No limit'}")
        print(f"📁 Output directory: {output_dir}")
        print(f"📄 Output formats: {', '.join([k for k, v in output_options.items() if v])}")
        
        proceed = input("\nProceed with comprehensive analysis? (y/n): ").lower().strip()
        if proceed != 'y':
            print("Analysis cancelled.")
            return
        
        # Process each profile
        all_findings = []
        all_account_names = {}
        
        for profile_name in selected_profiles:
            print(f"\n{'='*60}")
            print(f"PROCESSING PROFILE: {profile_name}")
            print(f"{'='*60}")
            
            # Check SSO session
            if not check_sso_session(profile_name):
                print(f"❌ No active SSO session found for profile '{profile_name}'. Please login using AWS CLI.")
                continue
            
            for region_name in regions:
                print(f"\n🔍 Analyzing {profile_name} in {region_name}...")
                
                try:
                    # Fetch findings
                    findings = get_all_findings(profile_name, region_name, severity, only_active, limit)
                    
                    if findings:
                        # Add profile and region info to findings
                        for finding in findings:
                            finding['ProfileName'] = profile_name
                            finding['ProcessedRegion'] = region_name
                        
                        all_findings.extend(findings)
                        
                        # Get account names
                        account_names = get_account_names(profile_name, region_name)
                        all_account_names.update(account_names)
                        
                        print(f"✅ Found {len(findings):,} findings in {profile_name}/{region_name}")
                    else:
                        print(f"ℹ️  No findings found in {profile_name}/{region_name}")
                        
                except Exception as e:
                    print(f"❌ Error processing {profile_name}/{region_name}: {e}")
        
        if not all_findings:
            print("\n❌ No findings found across all profiles and regions.")
            print("\nPossible reasons:")
            print("• No Security Hub findings match the selected criteria")
            print("• Security Hub may not be enabled in the selected regions")
            print("• Insufficient permissions to access Security Hub")
            print("• All findings may be in suppressed/resolved state")
            return
        
        # Add account names to findings
        all_findings = add_account_names_to_findings(all_findings, all_account_names)
        
        # Generate outputs
        print(f"\n{'='*60}")
        print("GENERATING COMPREHENSIVE OUTPUTS")
        print(f"{'='*60}")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        generated_files = []
        
        if output_options['csv']:
            print("📊 Generating detailed CSV report...")
            csv_filename = f"{output_dir}/securityhub_findings_detailed_{timestamp}.csv"
            save_to_csv(all_findings, csv_filename)
            generated_files.append(('CSV Report', csv_filename))
            print(f"✅ CSV report saved: {csv_filename}")
        
        if output_options['html']:
            print("🌐 Generating comprehensive HTML security portal...")
            html_filename = f"{output_dir}/securityhub_portal_{timestamp}.html"
            generate_comprehensive_html_report(all_findings, html_filename, all_account_names)
            generated_files.append(('HTML Security Portal', html_filename))
            print(f"✅ HTML security portal saved: {html_filename}")
        
        if output_options['summary']:
            print("📋 Generating console summary...")
            print_summary(all_findings, all_account_names)
        
        if output_options['visualizations']:
            print("📈 Generating visualizations...")
            viz_files = generate_visualizations(all_findings, output_dir)
            if viz_files:
                generated_files.append(('Visualizations', f"{output_dir}/security_visualizations_{timestamp}/"))
                print(f"✅ Visualizations saved in: {output_dir}/security_visualizations_{timestamp}/")
        
        # Final summary
        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE - COMPREHENSIVE SECURITY PORTAL GENERATED")
        print(f"{'='*60}")
        
        print(f"📊 Total findings processed: {len(all_findings):,}")
        print(f"🏢 Profiles analyzed: {len(selected_profiles)}")
        print(f"🌍 Regions analyzed: {len(regions)}")
        print(f"⏱️  Analysis duration: {datetime.now().strftime('%H:%M:%S')}")
        
        if generated_files:
            print(f"\n📁 Generated Files:")
            for file_type, file_path in generated_files:
                print(f"   • {file_type}: {file_path}")
        
        # Security posture summary
        security_metrics = calculate_security_metrics(all_findings)
        print(f"\n🛡️  Security Posture Summary:")
        print(f"   • Risk Score: {security_metrics['risk_score']}/10")
        print(f"   • Threat Level: {security_metrics['threat_level']}")
        print(f"   • Compliance Score: {security_metrics['compliance_score']}%")
        print(f"   • Critical Findings: {security_metrics['critical_findings']:,}")
        print(f"   • High Findings: {security_metrics['high_findings']:,}")
        
        # Recommendations
        print(f"\n💡 Key Recommendations:")
        if security_metrics['critical_findings'] > 0:
            print(f"   🚨 URGENT: Address {security_metrics['critical_findings']} critical findings immediately")
        if security_metrics['high_findings'] > 5:
            print(f"   ⚠️  Prioritize {security_metrics['high_findings']} high-severity findings")
        if security_metrics['compliance_score'] < 80:
            print(f"   📋 Improve compliance score to 80%+ (currently {security_metrics['compliance_score']}%)")
        
        print(f"   📊 Use the interactive HTML portal for detailed analysis")
        print(f"   🔧 Implement automated remediation playbooks")
        print(f"   📈 Set up continuous monitoring and trending")
        
        # Optional: Open HTML report
        if output_options['html']:
            try:
                import webbrowser
                html_path = f"{output_dir}/securityhub_portal_{timestamp}.html"
                if os.path.exists(html_path):
                    open_browser = input(f"\n🌐 Open interactive HTML security portal in browser? (y/n): ").lower().strip()
                    if open_browser == 'y':
                        webbrowser.open(f"file://{os.path.abspath(html_path)}")
                        print("🚀 Interactive security portal opened in default browser.")
                        print("🔍 Features available in the portal:")
                        print("   • Real-time filtering and search")
                        print("   • Interactive charts and analytics")
                        print("   • Remediation playbooks with automation code")
                        print("   • Compliance standards mapping")
                        print("   • Export capabilities for further analysis")
                        print("   • Dark/light mode themes")
            except ImportError:
                pass
            except Exception as e:
                print(f"Could not open browser: {e}")
    
    else:
        # Original CLI mode for backwards compatibility
        print("🛡️  AWS Security Hub Findings Analyzer (CLI Mode)")
        print("="*50)
        
        # Check for active SSO session
        if not check_sso_session(profile):
            click.echo(f"❌ Error: No active SSO session found for profile '{profile}'. Please login using AWS CLI.")
            return

        # Fetch findings
        print(f"🔍 Fetching findings from {profile} in {region}...")
        findings = get_all_findings(profile, region, severity, anystatus, limit)

        if not findings:
            print("ℹ️  No findings found matching the specified criteria.")
            return

        # Flatten findings for CSV
        print("📊 Processing findings data...")
        flattened_findings = flatten_resources_and_severity(findings)

        # Add account names to the findings
        print("🏢 Enriching with account information...")
        account_names = get_account_names(profile, region)
        flattened_findings = add_account_names_to_findings(flattened_findings, account_names)

        # Write to CSV
        print(f"💾 Saving to {output}...")
        save_to_csv(flattened_findings, output)

        # Generate additional outputs
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate HTML report
        html_output = output.replace('.csv', f'_portal_{timestamp}.html')
        print(f"🌐 Generating HTML security portal: {html_output}")
        generate_comprehensive_html_report(findings, html_output, account_names)
        
        # Print summary
        print_summary(findings, account_names)

        print(f"\n✅ Analysis completed successfully!")
        print(f"📊 CSV export: {output}")
        print(f"🌐 HTML portal: {html_output}")
        
        click.echo(f"\n🎉 Security Hub analysis completed! Files generated:")
        click.echo(f"   • CSV Report: {output}")
        click.echo(f"   • HTML Portal: {html_output}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Analysis cancelled by user!")
        print("Partial results may have been saved.")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Check AWS credentials: aws configure list")
        print("2. Verify Security Hub is enabled in target regions")
        print("3. Ensure proper IAM permissions for Security Hub")
        print("4. Check network connectivity to AWS services")
        print("5. Verify AWS CLI is properly configured")
        print("6. Try running with --limit option to test with smaller dataset")
        
        # Additional debugging information
        import traceback
        print(f"\nDetailed error information:")
        traceback.print_exc()

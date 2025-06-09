#!/usr/bin/env python3
"""
AWS Security Hub Findings Analyzer

A comprehensive tool to analyze Security Hub findings across AWS accounts,
generate detailed reports, and provide actionable insights.

Usage:
    python securityhub_analyzer.py [options]

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
    print("2. HTML Report")
    print("3. Console Summary")
    print("4. Visualizations (requires matplotlib)")
    print("5. All outputs")
    
    if not VISUALIZATION_AVAILABLE:
        print("\nNote: Visualizations require matplotlib and numpy libraries")
        print("Install with: pip install matplotlib numpy")
    
    print("\nSelect outputs (comma-separated numbers, default: 1,3):")
    selection = input("> ").strip()
    
    # Default selection if nothing entered
    if not selection:
        selection = "1,3"
    
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
        print("Invalid input. Using default outputs (CSV + Summary)")
        outputs['csv'] = True
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
    """Calculate security metrics and analytics"""
    if not findings:
        return {
            'risk_score': 0.0,
            'critical_findings': 0,
            'compliance_score': 100,
            'threat_level': 'LOW'
        }
    
    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL')
    high_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'HIGH')
    medium_findings = sum(1 for f in findings if f.get('Severity', {}).get('Label') == 'MEDIUM')
    
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
        'compliance_score': int(compliance_score),
        'threat_level': threat_level
    }

def generate_html_report(findings, output_file, account_names):
    """Generate enhanced HTML report with interactive features"""
    
    security_metrics = calculate_security_metrics(findings)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Group findings by various dimensions
    severity_breakdown = {}
    compliance_breakdown = {}
    resource_breakdown = {}
    
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        
        compliance_id = finding.get('ProductFields', {}).get('StandardsArn', 'Unknown')
        compliance_breakdown[compliance_id] = compliance_breakdown.get(compliance_id, 0) + 1
        
        resources = finding.get('Resources', [])
        for resource in resources:
            resource_type = resource.get('Type', 'Unknown')
            resource_breakdown[resource_type] = resource_breakdown.get(resource_type, 0) + 1

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AWS Security Hub Analysis Report - {timestamp}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
            }}
            
            * {{
                transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
            }}
            
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 0; 
                padding: 20px;
                background-color: var(--bg-color);
                color: var(--text-color);
                line-height: 1.6;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background-color: var(--card-bg);
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            
            .header {{
                background: linear-gradient(135degree, var(--primary-color), var(--danger-color));
                color: white;
                padding: 30px;
                position: relative;
            }}
            
            .header h1 {{ 
                margin: 0;
                font-size: 2.5em;
                font-weight: 300;
            }}
            
            .header p {{
                margin: 10px 0 0 0;
                font-size: 1.1em;
                opacity: 0.9;
            }}
            
            .dark-mode-toggle {{
                position: absolute;
                top: 20px;
                right: 20px;
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                padding: 10px 15px;
                border-radius: 20px;
                cursor: pointer;
                font-size: 16px;
                transition: all 0.3s ease;
            }}
            
            .dark-mode-toggle:hover {{
                background: rgba(255,255,255,0.3);
                transform: scale(1.05);
            }}
            
            .content {{
                padding: 30px;
            }}
            
            .dashboard-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }}
            
            .dashboard-card {{
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 25px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                transition: all 0.3s ease;
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
                font-size: 2em;
                margin-right: 15px;
            }}
            
            .card-title {{
                font-size: 1.3em;
                font-weight: 600;
                color: var(--text-color);
                margin: 0;
            }}
            
            .metric-large {{
                font-size: 2.5em;
                font-weight: 700;
                color: var(--primary-color);
                margin: 10px 0;
            }}
            
            .metric-small {{
                font-size: 1.1em;
                color: var(--text-color);
                opacity: 0.8;
            }}
            
            .threat-critical {{ color: var(--danger-color); }}
            .threat-high {{ color: #ff6b35; }}
            .threat-medium {{ color: var(--warning-color); }}
            .threat-low {{ color: var(--success-color); }}
            
            .collapsible {{
                cursor: pointer;
                padding: 15px 20px;
                background: var(--hover-bg);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                margin: 10px 0;
                transition: all 0.3s ease;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            
            .collapsible:hover {{
                background: var(--primary-color);
                color: white;
            }}
            
            .collapsible.active {{
                background: var(--primary-color);
                color: white;
            }}
            
            .collapsible-content {{
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.3s ease;
                background: var(--card-bg);
                border: 1px solid var(--border-color);
                border-top: none;
                border-radius: 0 0 8px 8px;
            }}
            
            .collapsible-content.active {{
                padding: 20px;
            }}
            
            .chart-container {{
                position: relative;
                height: 300px;
                margin: 20px 0;
            }}
            
            table {{ 
                border-collapse: collapse; 
                width: 100%; 
                margin: 20px 0;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            
            th {{ 
                background: linear-gradient(135deg, var(--primary-color), var(--danger-color));
                color: white;
                text-align: left; 
                padding: 15px 12px;
                font-weight: 500;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            td {{ 
                border-bottom: 1px solid var(--border-color); 
                text-align: left; 
                padding: 12px;
                vertical-align: top;
            }}
            
            tr:nth-child(even) {{ 
                background-color: var(--hover-bg); 
            }}
            
            tr:hover {{
                background-color: #fff3e0;
                transition: background-color 0.2s ease;
            }}
            
            .severity-badge {{
                display: inline-block;
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            .severity-critical {{
                background-color: rgba(220, 53, 69, 0.2);
                color: var(--danger-color);
            }}
            
            .severity-high {{
                background-color: rgba(255, 107, 53, 0.2);
                color: #ff6b35;
            }}
            
            .severity-medium {{
                background-color: rgba(255, 193, 7, 0.2);
                color: #856404;
            }}
            
            .severity-low {{
                background-color: rgba(40, 167, 69, 0.2);
                color: var(--success-color);
            }}
            
            .title-cell {{
                font-weight: 600;
                max-width: 300px;
                word-wrap: break-word;
            }}
            
            .description-cell {{
                max-width: 400px;
                word-wrap: break-word;
            }}
            
            @media (max-width: 768px) {{
                .dashboard-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .header h1 {{
                    font-size: 2em;
                }}
                
                .dark-mode-toggle {{
                    position: static;
                    margin-top: 20px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <button class="dark-mode-toggle" onclick="toggleDarkMode()">🌙 Dark Mode</button>
                <h1>🛡️ AWS Security Hub Analysis</h1>
                <p>Generated on {timestamp}</p>
            </div>
            
            <div class="content">
                <div class="dashboard-grid">
                    <div class="dashboard-card">
                        <div class="card-header">
                            <span class="card-icon">📊</span>
                            <h2 class="card-title">Executive Summary</h2>
                        </div>
                        <div class="metric-large">{len(findings)}</div>
                        <div class="metric-small">Total Findings</div>
                        <div class="metric-large">{security_metrics['critical_findings']}</div>
                        <div class="metric-small">Critical Findings</div>
                    </div>
                    
                    <div class="dashboard-card">
                        <div class="card-header">
                            <span class="card-icon">⚠️</span>
                            <h2 class="card-title">Risk Assessment</h2>
                        </div>
                        <div class="metric-large">{security_metrics['risk_score']}/10</div>
                        <div class="metric-small">Risk Score</div>
                        <div class="metric-large threat-{security_metrics['threat_level'].lower()}">{security_metrics['threat_level']}</div>
                        <div class="metric-small">Threat Level</div>
                    </div>
                    
                    <div class="dashboard-card">
                        <div class="card-header">
                            <span class="card-icon">✅</span>
                            <h2 class="card-title">Compliance Status</h2>
                        </div>
                        <div class="metric-large">{security_metrics['compliance_score']}%</div>
                        <div class="metric-small">Compliance Score</div>
                    </div>
                </div>
                
                <div class="collapsible" onclick="toggleCollapsible(this)">
                    <span><strong>📈 Severity Breakdown</strong></span>
                    <span>▼</span>
                </div>
                <div class="collapsible-content">
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                
                <div class="collapsible" onclick="toggleCollapsible(this)">
                    <span><strong>🔍 Detailed Findings</strong></span>
                    <span>▼</span>
                </div>
                <div class="collapsible-content">
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Title</th>
                                <th>Description</th>
                                <th>Resource</th>
                                <th>Account</th>
                                <th>Region</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
    """
    
    # Add findings to the table (limit to first 100 for performance)
    for finding in findings[:100]:
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        severity_class = f"severity-{severity.lower()}"
        
        title = finding.get('Title', 'No Title')[:100]
        description = finding.get('Description', 'No Description')[:200]
        
        resources = finding.get('Resources', [])
        resource_info = resources[0].get('Id', 'Unknown') if resources else 'Unknown'
        
        account_id = finding.get('AwsAccountId', 'Unknown')
        account_name = account_names.get(account_id, account_id)
        
        region = finding.get('Region', 'Unknown')
        status = finding.get('RecordState', 'Unknown')
        
        html_content += f"""
                            <tr>
                                <td><span class="severity-badge {severity_class}">{severity}</span></td>
                                <td class="title-cell">{title}</td>
                                <td class="description-cell">{description}</td>
                                <td>{resource_info}</td>
                                <td>{account_name}</td>
                                <td>{region}</td>
                                <td>{status}</td>
                            </tr>
        """
    
    # Convert severity breakdown to JSON for chart
    severity_labels = list(severity_breakdown.keys())
    severity_data = list(severity_breakdown.values())
    
    html_content += f"""
                        </tbody>
                    </table>
                    {f'<p><em>Showing first 100 of {len(findings)} findings</em></p>' if len(findings) > 100 else ''}
                </div>
                
                <script>
                    // Dark mode toggle
                    function toggleDarkMode() {{
                        const body = document.body;
                        const isDark = body.getAttribute('data-theme') === 'dark';
                        body.setAttribute('data-theme', isDark ? 'light' : 'dark');
                        
                        const toggle = document.querySelector('.dark-mode-toggle');
                        toggle.textContent = isDark ? '🌙 Dark Mode' : '☀️ Light Mode';
                        
                        localStorage.setItem('darkMode', isDark ? 'light' : 'dark');
                    }}
                    
                    // Load saved theme
                    document.addEventListener('DOMContentLoaded', function() {{
                        const savedTheme = localStorage.getItem('darkMode') || 'light';
                        document.body.setAttribute('data-theme', savedTheme);
                        
                        const toggle = document.querySelector('.dark-mode-toggle');
                        toggle.textContent = savedTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
                        
                        initializeCharts();
                    }});
                    
                    // Collapsible sections
                    function toggleCollapsible(element) {{
                        element.classList.toggle('active');
                        const content = element.nextElementSibling;
                        const arrow = element.querySelector('span:last-child');
                        
                        if (content.classList.contains('active')) {{
                            content.classList.remove('active');
                            content.style.maxHeight = null;
                            arrow.textContent = '▼';
                        }} else {{
                            content.classList.add('active');
                            content.style.maxHeight = content.scrollHeight + 'px';
                            arrow.textContent = '▲';
                        }}
                    }}
                    
                    // Initialize charts
                    function initializeCharts() {{
                        const ctx = document.getElementById('severityChart');
                        if (ctx) {{
                            new Chart(ctx, {{
                                type: 'doughnut',
                                data: {{
                                    labels: {json.dumps(severity_labels)},
                                    datasets: [{{
                                        data: {json.dumps(severity_data)},
                                        backgroundColor: [
                                            '#dc3545', // CRITICAL
                                            '#ff6b35', // HIGH
                                            '#ffc107', // MEDIUM
                                            '#28a745', // LOW
                                            '#17a2b8'  // INFORMATIONAL
                                        ],
                                        borderWidth: 2,
                                        borderColor: '#fff'
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
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }});
                        }}
                    }}
                </script>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def print_summary(findings, account_names):
    """Print a summary of the Security Hub findings analysis"""
    total_findings = len(findings)
    
    if total_findings == 0:
        print("\n" + "="*80)
        print("AWS SECURITY HUB ANALYSIS SUMMARY")
        print("="*80)
        print("No findings found matching the specified criteria.")
        return
    
    # Calculate metrics
    severity_counts = {}
    account_counts = {}
    resource_counts = {}
    
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        account_id = finding.get('AwsAccountId', 'Unknown')
        account_name = account_names.get(account_id, account_id)
        account_counts[account_name] = account_counts.get(account_name, 0) + 1
        
        resources = finding.get('Resources', [])
        for resource in resources:
            resource_type = resource.get('Type', 'Unknown')
            resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1
    
    security_metrics = calculate_security_metrics(findings)
    
    print("\n" + "="*80)
    print("AWS SECURITY HUB ANALYSIS SUMMARY")
    print("="*80)
    print(f"Total findings analyzed: {total_findings}")
    print(f"Risk Score: {security_metrics['risk_score']}/10")
    print(f"Threat Level: {security_metrics['threat_level']}")
    print(f"Compliance Score: {security_metrics['compliance_score']}%")
    
    print(f"\nSEVERITY BREAKDOWN:")
    print(f"{'Severity':<15} {'Count':<8} {'Percentage':<12}")
    print("-" * 40)
    for severity, count in sorted(severity_counts.items(), key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].index(x[0]) if x[0] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] else 999):
        percentage = (count / total_findings) * 100
        print(f"{severity:<15} {count:<8} {percentage:<12.1f}%")
    
    print(f"\nACCOUNT BREAKDOWN:")
    print(f"{'Account':<40} {'Findings':<10}")
    print("-" * 55)
    for account, count in sorted(account_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        account_display = account[:35] + "..." if len(account) > 38 else account
        print(f"{account_display:<40} {count:<10}")
    
    print(f"\nTOP RESOURCE TYPES:")
    print(f"{'Resource Type':<30} {'Findings':<10}")
    print("-" * 45)
    for resource_type, count in sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        resource_display = resource_type[:25] + "..." if len(resource_type) > 28 else resource_type
        print(f"{resource_display:<30} {count:<10}")
    
    # Recommendations
    print(f"\nRECOMMENDATIONS:")
    print("=" * 80)
    
    critical_count = severity_counts.get('CRITICAL', 0)
    high_count = severity_counts.get('HIGH', 0)
    
    if critical_count > 0:
        print(f"🚨 CRITICAL: {critical_count} critical findings require immediate attention")
        print("   • Review and remediate critical security vulnerabilities")
        print("   • Implement emergency response procedures if needed")
    
    if high_count > 10:
        print(f"⚠️  HIGH: {high_count} high-severity findings detected")
        print("   • Prioritize remediation of high-severity issues")
        print("   • Consider automated remediation for common issues")
    
    if security_metrics['compliance_score'] < 80:
        print(f"📋 COMPLIANCE: Compliance score is {security_metrics['compliance_score']}% - below recommended threshold")
        print("   • Review compliance standards alignment")
        print("   • Implement compliance monitoring and reporting")
    
    print(f"\n✅ Analysis completed successfully!")

def generate_visualizations(findings, reports_dir='security_reports'):
    """Generate visualizations of Security Hub findings"""
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
    
    # 1. Severity Distribution
    plt.figure(figsize=(12, 8))
    
    severity_counts = {}
    for finding in findings:
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    severities = list(severity_counts.keys())
    counts = list(severity_counts.values())
    
    colors = {'CRITICAL': '#dc3545', 'HIGH': '#ff6b35', 'MEDIUM': '#ffc107', 'LOW': '#28a745', 'INFORMATIONAL': '#17a2b8'}
    bar_colors = [colors.get(sev, '#6c757d') for sev in severities]
    
    plt.bar(severities, counts, color=bar_colors)
    plt.title('Security Hub Findings by Severity', fontsize=16, fontweight='bold')
    plt.xlabel('Severity Level', fontsize=12)
    plt.ylabel('Number of Findings', fontsize=12)
    plt.xticks(rotation=45)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{viz_dir}/severity_distribution.png", dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Security visualizations generated in: {viz_dir}")
    
    return {
        'severity_distribution': f"{viz_dir}/severity_distribution.png"
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
    Enhanced AWS Security Hub Findings Analyzer with interactive features
    """
    
    # Interactive mode when called without CLI arguments
    if profile == 'default' and not any([limit, output != 'securityhub_findings.csv']):
        print("AWS Security Hub Findings Analyzer")
        print("==================================")
        
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
        print("ANALYSIS CONFIGURATION")
        print("="*60)
        print(f"Profiles: {', '.join(selected_profiles)}")
        print(f"Regions: {', '.join(regions)}")
        print(f"Severity levels: {', '.join(severity)}")
        print(f"Status filter: {'Active only' if only_active else 'All findings'}")
        print(f"Limit: {limit if limit else 'No limit'}")
        print(f"Output directory: {output_dir}")
        
        proceed = input("\nProceed with analysis? (y/n): ").lower().strip()
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
                print(f"\nProcessing {profile_name} in {region_name}...")
                
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
                        
                        print(f"✅ Found {len(findings)} findings in {profile_name}/{region_name}")
                    else:
                        print(f"ℹ️  No findings found in {profile_name}/{region_name}")
                        
                except Exception as e:
                    print(f"❌ Error processing {profile_name}/{region_name}: {e}")
        
        if not all_findings:
            print("\n❌ No findings found across all profiles and regions.")
            return
        
        # Add account names to findings
        all_findings = add_account_names_to_findings(all_findings, all_account_names)
        
        # Generate outputs
        print(f"\n{'='*60}")
        print("GENERATING OUTPUTS")
        print(f"{'='*60}")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_options['csv']:
            print("Generating CSV report...")
            csv_filename = f"{output_dir}/securityhub_findings_{timestamp}.csv"
            save_to_csv(all_findings, csv_filename)
            print(f"✅ CSV report saved: {csv_filename}")
        
        if output_options['html']:
            print("Generating HTML report...")
            html_filename = f"{output_dir}/securityhub_findings_{timestamp}.html"
            generate_html_report(all_findings, html_filename, all_account_names)
            print(f"✅ HTML report saved: {html_filename}")
        
        if output_options['summary']:
            print_summary(all_findings, all_account_names)
        
        if output_options['visualizations']:
            print("Generating visualizations...")
            viz_files = generate_visualizations(all_findings, output_dir)
            if viz_files:
                print(f"✅ Visualizations saved in: {output_dir}")
        
        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*60}")
        print(f"Total findings processed: {len(all_findings)}")
        print(f"Profiles analyzed: {len(selected_profiles)}")
        print(f"Regions analyzed: {len(regions)}")
        
        # Optional: Open HTML report
        if output_options['html']:
            try:
                import webbrowser
                html_path = f"{output_dir}/securityhub_findings_{timestamp}.html"
                if os.path.exists(html_path):
                    open_browser = input(f"\nOpen HTML report in browser? (y/n): ").lower().strip()
                    if open_browser == 'y':
                        webbrowser.open(f"file://{os.path.abspath(html_path)}")
                        print("HTML report opened in default browser.")
            except ImportError:
                pass
            except Exception as e:
                print(f"Could not open browser: {e}")
    
    else:
        # Original CLI mode
        # Check for active SSO session
        if not check_sso_session(profile):
            click.echo(f"Error: No active SSO session found for profile '{profile}'. Please login using AWS CLI.")
            return

        # Fetch findings
        findings = get_all_findings(profile, region, severity, anystatus, limit)

        # Flatten findings
        flattened_findings = flatten_resources_and_severity(findings)

        # Add account names to the findings
        account_names = get_account_names(profile, region)
        flattened_findings = add_account_names_to_findings(flattened_findings, account_names)

        # Write to CSV
        save_to_csv(flattened_findings, output)

        click.echo(f"Findings exported to {output}.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Analysis cancelled by user!")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Check AWS credentials: aws configure list")
        print("2. Verify Security Hub is enabled in target regions")
        print("3. Ensure proper IAM permissions for Security Hub")
        print("4. Check network connectivity to AWS services")

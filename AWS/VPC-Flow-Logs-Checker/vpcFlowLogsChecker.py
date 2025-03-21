#!/usr/bin/env python3

import boto3
import botocore.session
import pandas as pd
from tabulate import tabulate
from datetime import datetime
import sys
import os

def get_profile_and_account_info():
    """Prompt for AWS profile and confirm account details"""
    # Get list of available profiles
    session = botocore.session.Session()
    profiles = session.available_profiles
    
    if not profiles:
        print("No AWS profiles found. Please configure AWS CLI first using 'aws configure'.")
        sys.exit(1)
    
    # Display available profiles
    print("Available AWS profiles:")
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")
    
    # Prompt for profile selection
    while True:
        try:
            if len(profiles) == 1:
                print(f"\nOnly one profile available, using '{profiles[0]}'")
                profile_name = profiles[0]
                break
            else:
                selection = input("\nEnter profile number or name (or press Enter for default): ")
                
                if not selection:
                    profile_name = "default"
                    break
                
                if selection.isdigit() and 1 <= int(selection) <= len(profiles):
                    profile_name = profiles[int(selection) - 1]
                    break
                elif selection in profiles:
                    profile_name = selection
                    break
                else:
                    print("Invalid selection. Please try again.")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    # Create session with selected profile
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client('sts')
        
        # Get account info
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        iam_arn = identity['Arn']
        
        # Display account information for confirmation
        print("\nAWS Account Information:")
        print(f"Profile: {profile_name}")
        print(f"Account ID: {account_id}")
        print(f"IAM ARN: {iam_arn}")
        
        # Confirm account
        confirmation = input("\nIs this the correct account? (yes/no): ").lower()
        if confirmation not in ['y', 'yes']:
            print("Aborting operation.")
            sys.exit(0)
        
        return session, account_id, profile_name
        
    except Exception as e:
        print(f"Error connecting to AWS with profile '{profile_name}': {str(e)}")
        sys.exit(1)

def get_vpc_flow_logs_status(session):
    """
    Lists all VPCs in the account and checks if VPC Flow Logs are enabled for each.
    Returns a formatted table with the results.
    """
    # Initialize AWS clients using the session
    ec2_client = session.client('ec2')
    ec2_resource = session.resource('ec2')
    
    print("Gathering VPC information...")
    
    # Get all VPCs
    try:
        vpcs = ec2_client.describe_vpcs()['Vpcs']
    except Exception as e:
        print(f"Error retrieving VPCs: {str(e)}")
        sys.exit(1)
        
    print(f"Found {len(vpcs)} VPCs")
    
    # Get all flow logs
    try:
        flow_logs = ec2_client.describe_flow_logs()['FlowLogs']
    except Exception as e:
        print(f"Error retrieving flow logs: {str(e)}")
        sys.exit(1)
        
    # Create a mapping of VPC IDs to their flow log status
    vpc_flow_log_map = {}
    for flow_log in flow_logs:
        resource_id = flow_log.get('ResourceId')
        if resource_id and resource_id.startswith('vpc-'):
            if resource_id not in vpc_flow_log_map:
                vpc_flow_log_map[resource_id] = []
            
            # Add details about this flow log
            destination = flow_log.get('LogDestination', 'N/A')
            log_group = flow_log.get('LogGroupName', 'N/A')
            status = flow_log.get('FlowLogStatus', 'N/A')
            
            vpc_flow_log_map[resource_id].append({
                'id': flow_log.get('FlowLogId', 'N/A'),
                'destination_type': flow_log.get('LogDestinationType', 'N/A'),
                'destination': destination,
                'log_group': log_group,
                'status': status
            })
    
    # Prepare results
    results = []
    
    print("Processing VPC flow logs status...")
    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        
        # Get VPC name from tags
        vpc_name = 'No Name'
        if 'Tags' in vpc:
            for tag in vpc['Tags']:
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                    break
        
        # Check CIDR blocks
        cidr_block = vpc.get('CidrBlock', 'N/A')
        
        # Check if flow logs are enabled
        flow_logs_info = vpc_flow_log_map.get(vpc_id, [])
        
        if flow_logs_info:
            for log in flow_logs_info:
                results.append({
                    'VPC ID': vpc_id,
                    'VPC Name': vpc_name,
                    'CIDR Block': cidr_block,
                    'Flow Logs': 'ACTIVE' if log['status'] == 'ACTIVE' else 'INACTIVE',
                    'Log Destination Type': log['destination_type'],
                    'Log Destination': log['destination'],
                    'Flow Log ID': log['id']
                })
        else:
            results.append({
                'VPC ID': vpc_id,
                'VPC Name': vpc_name,
                'CIDR Block': cidr_block,
                'Flow Logs': 'NOT CONFIGURED',
                'Log Destination Type': 'N/A',
                'Log Destination': 'N/A',
                'Flow Log ID': 'N/A'
            })

    return results

def display_results(results, account_id):
    """Display results in a formatted table"""
    if not results:
        print("No VPCs found in this account.")
        return []
    
    # Convert to DataFrame for easy output formatting
    df = pd.DataFrame(results)
    
    # Create report header
    terminal_width = 120
    output = []
    output.append("=" * terminal_width)
    output.append("VPC FLOW LOGS STATUS REPORT".center(terminal_width))
    output.append(f"Account ID: {account_id}".center(terminal_width))
    output.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(terminal_width))
    output.append("=" * terminal_width)
    output.append("")
    
    # Add table
    output.append(tabulate(df, headers='keys', tablefmt='pretty', showindex=False))
    
    # Summary statistics
    active_count = sum(1 for r in results if r['Flow Logs'] == 'ACTIVE')
    inactive_count = sum(1 for r in results if r['Flow Logs'] == 'INACTIVE')
    not_configured_count = sum(1 for r in results if r['Flow Logs'] == 'NOT CONFIGURED')
    
    output.append("\nSUMMARY:")
    output.append("-" * terminal_width)
    output.append(f"Total VPCs: {len(results)}")
    output.append(f"VPCs with Active Flow Logs: {active_count}")
    output.append(f"VPCs with Inactive Flow Logs: {inactive_count}")
    output.append(f"VPCs without Flow Logs: {not_configured_count}")
    
    output.append("\nRECOMMENDATIONS:")
    output.append("-" * terminal_width)
    if not_configured_count > 0:
        output.append(f"• Consider enabling Flow Logs for the {not_configured_count} VPCs that don't have them")
        output.append("  Flow Logs help with network monitoring, troubleshooting, and security analysis")
    if inactive_count > 0:
        output.append(f"• Review the {inactive_count} VPCs with inactive Flow Logs and consider activating them")
    
    if active_count == len(results):
        output.append("• All VPCs have active Flow Logs. Best practice achieved!")
    
    output.append("\n" + "=" * terminal_width)
    
    # Print the report
    print("\n".join(output))
    
    return output

def save_results_to_file(report_lines, results, account_id):
    """Save results to text and CSV files"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    text_filename = f"vpc_flow_logs_status_{account_id}_{timestamp}.txt"
    csv_filename = f"vpc_flow_logs_status_{account_id}_{timestamp}.csv"
    
    # Save text report
    with open(text_filename, 'w') as text_file:
        text_file.write("\n".join(report_lines))
    
    # Save CSV report
    if results:
        df = pd.DataFrame(results)
        df.to_csv(csv_filename, index=False)
        return text_filename, csv_filename
    else:
        return text_filename, None

def main():
    try:
        print("\n" + "="*80)
        print("AWS VPC FLOW LOGS CHECKER".center(80))
        print("="*80)
        print("\nThis script identifies:")
        print("  1. VPCs with Flow Logs enabled and active")
        print("  2. VPCs with Flow Logs configured but inactive")
        print("  3. VPCs without Flow Logs configured")
        
        # Get AWS profile and account ID
        session, account_id, profile_name = get_profile_and_account_info()
        
        print(f"\nFetching and analyzing VPC Flow Logs status...")
        
        # Get VPC flow logs status
        results = get_vpc_flow_logs_status(session)
        
        # Display and get report lines
        report_lines = display_results(results, account_id)
        
        # Save results to files
        text_file, csv_file = save_results_to_file(report_lines, results, account_id)
        
        print(f"\nDetailed text report saved to: {text_file}")
        if csv_file:
            print(f"CSV data saved to: {csv_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
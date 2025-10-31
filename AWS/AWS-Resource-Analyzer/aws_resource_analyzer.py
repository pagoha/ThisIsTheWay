#!/usr/bin/env python3
"""
AWS Resource Inventory Tool
Inventory AWS resources across multiple profiles and regions
"""

import boto3
import botocore.session
import json
import csv
import argparse
import os
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import List, Dict, Any, Optional
from tabulate import tabulate

# Thread-safe printing
print_lock = threading.Lock()

def safe_print(message: str, indent: int = 0):
    """Thread-safe print function"""
    with print_lock:
        print("  " * indent + message)

def get_profile_and_account_info():
    """Prompt for AWS profiles and confirm account details"""
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
    
    selected_profiles = []
    
    # Prompt for profile selection
    print("\nProfile selection options:")
    print("- Enter profile numbers separated by commas (e.g., 1,3,5)")
    print("- Enter ranges with dashes (e.g., 1-5)")
    print("- Enter profile names separated by commas (e.g., prod,staging,dev)")
    print("- Enter 'all' to select all profiles")
    print("- Press Enter to select default profile only")
    
    while True:
        try:
            selection = input("\nEnter your selection: ").strip()
            
            if not selection:
                selected_profiles = ["default"]
                break
            elif selection.lower() == "all":
                selected_profiles = profiles
                break
            else:
                # Parse comma-separated selections
                selections = [s.strip() for s in selection.split(',')]
                
                for sel in selections:
                    if '-' in sel and all(part.isdigit() for part in sel.split('-')):
                        # Handle range selection (e.g., 1-5)
                        start, end = map(int, sel.split('-'))
                        for i in range(start, end + 1):
                            if 1 <= i <= len(profiles):
                                profile = profiles[i - 1]
                                if profile not in selected_profiles:
                                    selected_profiles.append(profile)
                            else:
                                print(f"Invalid profile number in range: {i}")
                                selected_profiles = []
                                break
                        if not selected_profiles:
                            break
                    elif sel.isdigit():
                        # Handle numeric selection
                        index = int(sel) - 1
                        if 0 <= index < len(profiles):
                            if profiles[index] not in selected_profiles:
                                selected_profiles.append(profiles[index])
                        else:
                            print(f"Invalid profile number: {sel}")
                            selected_profiles = []
                            break
                    elif sel in profiles:
                        # Handle profile name selection
                        if sel not in selected_profiles:
                            selected_profiles.append(sel)
                    else:
                        print(f"Invalid profile: {sel}")
                        selected_profiles = []
                        break
                
                if selected_profiles:
                    break
                else:
                    print("Please try again.")
                    
        except Exception as e:
            print(f"Error: {str(e)}")
    
    # Validate profiles and get account information
    validated_accounts = []
    
    print(f"\nValidating {len(selected_profiles)} profile(s)...")
    
    for profile_name in selected_profiles:
        try:
            session = boto3.Session(profile_name=profile_name)
            sts = session.client('sts')
            
            # Get account info
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            iam_arn = identity['Arn']
            
            validated_accounts.append({
                'profile': profile_name,
                'account_id': account_id,
                'iam_arn': iam_arn,
                'session': session
            })
            
            print(f"[OK] {profile_name}: Account {account_id}")
            
        except Exception as e:
            print(f"[ERROR] {profile_name}: Error - {str(e)}")
            continue
    
    if not validated_accounts:
        print("No valid profiles found. Exiting.")
        sys.exit(1)
    
    # Display summary and confirm
    print(f"\nFound {len(validated_accounts)} valid account(s):")
    for account in validated_accounts:
        print(f"  - Profile: {account['profile']} | Account: {account['account_id']}")
    
    # Confirm accounts
    confirmation = input(f"\nProceed with analysis of these {len(validated_accounts)} account(s)? (yes/no): ").lower()
    if confirmation not in ['y', 'yes']:
        print("Aborting operation.")
        sys.exit(0)
    
    return validated_accounts

def get_available_regions():
    """Get list of all available AWS regions including US Gov regions"""
    try:
        # Try to get regions dynamically first
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        
        # Add US Gov regions if not already included (they might not appear in regular describe_regions call)
        gov_regions = ['us-gov-east-1', 'us-gov-west-1']
        for gov_region in gov_regions:
            if gov_region not in regions:
                regions.append(gov_region)
        
        return sorted(regions)
    except Exception as e:
        print(f"Error getting regions, using default list: {e}")
        # Fallback to comprehensive list including US Gov regions
        return [
            # Standard US regions
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            # Europe regions
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'eu-south-1',
            # Asia Pacific regions
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
            'ap-south-1', 'ap-east-1',
            # Other regions
            'ca-central-1', 'sa-east-1', 'af-south-1', 'me-south-1',
            # US Gov regions
            'us-gov-east-1', 'us-gov-west-1'
        ]

def get_region_selection():
    """Prompt for AWS region selection"""
    available_regions = get_available_regions()
    
    print(f"\nAvailable AWS Regions ({len(available_regions)} total):")
    print("-" * 60)
    
    # Display regions in columns for better readability
    for i, region in enumerate(available_regions, 1):
        print(f"{i:2d}. {region:<20}", end="")
        if i % 3 == 0:  # 3 columns
            print()
    if len(available_regions) % 3 != 0:
        print()  # Final newline if needed
    
    selected_regions = []
    
    print("\nRegion selection options:")
    print("- Enter region numbers separated by commas (e.g., 1,5,10)")
    print("- Enter ranges with dashes (e.g., 1-5)")
    print("- Enter region names separated by commas (e.g., us-east-1,eu-west-1)")
    print("- Enter 'all' to select all regions")
    print("- Enter 'common' for common regions (us-east-1, us-west-2, eu-west-1)")
    print("- Enter 'gov' for US Gov regions (us-gov-east-1, us-gov-west-1)")
    print("- Press Enter to select us-east-1 only")
    
    while True:
        try:
            selection = input("\nEnter your selection: ").strip()
            
            if not selection:
                selected_regions = ["us-east-1"]
                break
            elif selection.lower() == "all":
                selected_regions = available_regions.copy()
                break
            elif selection.lower() == "common":
                common_regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1']
                selected_regions = [r for r in common_regions if r in available_regions]
                break
            elif selection.lower() == "gov":
                gov_regions = ['us-gov-east-1', 'us-gov-west-1']
                selected_regions = [r for r in gov_regions if r in available_regions]
                break
            else:
                # Parse comma-separated selections
                selections = [s.strip() for s in selection.split(',')]
                
                for sel in selections:
                    if '-' in sel and all(part.isdigit() for part in sel.split('-')):
                        # Handle range selection (e.g., 1-5)
                        start, end = map(int, sel.split('-'))
                        for i in range(start, end + 1):
                            if 1 <= i <= len(available_regions):
                                region = available_regions[i - 1]
                                if region not in selected_regions:
                                    selected_regions.append(region)
                            else:
                                print(f"Invalid region number in range: {i}")
                                selected_regions = []
                                break
                        if not selected_regions:
                            break
                    elif sel.isdigit():
                        # Handle numeric selection
                        index = int(sel) - 1
                        if 0 <= index < len(available_regions):
                            region = available_regions[index]
                            if region not in selected_regions:
                                selected_regions.append(region)
                        else:
                            print(f"Invalid region number: {sel}")
                            selected_regions = []
                            break
                    elif sel in available_regions:
                        # Handle region name selection
                        if sel not in selected_regions:
                            selected_regions.append(sel)
                    else:
                        print(f"Invalid region: {sel}")
                        selected_regions = []
                        break
                
                if selected_regions:
                    break
                else:
                    print("Please try again.")
                    
        except Exception as e:
            print(f"Error: {str(e)}")
    
    print(f"\nSelected {len(selected_regions)} region(s):")
    for region in selected_regions:
        print(f"  - {region}")
    
    # Confirm regions
    if len(selected_regions) > 5:
        confirmation = input(f"\nProceed with analysis of these {len(selected_regions)} regions? (yes/no): ").lower()
        if confirmation not in ['y', 'yes']:
            print("Aborting operation.")
            sys.exit(0)
    
    return selected_regions

def inventory_resources(account: Dict[str, Any], region: str, resource_types: List[str]) -> Dict[str, Any]:
    """Inventory AWS resources for a specific account and region"""
    results = {
        'profile': account['profile'],
        'account_id': account['account_id'],
        'region': region,
        'resources': {}
    }
    
    try:
        session = account['session']
        
        # CloudFormation Stacks
        if 'cloudformation' in resource_types:
            try:
                cf_client = session.client('cloudformation', region_name=region)
                stacks = cf_client.list_stacks()
                stack_data = []
                for stack in stacks['StackSummaries']:
                    stack_data.append([stack['StackName'], stack['StackStatus']])
                results['resources']['cloudformation'] = stack_data
            except Exception as e:
                results['resources']['cloudformation'] = f"Error: {str(e)}"

        # EC2 Instances
        if 'ec2' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                instances = ec2_client.describe_instances()
                ec2_data = []
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        name = ''
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'Name':
                                    name = tag['Value']
                                    break
                        ec2_data.append([
                            name,
                            instance['InstanceId'],
                            instance['InstanceType'],
                            instance['State']['Name']
                        ])
                results['resources']['ec2'] = ec2_data
            except Exception as e:
                results['resources']['ec2'] = f"Error: {str(e)}"

        # VPCs
        if 'vpc' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                vpcs = ec2_client.describe_vpcs()
                vpc_data = [[vpc['VpcId'], vpc['CidrBlock']] for vpc in vpcs['Vpcs']]
                results['resources']['vpc'] = vpc_data
            except Exception as e:
                results['resources']['vpc'] = f"Error: {str(e)}"

        # Subnets
        if 'subnets' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                subnets = ec2_client.describe_subnets()
                subnet_data = [[subnet['SubnetId'], subnet['VpcId'], subnet['CidrBlock']] 
                              for subnet in subnets['Subnets']]
                results['resources']['subnets'] = subnet_data
            except Exception as e:
                results['resources']['subnets'] = f"Error: {str(e)}"

        # RDS Instances
        if 'rds' in resource_types:
            try:
                rds_client = session.client('rds', region_name=region)
                rds_instances = rds_client.describe_db_instances()
                rds_data = [[db['DBInstanceIdentifier'], db['DBInstanceClass'], db['DBInstanceStatus']] 
                           for db in rds_instances['DBInstances']]
                results['resources']['rds'] = rds_data
            except Exception as e:
                results['resources']['rds'] = f"Error: {str(e)}"

        # S3 Buckets (only check in us-east-1 to avoid duplicates)
        if 's3' in resource_types and region == 'us-east-1':
            try:
                s3_client = session.client('s3', region_name=region)
                buckets = s3_client.list_buckets()
                bucket_data = [[bucket['Name'], bucket['CreationDate']] for bucket in buckets['Buckets']]
                results['resources']['s3'] = bucket_data
            except Exception as e:
                results['resources']['s3'] = f"Error: {str(e)}"

        # EBS Volumes
        if 'ebs' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                volumes = ec2_client.describe_volumes()
                volume_data = [[vol['VolumeId'], vol['Size'], vol['State']] for vol in volumes['Volumes']]
                results['resources']['ebs'] = volume_data
            except Exception as e:
                results['resources']['ebs'] = f"Error: {str(e)}"

        # ECS Clusters
        if 'ecs' in resource_types:
            try:
                ecs_client = session.client('ecs', region_name=region)
                ecs_clusters = ecs_client.list_clusters()
                cluster_data = [[cluster] for cluster in ecs_clusters['clusterArns']]
                results['resources']['ecs'] = cluster_data
            except Exception as e:
                results['resources']['ecs'] = f"Error: {str(e)}"

        # EKS Clusters
        if 'eks' in resource_types:
            try:
                eks_client = session.client('eks', region_name=region)
                eks_clusters = eks_client.list_clusters()
                eks_data = [[cluster] for cluster in eks_clusters['clusters']]
                results['resources']['eks'] = eks_data
            except Exception as e:
                results['resources']['eks'] = f"Error: {str(e)}"

        # Lambda Functions
        if 'lambda' in resource_types:
            try:
                lambda_client = session.client('lambda', region_name=region)
                functions = lambda_client.list_functions()
                lambda_data = [[func['FunctionName'], func['Runtime'], func.get('State', 'N/A')] 
                              for func in functions['Functions']]
                results['resources']['lambda'] = lambda_data
            except Exception as e:
                results['resources']['lambda'] = f"Error: {str(e)}"

        # Elastic IPs
        if 'eip' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                addresses = ec2_client.describe_addresses()
                eip_data = [[addr['PublicIp'], addr['AllocationId'], addr.get('InstanceId', 'N/A')] 
                           for addr in addresses['Addresses']]
                results['resources']['eip'] = eip_data
            except Exception as e:
                results['resources']['eip'] = f"Error: {str(e)}"

        # DynamoDB Tables
        if 'dynamodb' in resource_types:
            try:
                dynamodb_client = session.client('dynamodb', region_name=region)
                tables = dynamodb_client.list_tables()
                table_data = [[table] for table in tables['TableNames']]
                results['resources']['dynamodb'] = table_data
            except Exception as e:
                results['resources']['dynamodb'] = f"Error: {str(e)}"

        # EFS File Systems
        if 'efs' in resource_types:
            try:
                efs_client = session.client('efs', region_name=region)
                file_systems = efs_client.describe_file_systems()
                efs_data = [[fs['FileSystemId'], fs['LifeCycleState']] for fs in file_systems['FileSystems']]
                results['resources']['efs'] = efs_data
            except Exception as e:
                results['resources']['efs'] = f"Error: {str(e)}"

        # IAM Users (only check in us-east-1 to avoid duplicates)
        if 'iam' in resource_types and region == 'us-east-1':
            try:
                iam_client = session.client('iam', region_name=region)
                
                # IAM Users
                users = iam_client.list_users()
                user_data = [[user['UserName'], user['UserId']] for user in users['Users']]
                results['resources']['iam_users'] = user_data
                
                # IAM Policies (account owned)
                policies = iam_client.list_policies(Scope='Local')
                policy_data = [[policy['PolicyName'], policy['PolicyId'], policy['AttachmentCount']] 
                              for policy in policies['Policies']]
                results['resources']['iam_policies'] = policy_data
            except Exception as e:
                results['resources']['iam_users'] = f"Error: {str(e)}"
                results['resources']['iam_policies'] = f"Error: {str(e)}"

    except Exception as e:
        safe_print(f"Error accessing account {account['profile']} in region {region}: {str(e)}")
        results['error'] = str(e)
    
    return results

def display_results(all_results: List[Dict[str, Any]], output_format: str, output_file: Optional[str] = None):
    """Display or save the inventory results"""
    
    resource_headers = {
        'cloudformation': ['StackName', 'StackStatus'],
        'ec2': ['Name', 'InstanceId', 'InstanceType', 'State'],
        'vpc': ['VpcId', 'CidrBlock'],
        'subnets': ['SubnetId', 'VpcId', 'CidrBlock'],
        'rds': ['DBInstanceIdentifier', 'DBInstanceClass', 'DBInstanceStatus'],
        's3': ['Name', 'CreationDate'],
        'ebs': ['VolumeId', 'Size', 'State'],
        'ecs': ['ClusterArn'],
        'eks': ['ClusterName'],
        'lambda': ['FunctionName', 'Runtime', 'State'],
        'eip': ['PublicIp', 'AllocationId', 'InstanceId'],
        'dynamodb': ['TableName'],
        'efs': ['FileSystemId', 'LifeCycleState'],
        'iam_users': ['UserName', 'UserId'],
        'iam_policies': ['PolicyName', 'PolicyId', 'AttachmentCount']
    }
    
    resource_titles = {
        'cloudformation': 'CloudFormation Stacks',
        'ec2': 'EC2 Instances',
        'vpc': 'VPCs',
        'subnets': 'Subnets',
        'rds': 'RDS Instances',
        's3': 'S3 Buckets',
        'ebs': 'EBS Volumes',
        'ecs': 'ECS Clusters',
        'eks': 'EKS Clusters',
        'lambda': 'Lambda Functions',
        'eip': 'Elastic IPs',
        'dynamodb': 'DynamoDB Tables',
        'efs': 'EFS File Systems',
        'iam_users': 'IAM Users',
        'iam_policies': 'IAM Policies (Account Owned)'
    }
    
    if output_format == 'table':
        for result in all_results:
            if 'error' in result:
                safe_print(f"\n❌ {result['profile']} ({result['account_id']}) - {result['region']}: {result['error']}")
                continue
                
            safe_print(f"\n📍 Profile: {result['profile']} | Account: {result['account_id']} | Region: {result['region']}")
            safe_print("=" * 80)
            
            for resource_type, data in result['resources'].items():
                if isinstance(data, str):  # Error message
                    safe_print(f"\n{resource_titles.get(resource_type, resource_type)}: {data}")
                elif data:  # Has data
                    safe_print(f"\n{resource_titles.get(resource_type, resource_type)}:")
                    headers = resource_headers.get(resource_type, [])
                    safe_print(tabulate(data, headers=headers, tablefmt='grid'), 1)
                else:  # Empty data
                    safe_print(f"\n{resource_titles.get(resource_type, resource_type)}: No resources found")
    
    elif output_format == 'json':
        output_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'results': all_results
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            print(f"Results saved to {output_file}")
        else:
            print(json.dumps(output_data, indent=2, default=str))
    
    elif output_format == 'csv':
        # Flatten results for CSV
        csv_data = []
        for result in all_results:
            if 'error' in result:
                csv_data.append({
                    'Profile': result['profile'],
                    'Account ID': result['account_id'],
                    'Region': result['region'],
                    'Resource Type': 'ERROR',
                    'Resource Details': result['error']
                })
                continue
                
            for resource_type, data in result['resources'].items():
                if isinstance(data, str):  # Error message
                    csv_data.append({
                        'Profile': result['profile'],
                        'Account ID': result['account_id'],
                        'Region': result['region'],
                        'Resource Type': resource_type,
                        'Resource Details': data
                    })
                elif data:  # Has data
                    for item in data:
                        csv_data.append({
                            'Profile': result['profile'],
                            'Account ID': result['account_id'],
                            'Region': result['region'],
                            'Resource Type': resource_type,
                            'Resource Details': ' | '.join(str(x) for x in item)
                        })
        
        if output_file:
            with open(output_file, 'w', newline='') as f:
                if csv_data:
                    writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                    writer.writeheader()
                    writer.writerows(csv_data)
            print(f"Results saved to {output_file}")
        else:
            if csv_data:
                writer = csv.DictWriter(sys.stdout, fieldnames=csv_data[0].keys())
                writer.writeheader()
                writer.writerows(csv_data)

def main():
    parser = argparse.ArgumentParser(description='AWS Resource Inventory Tool')
    parser.add_argument('--profiles', type=str, help='Comma-separated list of AWS profiles (overrides interactive selection)')
    parser.add_argument('--regions', type=str, help='Comma-separated list of regions (overrides interactive selection)')
    parser.add_argument('--resources', type=str, default='all', 
                       help='Comma-separated list of resource types to inventory (default: all)')
    parser.add_argument('--output-format', choices=['table', 'json', 'csv'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--output-file', type=str, help='Output file path (optional)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for parallel execution (default: 10)')
    
    args = parser.parse_args()
    
    # Available resource types
    available_resources = [
        'cloudformation', 'ec2', 'vpc', 'subnets', 'rds', 's3', 'ebs',
        'ecs', 'eks', 'lambda', 'eip', 'dynamodb', 'efs', 'iam'
    ]
    
    # Parse resource types
    if args.resources.lower() == 'all':
        resource_types = available_resources
    else:
        resource_types = [r.strip() for r in args.resources.split(',')]
        invalid_resources = [r for r in resource_types if r not in available_resources]
        if invalid_resources:
            print(f"Invalid resource types: {', '.join(invalid_resources)}")
            print(f"Available resource types: {', '.join(available_resources)}")
            sys.exit(1)
    
    # Get and validate profiles
    if args.profiles:
        selected_profile_names = [p.strip() for p in args.profiles.split(',')]
        
        # Validate provided profiles
        validated_accounts = []
        print(f"\nValidating {len(selected_profile_names)} profile(s)...")
        
        for profile_name in selected_profile_names:
            try:
                session = boto3.Session(profile_name=profile_name)
                sts = session.client('sts')
                
                # Get account info
                identity = sts.get_caller_identity()
                account_id = identity['Account']
                iam_arn = identity['Arn']
                
                validated_accounts.append({
                    'profile': profile_name,
                    'account_id': account_id,
                    'iam_arn': iam_arn,
                    'session': session
                })
                
                print(f"[OK] {profile_name}: Account {account_id}")
                
            except Exception as e:
                print(f"[ERROR] {profile_name}: Error - {str(e)}")
                continue
        
        if not validated_accounts:
            print("No valid profiles found. Exiting.")
            sys.exit(1)
        
        # Display summary and confirm
        print(f"\nFound {len(validated_accounts)} valid account(s):")
        for account in validated_accounts:
            print(f"  - Profile: {account['profile']} | Account: {account['account_id']}")
        
        # Confirm accounts
        confirmation = input(f"\nProceed with analysis of these {len(validated_accounts)} account(s)? (yes/no): ").lower()
        if confirmation not in ['y', 'yes']:
            print("Aborting operation.")
            sys.exit(0)
    else:
        validated_accounts = get_profile_and_account_info()
    
    # Get regions
    if args.regions:
        # Handle special region shortcuts for command line
        if args.regions.lower() == 'gov':
            regions = ['us-gov-east-1', 'us-gov-west-1']
        elif args.regions.lower() == 'common':
            regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1']
        elif args.regions.lower() == 'all':
            regions = get_available_regions()
        else:
            regions = [r.strip() for r in args.regions.split(',')]
    else:
        regions = get_region_selection()
    
    print(f"\nStarting inventory across {len(validated_accounts)} account(s) and {len(regions)} region(s)...")
    print(f"Resource types: {', '.join(resource_types)}")
    print(f"Using {args.threads} threads for parallel execution\n")
    
    # Execute inventory in parallel
    all_results = []
    tasks = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for account in validated_accounts:
            for region in regions:
                task = executor.submit(inventory_resources, account, region, resource_types)
                tasks.append(task)
        
        # Collect results as they complete
        for i, task in enumerate(as_completed(tasks), 1):
            try:
                result = task.result()
                all_results.append(result)
                safe_print(f"✅ Completed {i}/{len(tasks)}: {result['profile']} ({result['account_id']}) - {result['region']}")
            except Exception as e:
                safe_print(f"❌ Failed {i}/{len(tasks)}: {str(e)}")
    
    # Display results
    print(f"\n{'='*80}")
    print("INVENTORY RESULTS")
    print(f"{'='*80}")
    
    display_results(all_results, args.output_format, args.output_file)
    
    print(f"\n{'='*80}")
    print(f"Inventory completed: {len(all_results)} account-region combinations processed")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()

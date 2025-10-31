#!/usr/bin/env python3
"""
AWS Resource Inventory Tool
Comprehensive AWS resource discovery across multiple profiles and regions
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

        # Security Groups
        if 'security_groups' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                security_groups = ec2_client.describe_security_groups()
                sg_data = []
                for sg in security_groups['SecurityGroups']:
                    inbound_rules = len(sg.get('IpPermissions', []))
                    outbound_rules = len(sg.get('IpPermissionsEgress', []))
                    sg_data.append([
                        sg['GroupName'],
                        sg['GroupId'],
                        sg['VpcId'] if sg.get('VpcId') else 'EC2-Classic',
                        f"{inbound_rules} in / {outbound_rules} out"
                    ])
                results['resources']['security_groups'] = sg_data
            except Exception as e:
                results['resources']['security_groups'] = f"Error: {str(e)}"

        # VPCs
        if 'vpc' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                vpcs = ec2_client.describe_vpcs()
                vpc_data = []
                for vpc in vpcs['Vpcs']:
                    name = ''
                    if 'Tags' in vpc:
                        for tag in vpc['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    vpc_data.append([name, vpc['VpcId'], vpc['CidrBlock'], vpc['State']])
                results['resources']['vpc'] = vpc_data
            except Exception as e:
                results['resources']['vpc'] = f"Error: {str(e)}"

        # Subnets
        if 'subnets' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                subnets = ec2_client.describe_subnets()
                subnet_data = []
                for subnet in subnets['Subnets']:
                    name = ''
                    if 'Tags' in subnet:
                        for tag in subnet['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    subnet_data.append([
                        name,
                        subnet['SubnetId'],
                        subnet['VpcId'],
                        subnet['CidrBlock'],
                        subnet['AvailabilityZone'],
                        'Public' if subnet.get('MapPublicIpOnLaunch') else 'Private'
                    ])
                results['resources']['subnets'] = subnet_data
            except Exception as e:
                results['resources']['subnets'] = f"Error: {str(e)}"

        # Route Tables
        if 'route_tables' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                route_tables = ec2_client.describe_route_tables()
                rt_data = []
                for rt in route_tables['RouteTables']:
                    name = ''
                    if 'Tags' in rt:
                        for tag in rt['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    route_count = len(rt.get('Routes', []))
                    association_count = len(rt.get('Associations', []))
                    rt_data.append([
                        name,
                        rt['RouteTableId'],
                        rt['VpcId'],
                        f"{route_count} routes",
                        f"{association_count} associations"
                    ])
                results['resources']['route_tables'] = rt_data
            except Exception as e:
                results['resources']['route_tables'] = f"Error: {str(e)}"

        # Internet Gateways
        if 'internet_gateways' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                igws = ec2_client.describe_internet_gateways()
                igw_data = []
                for igw in igws['InternetGateways']:
                    name = ''
                    if 'Tags' in igw:
                        for tag in igw['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    attachments = ', '.join([att['VpcId'] for att in igw.get('Attachments', [])])
                    igw_data.append([
                        name,
                        igw['InternetGatewayId'],
                        attachments if attachments else 'Detached'
                    ])
                results['resources']['internet_gateways'] = igw_data
            except Exception as e:
                results['resources']['internet_gateways'] = f"Error: {str(e)}"

        # NAT Gateways
        if 'nat_gateways' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                nat_gws = ec2_client.describe_nat_gateways()
                nat_data = []
                for nat in nat_gws['NatGateways']:
                    name = ''
                    if 'Tags' in nat:
                        for tag in nat['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    nat_data.append([
                        name,
                        nat['NatGatewayId'],
                        nat['State'],
                        nat['SubnetId'],
                        nat.get('ConnectivityType', 'public')
                    ])
                results['resources']['nat_gateways'] = nat_data
            except Exception as e:
                results['resources']['nat_gateways'] = f"Error: {str(e)}"

        # Load Balancers (ALB/NLB)
        if 'load_balancers' in resource_types:
            try:
                elb_client = session.client('elbv2', region_name=region)
                lbs = elb_client.describe_load_balancers()
                lb_data = []
                for lb in lbs['LoadBalancers']:
                    # Get target group count
                    try:
                        tgs = elb_client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
                        target_group_count = len(tgs['TargetGroups'])
                    except:
                        target_group_count = 'Unknown'
                    
                    lb_data.append([
                        lb['LoadBalancerName'],
                        lb['Type'],
                        lb['State']['Code'],
                        lb['Scheme'],
                        f"{target_group_count} target groups"
                    ])
                results['resources']['load_balancers'] = lb_data
            except Exception as e:
                results['resources']['load_balancers'] = f"Error: {str(e)}"

        # Classic Load Balancers
        if 'classic_load_balancers' in resource_types:
            try:
                elb_client = session.client('elb', region_name=region)
                clbs = elb_client.describe_load_balancers()
                clb_data = []
                for clb in clbs['LoadBalancerDescriptions']:
                    instance_count = len(clb.get('Instances', []))
                    clb_data.append([
                        clb['LoadBalancerName'],
                        clb['Scheme'],
                        f"{instance_count} instances",
                        ', '.join(clb.get('AvailabilityZones', []))
                    ])
                results['resources']['classic_load_balancers'] = clb_data
            except Exception as e:
                results['resources']['classic_load_balancers'] = f"Error: {str(e)}"

        # Auto Scaling Groups
        if 'auto_scaling_groups' in resource_types:
            try:
                asg_client = session.client('autoscaling', region_name=region)
                asgs = asg_client.describe_auto_scaling_groups()
                asg_data = []
                for asg in asgs['AutoScalingGroups']:
                    asg_data.append([
                        asg['AutoScalingGroupName'],
                        f"Min: {asg['MinSize']}",
                        f"Max: {asg['MaxSize']}",
                        f"Desired: {asg['DesiredCapacity']}",
                        f"Current: {len(asg.get('Instances', []))}"
                    ])
                results['resources']['auto_scaling_groups'] = asg_data
            except Exception as e:
                results['resources']['auto_scaling_groups'] = f"Error: {str(e)}"

        # RDS Instances
        if 'rds' in resource_types:
            try:
                rds_client = session.client('rds', region_name=region)
                rds_instances = rds_client.describe_db_instances()
                rds_data = []
                for db in rds_instances['DBInstances']:
                    rds_data.append([
                        db['DBInstanceIdentifier'],
                        db['DBInstanceClass'],
                        db['DBInstanceStatus'],
                        db['Engine'],
                        f"{db.get('AllocatedStorage', 'N/A')} GB"
                    ])
                results['resources']['rds'] = rds_data
            except Exception as e:
                results['resources']['rds'] = f"Error: {str(e)}"

        # RDS Snapshots
        if 'rds_snapshots' in resource_types:
            try:
                rds_client = session.client('rds', region_name=region)
                snapshots = rds_client.describe_db_snapshots(SnapshotType='manual', MaxRecords=100)
                snapshot_data = []
                for snap in snapshots['DBSnapshots']:
                    age_days = (datetime.now(timezone.utc) - snap['SnapshotCreateTime']).days
                    snapshot_data.append([
                        snap['DBSnapshotIdentifier'],
                        snap['DBInstanceIdentifier'],
                        snap['Status'],
                        f"{age_days} days old",
                        f"{snap.get('AllocatedStorage', 'N/A')} GB"
                    ])
                results['resources']['rds_snapshots'] = snapshot_data
            except Exception as e:
                results['resources']['rds_snapshots'] = f"Error: {str(e)}"

        # S3 Buckets (only check in us-east-1 to avoid duplicates)
        if 's3' in resource_types and region == 'us-east-1':
            try:
                s3_client = session.client('s3', region_name=region)
                buckets = s3_client.list_buckets()
                bucket_data = []
                for bucket in buckets['Buckets']:
                    # Get bucket region
                    try:
                        bucket_region = s3_client.get_bucket_location(Bucket=bucket['Name'])
                        bucket_region = bucket_region['LocationConstraint'] or 'us-east-1'
                    except:
                        bucket_region = 'Unknown'
                    
                    # Get bucket size (this can be expensive, so we'll skip for now)
                    bucket_data.append([
                        bucket['Name'],
                        bucket['CreationDate'],
                        bucket_region
                    ])
                results['resources']['s3'] = bucket_data
            except Exception as e:
                results['resources']['s3'] = f"Error: {str(e)}"

        # EBS Volumes
        if 'ebs' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                volumes = ec2_client.describe_volumes()
                volume_data = []
                for vol in volumes['Volumes']:
                    name = ''
                    if 'Tags' in vol:
                        for tag in vol['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    
                    # Check if attached
                    attachment_status = 'Unattached'
                    if vol.get('Attachments'):
                        attachment_status = f"Attached to {vol['Attachments'][0]['InstanceId']}"
                    
                    volume_data.append([
                        name,
                        vol['VolumeId'],
                        f"{vol['Size']} GB",
                        vol['VolumeType'],
                        vol['State'],
                        attachment_status
                    ])
                results['resources']['ebs'] = volume_data
            except Exception as e:
                results['resources']['ebs'] = f"Error: {str(e)}"

        # EBS Snapshots
        if 'ebs_snapshots' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                # Only get snapshots owned by this account to avoid AWS public snapshots
                snapshots = ec2_client.describe_snapshots(OwnerIds=['self'], MaxResults=100)
                snapshot_data = []
                for snap in snapshots['Snapshots']:
                    age_days = (datetime.now(timezone.utc) - snap['StartTime']).days
                    snapshot_data.append([
                        snap['SnapshotId'],
                        snap.get('VolumeId', 'N/A'),
                        snap['State'],
                        f"{age_days} days old",
                        f"{snap.get('VolumeSize', 'N/A')} GB"
                    ])
                results['resources']['ebs_snapshots'] = snapshot_data
            except Exception as e:
                results['resources']['ebs_snapshots'] = f"Error: {str(e)}"

        # Elastic IPs
        if 'eip' in resource_types:
            try:
                ec2_client = session.client('ec2', region_name=region)
                addresses = ec2_client.describe_addresses()
                eip_data = []
                for addr in addresses['Addresses']:
                    status = 'Unattached' if not addr.get('InstanceId') and not addr.get('NetworkInterfaceId') else 'Attached'
                    attached_to = addr.get('InstanceId', addr.get('NetworkInterfaceId', 'N/A'))
                    eip_data.append([
                        addr['PublicIp'],
                        addr['AllocationId'],
                        status,
                        attached_to
                    ])
                results['resources']['eip'] = eip_data
            except Exception as e:
                results['resources']['eip'] = f"Error: {str(e)}"

        # ECS Clusters
        if 'ecs' in resource_types:
            try:
                ecs_client = session.client('ecs', region_name=region)
                ecs_clusters = ecs_client.list_clusters()
                cluster_data = []
                if ecs_clusters['clusterArns']:
                    cluster_details = ecs_client.describe_clusters(clusters=ecs_clusters['clusterArns'])
                    for cluster in cluster_details['clusters']:
                        cluster_data.append([
                            cluster['clusterName'],
                            cluster['status'],
                            f"{cluster['runningTasksCount']} running tasks",
                            f"{cluster['activeServicesCount']} services"
                        ])
                results['resources']['ecs'] = cluster_data
            except Exception as e:
                results['resources']['ecs'] = f"Error: {str(e)}"

        # EKS Clusters
        if 'eks' in resource_types:
            try:
                eks_client = session.client('eks', region_name=region)
                eks_clusters = eks_client.list_clusters()
                eks_data = []
                for cluster_name in eks_clusters['clusters']:
                    try:
                        cluster_details = eks_client.describe_cluster(name=cluster_name)
                        cluster = cluster_details['cluster']
                        eks_data.append([
                            cluster['name'],
                            cluster['status'],
                            cluster['version'],
                            cluster['endpoint'][:50] + '...' if len(cluster['endpoint']) > 50 else cluster['endpoint']
                        ])
                    except:
                        eks_data.append([cluster_name, 'Unknown', 'Unknown', 'Unknown'])
                results['resources']['eks'] = eks_data
            except Exception as e:
                results['resources']['eks'] = f"Error: {str(e)}"

        # Lambda Functions
        if 'lambda' in resource_types:
            try:
                lambda_client = session.client('lambda', region_name=region)
                functions = lambda_client.list_functions()
                lambda_data = []
                for func in functions['Functions']:
                    lambda_data.append([
                        func['FunctionName'],
                        func['Runtime'],
                        func.get('State', 'N/A'),
                        f"{func.get('CodeSize', 0)} bytes",
                        func.get('LastModified', 'N/A')[:10]  # Just the date part
                    ])
                results['resources']['lambda'] = lambda_data
            except Exception as e:
                results['resources']['lambda'] = f"Error: {str(e)}"

        # API Gateway
        if 'api_gateway' in resource_types:
            try:
                # API Gateway v1 (REST APIs)
                apigw_client = session.client('apigateway', region_name=region)
                apis = apigw_client.get_rest_apis()
                apigw_data = []
                for api in apis['items']:
                    apigw_data.append([
                        api['name'],
                        api['id'],
                        'REST API',
                        api.get('createdDate', 'N/A')
                    ])
                
                # API Gateway v2 (HTTP APIs)
                try:
                    apigwv2_client = session.client('apigatewayv2', region_name=region)
                    http_apis = apigwv2_client.get_apis()
                    for api in http_apis['Items']:
                        apigw_data.append([
                            api['Name'],
                            api['ApiId'],
                            api['ProtocolType'],
                            api.get('CreatedDate', 'N/A')
                        ])
                except:
                    pass  # API Gateway v2 might not be available in all regions
                results['resources']['api_gateway'] = apigw_data
            except Exception as e:
                results['resources']['api_gateway'] = f"Error: {str(e)}"

        # ElastiCache Clusters
        if 'elasticache' in resource_types:
            try:
                elasticache_client = session.client('elasticache', region_name=region)
                
                # Redis clusters
                redis_clusters = elasticache_client.describe_replication_groups()
                elasticache_data = []
                for cluster in redis_clusters['ReplicationGroups']:
                    elasticache_data.append([
                        cluster['ReplicationGroupId'],
                        'Redis',
                        cluster['Status'],
                        cluster.get('NodeType', 'N/A'),
                        f"{cluster.get('NumCacheClusters', 0)} nodes"
                    ])
                
                # Memcached clusters
                memcached_clusters = elasticache_client.describe_cache_clusters()
                for cluster in memcached_clusters['CacheClusters']:
                    if cluster.get('Engine') == 'memcached':
                        elasticache_data.append([
                            cluster['CacheClusterId'],
                            'Memcached',
                            cluster['CacheClusterStatus'],
                            cluster.get('CacheNodeType', 'N/A'),
                            f"{cluster.get('NumCacheNodes', 0)} nodes"
                        ])
                
                results['resources']['elasticache'] = elasticache_data
            except Exception as e:
                results['resources']['elasticache'] = f"Error: {str(e)}"

        # CloudWatch Log Groups
        if 'cloudwatch_logs' in resource_types:
            try:
                logs_client = session.client('logs', region_name=region)
                log_groups = logs_client.describe_log_groups()
                log_data = []
                for lg in log_groups['logGroups']:
                    retention = lg.get('retentionInDays', 'Never expires')
                    size_mb = lg.get('storedBytes', 0) / (1024 * 1024)  # Convert to MB
                    log_data.append([
                        lg['logGroupName'],
                        f"{retention} days" if isinstance(retention, int) else retention,
                        f"{size_mb:.2f} MB" if size_mb > 0 else "Unknown size"
                    ])
                results['resources']['cloudwatch_logs'] = log_data
            except Exception as e:
                results['resources']['cloudwatch_logs'] = f"Error: {str(e)}"

        # CloudWatch Alarms
        if 'cloudwatch_alarms' in resource_types:
            try:
                cloudwatch_client = session.client('cloudwatch', region_name=region)
                alarms = cloudwatch_client.describe_alarms()
                alarm_data = []
                for alarm in alarms['MetricAlarms']:
                    alarm_data.append([
                        alarm['AlarmName'],
                        alarm['StateValue'],
                        alarm['MetricName'],
                        alarm.get('Namespace', 'N/A'),
                        'Yes' if alarm.get('ActionsEnabled') else 'No'
                    ])
                results['resources']['cloudwatch_alarms'] = alarm_data
            except Exception as e:
                results['resources']['cloudwatch_alarms'] = f"Error: {str(e)}"

        # SNS Topics
        if 'sns' in resource_types:
            try:
                sns_client = session.client('sns', region_name=region)
                topics = sns_client.list_topics()
                sns_data = []
                for topic in topics['Topics']:
                    topic_arn = topic['TopicArn']
                    topic_name = topic_arn.split(':')[-1]
                    # Get subscription count
                    try:
                        subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
                        sub_count = len(subscriptions['Subscriptions'])
                    except:
                        sub_count = 'Unknown'
                    
                    sns_data.append([
                        topic_name,
                        topic_arn,
                        f"{sub_count} subscriptions"
                    ])
                results['resources']['sns'] = sns_data
            except Exception as e:
                results['resources']['sns'] = f"Error: {str(e)}"

        # SQS Queues
        if 'sqs' in resource_types:
            try:
                sqs_client = session.client('sqs', region_name=region)
                queues = sqs_client.list_queues()
                sqs_data = []
                for queue_url in queues.get('QueueUrls', []):
                    queue_name = queue_url.split('/')[-1]
                    try:
                        attrs = sqs_client.get_queue_attributes(
                            QueueUrl=queue_url,
                            AttributeNames=['ApproximateNumberOfMessages', 'VisibilityTimeout']
                        )
                        msg_count = attrs['Attributes'].get('ApproximateNumberOfMessages', '0')
                        visibility = attrs['Attributes'].get('VisibilityTimeout', 'Unknown')
                    except:
                        msg_count = 'Unknown'
                        visibility = 'Unknown'
                    
                    sqs_data.append([
                        queue_name,
                        queue_url,
                        f"{msg_count} messages",
                        f"{visibility}s visibility"
                    ])
                results['resources']['sqs'] = sqs_data
            except Exception as e:
                results['resources']['sqs'] = f"Error: {str(e)}"

        # DynamoDB Tables
        if 'dynamodb' in resource_types:
            try:
                dynamodb_client = session.client('dynamodb', region_name=region)
                tables = dynamodb_client.list_tables()
                table_data = []
                for table_name in tables['TableNames']:
                    try:
                        table_info = dynamodb_client.describe_table(TableName=table_name)
                        table = table_info['Table']
                        table_data.append([
                            table_name,
                            table['TableStatus'],
                            table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
                            f"{table.get('ItemCount', 'Unknown')} items"
                        ])
                    except:
                        table_data.append([table_name, 'Unknown', 'Unknown', 'Unknown'])
                results['resources']['dynamodb'] = table_data
            except Exception as e:
                results['resources']['dynamodb'] = f"Error: {str(e)}"

        # EFS File Systems
        if 'efs' in resource_types:
            try:
                efs_client = session.client('efs', region_name=region)
                file_systems = efs_client.describe_file_systems()
                efs_data = []
                for fs in file_systems['FileSystems']:
                    name = ''
                    if 'Tags' in fs:
                        for tag in fs['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    
                    size_gb = fs.get('SizeInBytes', {}).get('Value', 0) / (1024**3)  # Convert to GB
                    efs_data.append([
                        name if name else fs['FileSystemId'],
                        fs['FileSystemId'],
                        fs['LifeCycleState'],
                        f"{size_gb:.2f} GB" if size_gb > 0 else "Empty"
                    ])
                results['resources']['efs'] = efs_data
            except Exception as e:
                results['resources']['efs'] = f"Error: {str(e)}"

        # CloudTrail
        if 'cloudtrail' in resource_types:
            try:
                cloudtrail_client = session.client('cloudtrail', region_name=region)
                trails = cloudtrail_client.describe_trails()
                trail_data = []
                for trail in trails['trailList']:
                    # Get trail status
                    try:
                        status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                        is_logging = status['IsLogging']
                    except:
                        is_logging = 'Unknown'
                    
                    trail_data.append([
                        trail['Name'],
                        'Multi-region' if trail.get('IsMultiRegionTrail') else 'Single region',
                        'Logging' if is_logging else 'Not logging',
                        trail.get('S3BucketName', 'N/A')
                    ])
                results['resources']['cloudtrail'] = trail_data
            except Exception as e:
                results['resources']['cloudtrail'] = f"Error: {str(e)}"

        # KMS Keys
        if 'kms' in resource_types:
            try:
                kms_client = session.client('kms', region_name=region)
                keys = kms_client.list_keys()
                kms_data = []
                for key in keys['Keys']:
                    try:
                        key_info = kms_client.describe_key(KeyId=key['KeyId'])
                        key_detail = key_info['KeyMetadata']
                        # Skip AWS managed keys
                        if key_detail.get('KeyManager') == 'AWS':
                            continue
                        
                        kms_data.append([
                            key_detail.get('Description', 'No description'),
                            key['KeyId'],
                            key_detail['KeyUsage'],
                            key_detail['KeyState'],
                            'Yes' if key_detail.get('Enabled') else 'No'
                        ])
                    except:
                        # Skip keys we can't access
                        continue
                results['resources']['kms'] = kms_data
            except Exception as e:
                results['resources']['kms'] = f"Error: {str(e)}"

        # IAM Users and Roles (only check in us-east-1 to avoid duplicates - IAM is global)
        if 'iam' in resource_types and region == 'us-east-1':
            try:
                iam_client = session.client('iam', region_name=region)
                
                # IAM Users
                users = iam_client.list_users()
                user_data = []
                for user in users['Users']:
                    # Get last activity
                    try:
                        last_used = user.get('PasswordLastUsed', 'Never')
                        if hasattr(last_used, 'strftime'):
                            last_used = last_used.strftime('%Y-%m-%d')
                    except:
                        last_used = 'Unknown'
                    
                    user_data.append([
                        user['UserName'],
                        user['UserId'],
                        user['CreateDate'].strftime('%Y-%m-%d'),
                        last_used
                    ])
                results['resources']['iam_users'] = user_data
                
                # IAM Roles
                roles = iam_client.list_roles()
                role_data = []
                for role in roles['Roles']:
                    # Skip AWS service roles
                    if role['RoleName'].startswith('aws-service-role/'):
                        continue
                    
                    role_data.append([
                        role['RoleName'],
                        role['CreateDate'].strftime('%Y-%m-%d'),
                        role.get('Description', 'No description')[:50] + '...' if len(role.get('Description', '')) > 50 else role.get('Description', 'No description')
                    ])
                results['resources']['iam_roles'] = role_data
                
                # IAM Policies (account owned)
                policies = iam_client.list_policies(Scope='Local')
                policy_data = []
                for policy in policies['Policies']:
                    policy_data.append([
                        policy['PolicyName'],
                        policy['PolicyId'],
                        policy['AttachmentCount'],
                        policy['CreateDate'].strftime('%Y-%m-%d')
                    ])
                results['resources']['iam_policies'] = policy_data
                
            except Exception as e:
                results['resources']['iam_users'] = f"Error: {str(e)}"
                results['resources']['iam_roles'] = f"Error: {str(e)}"
                results['resources']['iam_policies'] = f"Error: {str(e)}"

        # Global resources (only check once per account)
        if region == 'us-east-1':
            
            # CloudFront Distributions
            if 'cloudfront' in resource_types:
                try:
                    cloudfront_client = session.client('cloudfront', region_name=region)
                    distributions = cloudfront_client.list_distributions()
                    cf_data = []
                    if 'Items' in distributions['DistributionList']:
                        for dist in distributions['DistributionList']['Items']:
                            cf_data.append([
                                dist['Id'],
                                dist['DomainName'],
                                dist['Status'],
                                'Enabled' if dist['Enabled'] else 'Disabled',
                                dist['Origins']['Items'][0]['DomainName'] if dist['Origins']['Items'] else 'No origin'
                            ])
                    results['resources']['cloudfront'] = cf_data
                except Exception as e:
                    results['resources']['cloudfront'] = f"Error: {str(e)}"

            # Route 53 Hosted Zones
            if 'route53' in resource_types:
                try:
                    route53_client = session.client('route53', region_name=region)
                    hosted_zones = route53_client.list_hosted_zones()
                    r53_data = []
                    for zone in hosted_zones['HostedZones']:
                        # Get record count
                        try:
                            records = route53_client.list_resource_record_sets(HostedZoneId=zone['Id'])
                            record_count = len(records['ResourceRecordSets'])
                        except:
                            record_count = 'Unknown'
                        
                        r53_data.append([
                            zone['Name'].rstrip('.'),
                            zone['Id'].split('/')[-1],
                            'Private' if zone['Config']['PrivateZone'] else 'Public',
                            f"{record_count} records"
                        ])
                    results['resources']['route53'] = r53_data
                except Exception as e:
                    results['resources']['route53'] = f"Error: {str(e)}"

    except Exception as e:
        safe_print(f"Error accessing account {account['profile']} in region {region}: {str(e)}")
        results['error'] = str(e)
    
    return results

def display_results(all_results: List[Dict[str, Any]], output_format: str, output_file: Optional[str] = None):
    """Display or save the inventory results"""
    
    resource_headers = {
        'cloudformation': ['StackName', 'StackStatus'],
        'ec2': ['Name', 'InstanceId', 'InstanceType', 'State'],
        'security_groups': ['GroupName', 'GroupId', 'VPC', 'Rules'],
        'vpc': ['Name', 'VpcId', 'CidrBlock', 'State'],
        'subnets': ['Name', 'SubnetId', 'VpcId', 'CidrBlock', 'AZ', 'Type'],
        'route_tables': ['Name', 'RouteTableId', 'VpcId', 'Routes', 'Associations'],
        'internet_gateways': ['Name', 'InternetGatewayId', 'Attachments'],
        'nat_gateways': ['Name', 'NatGatewayId', 'State', 'SubnetId', 'Type'],
        'load_balancers': ['Name', 'Type', 'State', 'Scheme', 'Target Groups'],
        'classic_load_balancers': ['Name', 'Scheme', 'Instances', 'AZs'],
        'auto_scaling_groups': ['Name', 'Min', 'Max', 'Desired', 'Current'],
        'rds': ['DBInstanceIdentifier', 'DBInstanceClass', 'DBInstanceStatus', 'Engine', 'Storage'],
        'rds_snapshots': ['SnapshotId', 'DBInstanceId', 'Status', 'Age', 'Size'],
        's3': ['Name', 'CreationDate', 'Region'],
        'ebs': ['Name', 'VolumeId', 'Size', 'Type', 'State', 'Attachment'],
        'ebs_snapshots': ['SnapshotId', 'VolumeId', 'State', 'Age', 'Size'],
        'eip': ['PublicIp', 'AllocationId', 'Status', 'AttachedTo'],
        'ecs': ['ClusterName', 'Status', 'Tasks', 'Services'],
        'eks': ['ClusterName', 'Status', 'Version', 'Endpoint'],
        'lambda': ['FunctionName', 'Runtime', 'State', 'CodeSize', 'LastModified'],
        'api_gateway': ['Name', 'Id', 'Type', 'Created'],
        'elasticache': ['ClusterId', 'Engine', 'Status', 'NodeType', 'Nodes'],
        'cloudwatch_logs': ['LogGroupName', 'Retention', 'Size'],
        'cloudwatch_alarms': ['AlarmName', 'State', 'MetricName', 'Namespace', 'ActionsEnabled'],
        'sns': ['TopicName', 'TopicArn', 'Subscriptions'],
        'sqs': ['QueueName', 'QueueUrl', 'Messages', 'Visibility'],
        'dynamodb': ['TableName', 'Status', 'BillingMode', 'Items'],
        'efs': ['Name', 'FileSystemId', 'LifeCycleState', 'Size'],
        'cloudtrail': ['TrailName', 'Type', 'Status', 'S3Bucket'],
        'kms': ['Description', 'KeyId', 'KeyUsage', 'KeyState', 'Enabled'],
        'iam_users': ['UserName', 'UserId', 'Created', 'LastUsed'],
        'iam_roles': ['RoleName', 'Created', 'Description'],
        'iam_policies': ['PolicyName', 'PolicyId', 'AttachmentCount', 'Created'],
        'cloudfront': ['DistributionId', 'DomainName', 'Status', 'Enabled', 'Origin'],
        'route53': ['DomainName', 'HostedZoneId', 'Type', 'Records']
    }
    
    resource_titles = {
        'cloudformation': 'CloudFormation Stacks',
        'ec2': 'EC2 Instances',
        'security_groups': 'Security Groups',
        'vpc': 'VPCs',
        'subnets': 'Subnets',
        'route_tables': 'Route Tables',
        'internet_gateways': 'Internet Gateways',
        'nat_gateways': 'NAT Gateways',
        'load_balancers': 'Application/Network Load Balancers',
        'classic_load_balancers': 'Classic Load Balancers',
        'auto_scaling_groups': 'Auto Scaling Groups',
        'rds': 'RDS Instances',
        'rds_snapshots': 'RDS Snapshots',
        's3': 'S3 Buckets',
        'ebs': 'EBS Volumes',
        'ebs_snapshots': 'EBS Snapshots',
        'eip': 'Elastic IPs',
        'ecs': 'ECS Clusters',
        'eks': 'EKS Clusters',
        'lambda': 'Lambda Functions',
        'api_gateway': 'API Gateway',
        'elasticache': 'ElastiCache Clusters',
        'cloudwatch_logs': 'CloudWatch Log Groups',
        'cloudwatch_alarms': 'CloudWatch Alarms',
        'sns': 'SNS Topics',
        'sqs': 'SQS Queues',
        'dynamodb': 'DynamoDB Tables',
        'efs': 'EFS File Systems',
        'cloudtrail': 'CloudTrail',
        'kms': 'KMS Keys',
        'iam_users': 'IAM Users',
        'iam_roles': 'IAM Roles',
        'iam_policies': 'IAM Policies (Account Owned)',
        'cloudfront': 'CloudFront Distributions',
        'route53': 'Route 53 Hosted Zones'
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
    parser = argparse.ArgumentParser(description='AWS Resource Inventory Tool - Comprehensive AWS resource discovery')
    parser.add_argument('--profiles', type=str, help='Comma-separated list of AWS profiles (overrides interactive selection)')
    parser.add_argument('--regions', type=str, help='Comma-separated list of regions (overrides interactive selection)')
    parser.add_argument('--resources', type=str, default='all', 
                       help='Comma-separated list of resource types to inventory (default: all)')
    parser.add_argument('--output-format', choices=['table', 'json', 'csv'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--output-file', type=str, help='Output file path (optional)')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads for parallel execution (default: 10)')
    parser.add_argument('--list-resources', action='store_true', help='List all available resource types and exit')
    
    args = parser.parse_args()
    
    # Available resource types - now comprehensive
    available_resources = [
        # Compute
        'ec2', 'lambda', 'ecs', 'eks', 'auto_scaling_groups',
        # Storage
        'ebs', 'ebs_snapshots', 's3', 'efs',
        # Database
        'rds', 'rds_snapshots', 'dynamodb', 'elasticache',
        # Networking
        'vpc', 'subnets', 'security_groups', 'route_tables', 'internet_gateways', 
        'nat_gateways', 'eip', 'load_balancers', 'classic_load_balancers',
        # Application Services
        'api_gateway', 'sns', 'sqs', 'cloudfront', 'route53',
        # Management & Governance
        'cloudformation', 'cloudtrail', 'cloudwatch_logs', 'cloudwatch_alarms',
        # Security & Identity
        'iam', 'kms'
    ]
    
    # List available resources if requested
    if args.list_resources:
        print("Available resource types:")
        print("\nCompute:")
        print("  ec2, lambda, ecs, eks, auto_scaling_groups")
        print("\nStorage:")
        print("  ebs, ebs_snapshots, s3, efs")
        print("\nDatabase:")
        print("  rds, rds_snapshots, dynamodb, elasticache")
        print("\nNetworking:")
        print("  vpc, subnets, security_groups, route_tables, internet_gateways,")
        print("  nat_gateways, eip, load_balancers, classic_load_balancers")
        print("\nApplication Services:")
        print("  api_gateway, sns, sqs, cloudfront, route53")
        print("\nManagement & Governance:")
        print("  cloudformation, cloudtrail, cloudwatch_logs, cloudwatch_alarms")
        print("\nSecurity & Identity:")
        print("  iam, kms")
        print(f"\nTotal: {len(available_resources)} resource types")
        print("\nUse 'all' to select all resource types, or specify individual types separated by commas.")
        sys.exit(0)
    
    # Parse resource types
    if args.resources.lower() == 'all':
        resource_types = available_resources
    else:
        resource_types = [r.strip() for r in args.resources.split(',')]
        invalid_resources = [r for r in resource_types if r not in available_resources]
        if invalid_resources:
            print(f"Invalid resource types: {', '.join(invalid_resources)}")
            print(f"Use --list-resources to see all available resource types")
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
    
    print(f"\nStarting comprehensive inventory across {len(validated_accounts)} account(s) and {len(regions)} region(s)...")
    print(f"Resource types ({len(resource_types)}): {', '.join(resource_types)}")
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
    print("COMPREHENSIVE AWS RESOURCE INVENTORY RESULTS")
    print(f"{'='*80}")
    
    display_results(all_results, args.output_format, args.output_file)
    
    # Summary statistics
    print(f"\n{'='*80}")
    print("INVENTORY SUMMARY")
    print(f"{'='*80}")
    
    total_resources = 0
    resource_counts = {}
    
    for result in all_results:
        if 'error' not in result:
            for resource_type, data in result['resources'].items():
                if isinstance(data, list) and data:  # Valid data
                    count = len(data)
                    total_resources += count
                    if resource_type not in resource_counts:
                        resource_counts[resource_type] = 0
                    resource_counts[resource_type] += count
    
    print(f"Total resources discovered: {total_resources}")
    print(f"Account-region combinations processed: {len(all_results)}")
    
    if resource_counts:
        print(f"\nTop resource types by count:")
        sorted_resources = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)
        for resource_type, count in sorted_resources[:10]:  # Top 10
            resource_title = {
                'cloudformation': 'CloudFormation Stacks',
                'ec2': 'EC2 Instances',
                'security_groups': 'Security Groups',
                'vpc': 'VPCs',
                'subnets': 'Subnets',
                'route_tables': 'Route Tables',
                'internet_gateways': 'Internet Gateways',
                'nat_gateways': 'NAT Gateways',
                'load_balancers': 'Load Balancers',
                'classic_load_balancers': 'Classic Load Balancers',
                'auto_scaling_groups': 'Auto Scaling Groups',
                'rds': 'RDS Instances',
                'rds_snapshots': 'RDS Snapshots',
                's3': 'S3 Buckets',
                'ebs': 'EBS Volumes',
                'ebs_snapshots': 'EBS Snapshots',
                'eip': 'Elastic IPs',
                'ecs': 'ECS Clusters',
                'eks': 'EKS Clusters',
                'lambda': 'Lambda Functions',
                'api_gateway': 'API Gateway',
                'elasticache': 'ElastiCache',
                'cloudwatch_logs': 'CloudWatch Log Groups',
                'cloudwatch_alarms': 'CloudWatch Alarms',
                'sns': 'SNS Topics',
                'sqs': 'SQS Queues',
                'dynamodb': 'DynamoDB Tables',
                'efs': 'EFS File Systems',
                'cloudtrail': 'CloudTrail',
                'kms': 'KMS Keys',
                'iam_users': 'IAM Users',
                'iam_roles': 'IAM Roles',
                'iam_policies': 'IAM Policies',
                'cloudfront': 'CloudFront Distributions',
                'route53': 'Route 53 Hosted Zones'
            }.get(resource_type, resource_type.replace('_', ' ').title())
            
            print(f"  {resource_title}: {count}")
    
    print(f"\n{'='*80}")
    print(f"Inventory completed successfully!")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()

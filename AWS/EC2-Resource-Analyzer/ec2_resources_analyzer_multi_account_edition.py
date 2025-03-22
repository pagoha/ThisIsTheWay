import boto3
import pandas as pd
import configparser
import os
from datetime import datetime
import concurrent.futures

# Define regions to scan
DEFAULT_REGIONS = ['us-east-1', 'us-west-2']

def get_available_aws_profiles():
    """Get all available AWS profiles from credentials and config files"""
    profiles = set()
    
    # Check ~/.aws/credentials
    credentials_path = os.path.expanduser('~/.aws/credentials')
    config_path = os.path.expanduser('~/.aws/config')
    
    config = configparser.ConfigParser()
    
    # Read credentials file
    if os.path.exists(credentials_path):
        config.read(credentials_path)
        for section in config.sections():
            # In credentials file, the sections are directly the profile names
            profiles.add(section)
    
    # Read config file
    if os.path.exists(config_path):
        config.read(config_path)
        for section in config.sections():
            # In config file, the sections are often in format "profile name"
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
    
    print("\nAvailable AWS profiles:")
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

def get_ec2_details(account, region):
    print(f"Processing {account['name']} (profile: {account['profile_name']}) in region {region}...")
    
    # Create session based on profile or credentials
    try:
        session = boto3.Session(profile_name=account["profile_name"], region_name=region)
        ec2_client = session.client('ec2')
        ec2_resource = session.resource('ec2')
        elb_client = session.client('elbv2')
        cloudwatch_client = session.client('cloudwatch')
    except Exception as e:
        print(f"Error creating session for {account['name']} in {region}: {str(e)}")
        return []
    
    try:
        instances = ec2_client.describe_instances()['Reservations']
    except Exception as e:
        print(f"Error accessing {account['name']} in {region}: {str(e)}")
        return []
        
    instance_data = []

    # Get all target groups
    try:
        target_groups = elb_client.describe_target_groups()['TargetGroups']
        target_group_arns = [tg['TargetGroupArn'] for tg in target_groups]
    except Exception as e:
        print(f"Error getting target groups in {account['name']} ({region}): {str(e)}")
        target_group_arns = []

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            ec2_instance = ec2_resource.Instance(instance_id)
            
            # Extract the EC2 Name from tags
            instance_name = 'N/A'
            formatted_tags = []
            
            for tag in instance.get('Tags', []):
                # Format each tag with spacing
                formatted_tags.append(f"{tag['Key']}: {tag['Value']}")
                
                # Find the Name tag
                if tag['Key'].lower() == 'name':
                    instance_name = tag['Value']
            
            instance_info = {
                'Account': account['name'],
                'Account ID': account.get('account_id', 'Unknown'),
                'Region': region,
                'Instance ID': instance_id,
                'Name': instance_name,  # Added Name field
                'State': instance['State']['Name'],
                'Instance Type': instance['InstanceType'],
                'Public IP': instance.get('PublicIpAddress', 'N/A'),
                'Private IP': instance.get('PrivateIpAddress', 'N/A'),
                'Launch Time': instance['LaunchTime'],
                'VPC ID': instance.get('VpcId', 'N/A'),
                'Subnet ID': instance.get('SubnetId', 'N/A'),
                'Tags': ' | '.join(formatted_tags),  # Formatted tags with spacing
            }

            # Get AMI information
            if 'ImageId' in instance:
                try:
                    image = ec2_client.describe_images(ImageIds=[instance['ImageId']])['Images'][0]
                    instance_info['AMI ID'] = image['ImageId']
                    instance_info['AMI Name'] = image.get('Name', 'N/A')
                except Exception as e:
                    instance_info['AMI ID'] = instance['ImageId']
                    instance_info['AMI Name'] = f"Error: {str(e)}"
            else:
                instance_info['AMI ID'] = 'N/A'
                instance_info['AMI Name'] = 'N/A'

            # Get Security Groups
            security_groups = [f"{sg['GroupId']} ({sg['GroupName']})" for sg in instance['SecurityGroups']]
            instance_info['Security Groups'] = ', '.join(security_groups)

            # Get attached volumes and their snapshots
            volumes = ec2_instance.volumes.all()
            volume_info = []
            snapshot_info = []
            for vol in volumes:
                volume_info.append(f"{vol.id} ({vol.size} GB, {vol.volume_type})")
                
                # Get snapshots for this volume
                try:
                    snapshots = list(vol.snapshots.all())
                    for snap in snapshots:
                        snapshot_info.append(f"{snap.id} (Volume: {vol.id}, {snap.start_time})")
                except Exception as e:
                    snapshot_info.append(f"Error getting snapshots: {str(e)}")

            instance_info['EBS Volumes'] = ', '.join(volume_info)
            instance_info['Associated Snapshots'] = ', '.join(snapshot_info)

            # Get Elastic IPs
            try:
                addresses = ec2_client.describe_addresses(Filters=[{'Name': 'instance-id', 'Values': [instance_id]}])['Addresses']
                elastic_ips = [f"{addr['PublicIp']} ({addr['AllocationId']})" for addr in addresses]
                instance_info['Elastic IPs'] = ', '.join(elastic_ips)
            except Exception as e:
                instance_info['Elastic IPs'] = f"Error: {str(e)}"

            # Get Network Interfaces
            interfaces = ec2_instance.network_interfaces
            if interfaces:
                eni_info = [f"{eni.id} ({eni.private_ip_address})" for eni in interfaces]
                instance_info['Network Interfaces'] = ', '.join(eni_info)
            else:
                instance_info['Network Interfaces'] = 'No network interfaces'
                
            # Get associated backups (AWS Backup)
            try:
                backup_client = session.client('backup')
                backups = backup_client.list_recovery_points_by_resource(
                    ResourceArn=ec2_instance.arn
                )
                backup_info = [f"{backup['RecoveryPointArn']} ({backup['CreationDate']})" for backup in backups.get('RecoveryPoints', [])]
                instance_info['Associated Backups'] = ', '.join(backup_info)
            except Exception as e:
                instance_info['Associated Backups'] = f"Error retrieving backups: {str(e)}"

            # Get Load Balancer Target information
            instance_info['Load Balancer Targets'] = []
            for tg_arn in target_group_arns:
                try:
                    targets = elb_client.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
                    for target in targets:
                        if target['Target']['Id'] == instance_id:
                            tg_info = elb_client.describe_target_groups(TargetGroupArns=[tg_arn])['TargetGroups'][0]
                            instance_info['Load Balancer Targets'].append(f"{tg_info['TargetGroupName']} ({tg_arn})")
                except Exception as e:
                    pass
            instance_info['Load Balancer Targets'] = ', '.join(instance_info['Load Balancer Targets'])

            # Check for associated CloudWatch alarms
            try:
                alarms = cloudwatch_client.describe_alarms_for_metric(
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    MetricName='CPUUtilization',
                    Namespace='AWS/EC2'
                )['MetricAlarms']
                instance_info['CloudWatch Alarms'] = ', '.join([alarm['AlarmName'] for alarm in alarms]) if alarms else 'No alarms'
            except Exception as e:
                instance_info['CloudWatch Alarms'] = f"Error retrieving alarms: {str(e)}"

            instance_data.append(instance_info)

    return instance_data

def export_to_csv(all_data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ec2_resources_analyzer_multi_account_{timestamp}.csv"
    
    # Order columns to put Name near the beginning
    columns_order = ['Account', 'Account ID', 'Region', 'Instance ID', 'Name', 'State', 'Instance Type']
    
    df = pd.DataFrame(all_data)
    
    # Reorder columns to put important ones first, then the rest in their original order
    if not df.empty:
        first_columns = [col for col in columns_order if col in df.columns]
        other_columns = [col for col in df.columns if col not in columns_order]
        df = df[first_columns + other_columns]
    
    df.to_csv(filename, index=False)
    print(f"\nEC2 instance details from all accounts exported to {filename}")

def process_account_region(args):
    account, region = args
    return get_ec2_details(account, region)

if __name__ == '__main__':
    print("AWS EC2 Resources Analyzer - Multi-Account Edition")
    print("=================================================")
    
    # Select AWS profiles to use
    selected_profiles = select_aws_profiles()
    
    if not selected_profiles:
        print("No profiles selected. Exiting.")
        exit(0)
    
    # Convert profiles to account info
    AWS_ACCOUNTS = []
    for profile in selected_profiles:
        account_id = get_profile_account_id(profile)
        account_info = {
            "name": f"{profile} ({account_id})",
            "profile_name": profile,
            "account_id": account_id
        }
        AWS_ACCOUNTS.append(account_info)
    
    print(f"\nSelected {len(AWS_ACCOUNTS)} AWS accounts:")
    for account in AWS_ACCOUNTS:
        print(f"- {account['name']}")
    
    # Ask if user wants to use the default regions or specify their own
    print(f"\nDefault regions: {', '.join(DEFAULT_REGIONS)}")
    use_default = input("Use default regions? (y/n, default: y): ").lower() != 'n'
    
    REGIONS = DEFAULT_REGIONS
    if not use_default:
        regions_input = input("Enter the AWS regions separated by commas (e.g., us-east-1,us-west-2): ")
        REGIONS = [r.strip() for r in regions_input.split(',')]
    
    print(f"\nSelected regions: {', '.join(REGIONS)}")
    print(f"\nGathering EC2 instance details for {len(AWS_ACCOUNTS)} accounts across {len(REGIONS)} regions")
    
    all_instance_data = []
    
    # Create a list of all account-region combinations to process
    tasks = [(account, region) for account in AWS_ACCOUNTS for region in REGIONS]
    
    # Ask for concurrency level
    max_workers = 10
    concurrency_input = input(f"\nEnter maximum parallel tasks (default: {max_workers}): ")
    if concurrency_input.strip() and concurrency_input.strip().isdigit():
        max_workers = int(concurrency_input.strip())
    
    # Process accounts and regions in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(process_account_region, tasks))
        
    # Flatten the results list
    for result in results:
        all_instance_data.extend(result)
    
    print(f"\nFound {len(all_instance_data)} instances across all accounts and regions")
    export_to_csv(all_instance_data)
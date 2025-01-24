# Before running the script, make sure you have boto3 and pandas installed:
# >> pip install boto3 pandas
# This script performs the following tasks:
# Connects to the EC2 service in the specified region.
# Retrieves details of EC2 instances, including state, instance type, IP addresses, launch time, security groups, associated snapshots, associated aws backups, and tags.
# Gathers information on attached EBS volumes, Elastic IP addresses, and network interfaces.
# Exports the collected information to a CSV file.
# When you run the script, it will prompt you to enter the region [eg., us-east-1]

import boto3
import pandas as pd
from datetime import datetime

def get_ec2_details(region):
    ec2_client = boto3.client('ec2', region_name=region)
    ec2_resource = boto3.resource('ec2', region_name=region)
    instances = ec2_client.describe_instances()['Reservations']
    instance_data = []

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            ec2_instance = ec2_resource.Instance(instance_id)
            
            instance_info = {
                'Instance ID': instance_id,
                'State': instance['State']['Name'],
                'Instance Type': instance['InstanceType'],
                'Public IP': instance.get('PublicIpAddress', 'N/A'),
                'Private IP': instance.get('PrivateIpAddress', 'N/A'),
                'Launch Time': instance['LaunchTime'],
                'VPC ID': instance.get('VpcId', 'N/A'),
                'Subnet ID': instance.get('SubnetId', 'N/A'),
                'Tags': ', '.join([f"{tag['Key']}:{tag['Value']}" for tag in instance.get('Tags', [])]),
            }

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
                snapshots = list(vol.snapshots.all())
                for snap in snapshots:
                    snapshot_info.append(f"{snap.id} (Volume: {vol.id}, {snap.start_time})")

            instance_info['EBS Volumes'] = ', '.join(volume_info)
            instance_info['Associated Snapshots'] = ', '.join(snapshot_info)

            # Get Elastic IPs
            addresses = ec2_client.describe_addresses(Filters=[{'Name': 'instance-id', 'Values': [instance_id]}])['Addresses']
            elastic_ips = [f"{addr['PublicIp']} ({addr['AllocationId']})" for addr in addresses]
            instance_info['Elastic IPs'] = ', '.join(elastic_ips)

            # Get Network Interfaces
            interfaces = ec2_instance.network_interfaces
            eni_info = [f"{eni.id} ({eni.private_ip_address})" for eni in interfaces]
            instance_info['Network Interfaces'] = ', '.join(eni_info)

            # Get associated backups (AWS Backup)
            backup_client = boto3.client('backup', region_name=region)
            try:
                backups = backup_client.list_recovery_points_by_resource(
                    ResourceArn=ec2_instance.arn
                )
                backup_info = [f"{backup['RecoveryPointArn']} ({backup['CreationDate']})" for backup in backups.get('RecoveryPoints', [])]
                instance_info['Associated Backups'] = ', '.join(backup_info)
            except Exception as e:
                instance_info['Associated Backups'] = f"Error retrieving backups: {str(e)}"

            instance_data.append(instance_info)

    return instance_data

def export_to_csv(data, region):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ec2_instance_details_{region}_{timestamp}.csv"
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    print(f"EC2 instance details exported to {filename}")

if __name__ == '__main__':
    region = input("Enter the AWS region (e.g., us-east-1): ")
    
    print(f"Gathering EC2 instance details for region: {region}")
    ec2_details = get_ec2_details(region)
    
    export_to_csv(ec2_details, region)

# Before running the script, make sure you have boto3 and pandas installed:
# >> pip install boto3 pandas
# This script performs the following tasks:
# Connects to the EC2 service in the specified region.
# Retrieves details of EC2 instances, including state, instance type, IP addresses, launch time, security groups, and tags.
# Gathers information on attached EBS volumes, Elastic IP addresses, and network interfaces.
# Exports the collected information to a CSV file.
# Replace region with the desired AWS region (e.g., us-east-1) and specify the filename for the CSV export.

import boto3
import pandas as pd

def get_ec2_details(region):
    ec2_client = boto3.client('ec2', region_name=region)
    instances = ec2_client.describe_instances()['Reservations']
    instance_data = []

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_info = {
                'Instance ID': instance_id,
                'State': instance['State']['Name'],
                'Instance Type': instance['InstanceType'],
                'Public IP': instance.get('PublicIpAddress', 'N/A'),
                'Private IP': instance.get('PrivateIpAddress', 'N/A'),
                'Launch Time': instance['LaunchTime'],
                'Security Groups': [sg['GroupName'] for sg in instance['SecurityGroups']],
                'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            }

            # Get attached volumes
            volumes = ec2_client.describe_volumes(Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}])['Volumes']
            instance_info['EBS Volumes'] = [vol['VolumeId'] for vol in volumes]

            # Get Elastic IPs
            addresses = ec2_client.describe_addresses(Filters=[{'Name': 'instance-id', 'Values': [instance_id]}])['Addresses']
            instance_info['Elastic IPs'] = [addr['PublicIp'] for addr in addresses]

            # Get Network Interfaces
            interfaces = ec2_client.describe_network_interfaces(Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}])['NetworkInterfaces']
            instance_info['Network Interfaces'] = [eni['NetworkInterfaceId'] for eni in interfaces]

            instance_data.append(instance_info)

    return instance_data

def export_to_csv(data, filename):
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)

if __name__ == '__main__':
    region = 'us-east-1'  # Specify or change the AWS region
    filename = 'ec2_instance_details.csv' # Specify or change the filename

    ec2_details = get_ec2_details(region)
    export_to_csv(ec2_details, filename)
    print(f"EC2 instance details exported to {filename}")

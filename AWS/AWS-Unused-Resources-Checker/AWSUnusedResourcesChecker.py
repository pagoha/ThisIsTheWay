import boto3
import botocore
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from datetime import datetime, timedelta
import argparse

def get_profile_name():
    parser = argparse.ArgumentParser(description='Check for unused AWS resources.')
    parser.add_argument('--profile', help='AWS profile name to use')
    args = parser.parse_args()

    if args.profile:
        return args.profile
    else:
        return input("Enter the AWS profile name to use: ").strip()

def check_unused_resources(profile_name):
    try:
        session = boto3.Session(profile_name=profile_name)
        ec2 = session.client('ec2')
        
        findings = {
            "Unassociated Elastic IPs": [],
            "Orphaned EBS Volumes": [],
            "Old Snapshots": [],
            "Stopped EC2 Instances": [],
            "Errors": []
        }

        # Check for unassociated Elastic IPs
        try:
            elastic_ips = ec2.describe_addresses()
            for eip in elastic_ips['Addresses']:
                if 'InstanceId' not in eip:
                    findings["Unassociated Elastic IPs"].append(f"Elastic IP: {eip['PublicIp']}")
        except ClientError as e:
            findings["Errors"].append(f"Unable to check Elastic IPs: {str(e)}")

        # Check for orphaned EBS volumes
        try:
            volumes = ec2.describe_volumes()
            for volume in volumes['Volumes']:
                if len(volume['Attachments']) == 0:
                    findings["Orphaned EBS Volumes"].append(f"Volume ID: {volume['VolumeId']}")
        except ClientError as e:
            findings["Errors"].append(f"Unable to check EBS volumes: {str(e)}")

        # Check for old snapshots (older than 30 days)
        try:
            snapshots = ec2.describe_snapshots(OwnerIds=['self'])
            thirty_days_ago = datetime.now(snapshots['Snapshots'][0]['StartTime'].tzinfo) - timedelta(days=30)
            for snapshot in snapshots['Snapshots']:
                if snapshot['StartTime'] < thirty_days_ago:
                    findings["Old Snapshots"].append(f"Snapshot ID: {snapshot['SnapshotId']}, Created: {snapshot['StartTime']}")
        except ClientError as e:
            findings["Errors"].append(f"Unable to check snapshots: {str(e)}")

        # Check for stopped EC2 instances
        try:
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'stopped':
                        findings["Stopped EC2 Instances"].append(f"Instance ID: {instance['InstanceId']}")
        except ClientError as e:
            findings["Errors"].append(f"Unable to check EC2 instances: {str(e)}")

        return findings

    except NoCredentialsError:
        return {"Errors": ["Error: Unable to locate credentials. Please check your AWS configuration and the specified profile."]}
    except ProfileNotFound:
        return {"Errors": [f"Error: The specified profile '{profile_name}' was not found."]}
    except botocore.exceptions.TokenRetrievalError:
        return {"Errors": [f"Error: SSO token has expired. Please renew your SSO session using 'aws sso login --profile {profile_name}'"]}
    except Exception as e:
        return {"Errors": [f"An unexpected error occurred: {str(e)}"]}

def write_findings_to_file(findings, profile_name):
    with open('aws_unused_resources.txt', 'w') as f:
        f.write(f"AWS Unused Resources Report\n")
        f.write(f"Profile: {profile_name}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for category, items in findings.items():
            if items:
                f.write(f"{category}:\n")
                for item in items:
                    f.write(f"  - {item}\n")
                f.write("\n")

def main():
    profile_name = get_profile_name()
    print(f"Using AWS profile: {profile_name}")

    findings = check_unused_resources(profile_name)
    
    if any(findings.values()):
        print("\nUnused resources found:")
        for category, items in findings.items():
            if items:
                print(f"\n{category}:")
                for item in items:
                    print(f"  - {item}")
    else:
        print("\nNo unused resources found.")

    write_findings_to_file(findings, profile_name)
    print("\nFindings have been written to aws_unused_resources.txt")

if __name__ == "__main__":
    main()

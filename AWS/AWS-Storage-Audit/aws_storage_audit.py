import boto3
from botocore.exceptions import ClientError

def get_ec2_storage_total(region='us-east-1'):
    """Calculate total EBS volume storage in GB"""
    ec2 = boto3.client('ec2', region_name=region)
    total_gb = 0
    
    try:
        response = ec2.describe_volumes()
        for volume in response['Volumes']:
            total_gb += volume['Size']
        return total_gb
    except ClientError as e:
        print(f"Error getting EC2 volumes: {e}")
        return 0

def get_rds_storage_total(region='us-east-1'):
    """Calculate total RDS storage in GB"""
    rds = boto3.client('rds', region_name=region)
    total_gb = 0
    
    try:
        response = rds.describe_db_instances()
        for db in response['DBInstances']:
            total_gb += db['AllocatedStorage']
        return total_gb
    except ClientError as e:
        print(f"Error getting RDS instances: {e}")
        return 0

def get_dynamodb_storage_total(region='us-east-1'):
    """Calculate total DynamoDB storage in GB"""
    dynamodb = boto3.client('dynamodb', region_name=region)
    total_bytes = 0
    
    try:
        response = dynamodb.list_tables()
        for table_name in response['TableNames']:
            table_info = dynamodb.describe_table(TableName=table_name)
            total_bytes += table_info['Table']['TableSizeBytes']
        
        # Convert bytes to GB
        total_gb = total_bytes / (1024**3)
        return round(total_gb, 2)
    except ClientError as e:
        print(f"Error getting DynamoDB tables: {e}")
        return 0

def main():
    # Specify your region(s)
    regions = ['us-east-1']  # Add more regions as needed
    
    for region in regions:
        print(f"\n=== Storage Totals for {region} ===")
        ec2_storage = get_ec2_storage_total(region)
        rds_storage = get_rds_storage_total(region)
        dynamo_storage = get_dynamodb_storage_total(region)
        
        print(f"EC2 Storage Total (GB): {ec2_storage}")
        print(f"RDS Storage Total (GB): {rds_storage}")
        print(f"DynamoDB Storage Total (GB): {dynamo_storage}")
        print(f"Total Storage (GB): {ec2_storage + rds_storage + dynamo_storage}")

if __name__ == "__main__":
    main()

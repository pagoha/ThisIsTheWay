import boto3
import botocore
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from datetime import datetime, timedelta, timezone
import argparse

def get_profile_name():
    parser = argparse.ArgumentParser(description='Check for unused AWS resources.')
    parser.add_argument('--profile', help='AWS profile name to use')
    args = parser.parse_args()

    if args.profile:
        return args.profile
    else:
        return input("Enter the AWS profile name to use: ").strip()

def confirm_profile(profile_name):
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        print(f"Using AWS profile: {profile_name}")
        print(f"Account: {identity['Account']}")
        print(f"User ARN: {identity['Arn']}")
        return session, identity['Account']
    except Exception as e:
        print(f"Error confirming profile {profile_name}: {str(e)}")
        return None, None

def check_unused_resources(session):
    findings = {
        # EC2 related
        "Unassociated Elastic IPs": [],
        "Orphaned EBS Volumes": [],
        "Old EBS Snapshots": [],
        "Stopped EC2 Instances": [],
        "Unused AMIs": [],
        "Unused Security Groups": [],
        "Unused Key Pairs": [],
        
        # Load Balancing
        "Idle Load Balancers": [],
        
        # S3 related
        "Empty S3 Buckets": [],
        "S3 Buckets with Old Objects": [],
        
        # Database related
        "Stopped RDS Instances": [],
        "Unused RDS Snapshots": [],
        "Idle ElastiCache Clusters": [],
        "Idle DynamoDB Tables": [],
        
        # Networking
        "Unused NAT Gateways": [],
        "Unused Elastic Network Interfaces": [],
        "Unused VPCs": [],
        
        # Serverless/Container
        "Unused Lambda Functions": [],
        "Idle ECS Services": [],
        
        # Other services
        "Unused CloudFormation Stacks": [],
        "Idle ElasticBeanstalk Environments": [],
        "Unused IAM Roles": [],
        "Unused IAM Access Keys": [],
        
        # Errors
        "Errors": []
    }

    # Check EC2 related resources
    try:
        check_ec2_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking EC2 resources: {str(e)}")

    # Check S3 resources
    try:
        check_s3_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking S3 resources: {str(e)}")

    # Check RDS resources
    try:
        check_rds_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking RDS resources: {str(e)}")

    # Check ElastiCache resources
    try:
        check_elasticache_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking ElastiCache resources: {str(e)}")

    # Check DynamoDB resources
    try:
        check_dynamodb_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking DynamoDB resources: {str(e)}")

    # Check networking resources
    try:
        check_networking_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking networking resources: {str(e)}")

    # Check Load Balancers
    try:
        check_load_balancers(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking Load Balancers: {str(e)}")

    # Check Serverless/Container resources
    try:
        check_serverless_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking serverless resources: {str(e)}")

    # Check IAM resources
    try:
        check_iam_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking IAM resources: {str(e)}")

    # Check CloudFormation resources
    try:
        check_cloudformation_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking CloudFormation resources: {str(e)}")

    # Check Elastic Beanstalk resources
    try:
        check_elasticbeanstalk_resources(session, findings)
    except Exception as e:
        findings["Errors"].append(f"Error checking Elastic Beanstalk environments: {str(e)}")

    return findings

def check_ec2_resources(session, findings):
    ec2 = session.client('ec2')
    
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
                findings["Orphaned EBS Volumes"].append(f"Volume ID: {volume['VolumeId']}, Size: {volume['Size']} GB, Created: {volume.get('CreateTime', 'Unknown')}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check EBS volumes: {str(e)}")

    # Check for old snapshots (older than 30 days)
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=['self'])
        if snapshots['Snapshots']:
            thirty_days_ago = datetime.now(snapshots['Snapshots'][0]['StartTime'].tzinfo) - timedelta(days=30)
            for snapshot in snapshots['Snapshots']:
                if snapshot['StartTime'] < thirty_days_ago:
                    findings["Old EBS Snapshots"].append(f"Snapshot ID: {snapshot['SnapshotId']}, Size: {snapshot['VolumeSize']} GB, Created: {snapshot['StartTime']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check snapshots: {str(e)}")

    # Check for stopped EC2 instances
    try:
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'stopped':
                    # Get instance name from tags if available
                    name = "Unnamed"
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    
                    findings["Stopped EC2 Instances"].append(f"Instance ID: {instance['InstanceId']}, Name: {name}, Type: {instance['InstanceType']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check EC2 instances: {str(e)}")

    # Check for unused AMIs (not used by any instance)
    try:
        # Get all AMIs owned by this account
        amis = ec2.describe_images(Owners=['self'])
        
        # Get all instances
        instances = ec2.describe_instances()
        used_amis = set()
        
        # Identify used AMIs
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                used_amis.add(instance['ImageId'])
        
        # Find unused AMIs
        for ami in amis['Images']:
            if ami['ImageId'] not in used_amis:
                findings["Unused AMIs"].append(f"AMI ID: {ami['ImageId']}, Name: {ami['Name']}, Created: {ami.get('CreationDate', 'Unknown')}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check AMIs: {str(e)}")

    # Check for unused security groups (not associated with any resource)
    try:
        # Get all security groups
        security_groups = ec2.describe_security_groups()
        
        # Get all instances
        instances = ec2.describe_instances()
        used_sgs = set()
        
        # Identify security groups used by instances
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for sg in instance['SecurityGroups']:
                    used_sgs.add(sg['GroupId'])
        
        # Get ENIs to check for security groups used by other resources
        enis = ec2.describe_network_interfaces()
        for eni in enis['NetworkInterfaces']:
            for sg in eni['Groups']:
                used_sgs.add(sg['GroupId'])
        
        # Find unused security groups
        for sg in security_groups['SecurityGroups']:
            if sg['GroupId'] not in used_sgs and sg['GroupName'] != 'default':
                findings["Unused Security Groups"].append(f"Security Group ID: {sg['GroupId']}, Name: {sg['GroupName']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Security Groups: {str(e)}")
        
    # Check for unused key pairs
    try:
        # Get all key pairs
        key_pairs = ec2.describe_key_pairs()
        
        # Get all instances
        instances = ec2.describe_instances()
        used_key_pairs = set()
        
        # Identify used key pairs
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                if 'KeyName' in instance:
                    used_key_pairs.add(instance['KeyName'])
        
        # Find unused key pairs
        for key_pair in key_pairs['KeyPairs']:
            if key_pair['KeyName'] not in used_key_pairs:
                findings["Unused Key Pairs"].append(f"Key Pair: {key_pair['KeyName']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Key Pairs: {str(e)}")

def check_load_balancers(session, findings):
    # Check for Classic Load Balancers with no instances
    try:
        elb = session.client('elb')
        lbs = elb.describe_load_balancers()
        for lb in lbs['LoadBalancerDescriptions']:
            if len(lb['Instances']) == 0:
                findings["Idle Load Balancers"].append(f"Classic Load Balancer: {lb['LoadBalancerName']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Classic Load Balancers: {str(e)}")
        
    # Check for Application/Network Load Balancers with no targets
    try:
        elbv2 = session.client('elbv2')
        lbs = elbv2.describe_load_balancers()
        
        for lb in lbs['LoadBalancers']:
            # Get target groups for this LB
            target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])
            has_targets = False
            
            for tg in target_groups['TargetGroups']:
                # Check if target group has targets
                targets = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                if len(targets['TargetHealthDescriptions']) > 0:
                    has_targets = True
                    break
            
            if not has_targets:
                findings["Idle Load Balancers"].append(f"{lb['Type']} Load Balancer: {lb['LoadBalancerName']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Application/Network Load Balancers: {str(e)}")

def check_s3_resources(session, findings):
    s3 = session.client('s3')
    
    # Check for empty S3 buckets
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            try:
                # Check if bucket is empty
                objects = s3.list_objects_v2(Bucket=bucket['Name'], MaxKeys=1)
                if 'Contents' not in objects or len(objects['Contents']) == 0:
                    findings["Empty S3 Buckets"].append(f"Bucket: {bucket['Name']}, Created: {bucket['CreationDate']}")
            except ClientError as e:
                # Skip if we don't have permission to list objects
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check S3 buckets: {str(e)}")
    
    # Check for S3 buckets with old objects (no new objects in the last 90 days)
    try:
        ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
        for bucket in buckets['Buckets']:
            try:
                # Get the most recent object
                objects = s3.list_objects_v2(Bucket=bucket['Name'])
                if 'Contents' in objects and len(objects['Contents']) > 0:
                    # Sort objects by last modified
                    latest_object = sorted(objects['Contents'], key=lambda x: x['LastModified'], reverse=True)[0]
                    
                    if latest_object['LastModified'].replace(tzinfo=None) < ninety_days_ago.replace(tzinfo=None):
                        findings["S3 Buckets with Old Objects"].append(f"Bucket: {bucket['Name']}, Last Modified: {latest_object['LastModified']}")
            except ClientError:
                # Skip if we don't have permission
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check S3 object age: {str(e)}")

def check_rds_resources(session, findings):
    rds = session.client('rds')
    
    # Check for stopped RDS instances
    try:
        instances = rds.describe_db_instances()
        for instance in instances['DBInstances']:
            if instance['DBInstanceStatus'] == 'stopped':
                findings["Stopped RDS Instances"].append(f"DB Instance: {instance['DBInstanceIdentifier']}, Type: {instance['DBInstanceClass']}, Engine: {instance['Engine']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check RDS instances: {str(e)}")
    
    # Check for old RDS snapshots
    try:
        snapshots = rds.describe_db_snapshots(SnapshotType='manual')
        if snapshots['DBSnapshots']:
            thirty_days_ago = datetime.now(snapshots['DBSnapshots'][0]['SnapshotCreateTime'].tzinfo) - timedelta(days=30)
            
            for snapshot in snapshots['DBSnapshots']:
                if snapshot['SnapshotCreateTime'] < thirty_days_ago:
                    findings["Unused RDS Snapshots"].append(f"Snapshot: {snapshot['DBSnapshotIdentifier']}, Created: {snapshot['SnapshotCreateTime']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check RDS snapshots: {str(e)}")

def check_elasticache_resources(session, findings):
    elasticache = session.client('elasticache')
    
    # Check for idle ElastiCache clusters (low CPU usage could indicate idle, but would need CloudWatch metrics)
    try:
        clusters = elasticache.describe_cache_clusters()
        cloudwatch = session.client('cloudwatch')
        
        for cluster in clusters['CacheClusters']:
            # Get CPU utilization for the past day
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=1)
            
            try:
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/ElastiCache',
                    MetricName='CPUUtilization',
                    Dimensions=[
                        {
                            'Name': 'CacheClusterId',
                            'Value': cluster['CacheClusterId']
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day in seconds
                    Statistics=['Average']
                )
                
                # If CPU usage is very low, mark as potentially idle
                if len(response['Datapoints']) > 0:
                    avg_cpu = min([point['Average'] for point in response['Datapoints']])
                    if avg_cpu < 5:  # Less than 5% CPU usage
                        findings["Idle ElastiCache Clusters"].append(f"Cluster: {cluster['CacheClusterId']}, Type: {cluster['CacheNodeType']}, Engine: {cluster['Engine']}, Avg CPU: {avg_cpu:.2f}%")
            except Exception:
                # Skip if we can't get metrics
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check ElastiCache clusters: {str(e)}")

def check_dynamodb_resources(session, findings):
    dynamodb = session.client('dynamodb')
    cloudwatch = session.client('cloudwatch')
    
    # Check for idle DynamoDB tables (low read/write capacity usage)
    try:
        tables = dynamodb.list_tables()
        
        for table_name in tables['TableNames']:
            try:
                # Get table details
                table = dynamodb.describe_table(TableName=table_name)
                
                # Get read/write operations for the past day
                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(days=1)
                
                # Check consumed read capacity
                read_response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName='ConsumedReadCapacityUnits',
                    Dimensions=[
                        {
                            'Name': 'TableName',
                            'Value': table_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
                
                # Check consumed write capacity
                write_response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName='ConsumedWriteCapacityUnits',
                    Dimensions=[
                        {
                            'Name': 'TableName',
                            'Value': table_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
                
                # If both read and write capacity are very low, mark as potentially idle
                read_sum = sum([point['Sum'] for point in read_response['Datapoints']]) if read_response['Datapoints'] else 0
                write_sum = sum([point['Sum'] for point in write_response['Datapoints']]) if write_response['Datapoints'] else 0
                
                if read_sum < 100 and write_sum < 100:  # Arbitrary threshold
                    findings["Idle DynamoDB Tables"].append(f"Table: {table_name}, Size: {table['Table'].get('TableSizeBytes', 'Unknown')} bytes, Items: {table['Table'].get('ItemCount', 'Unknown')}")
            except Exception:
                # Skip if we can't get metrics or table details
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check DynamoDB tables: {str(e)}")

def check_networking_resources(session, findings):
    ec2 = session.client('ec2')
    
    # Check for unused NAT Gateways
    try:
        # Get all NAT gateways
        nat_gateways = ec2.describe_nat_gateways()
        
        # Check route tables to see if NAT is being used
        route_tables = ec2.describe_route_tables()
        used_nat_gateways = set()
        
        for rt in route_tables['RouteTables']:
            for route in rt['Routes']:
                if 'NatGatewayId' in route:
                    used_nat_gateways.add(route['NatGatewayId'])
        
        # Find unused NAT gateways
        for nat in nat_gateways['NatGateways']:
            if nat['NatGatewayId'] not in used_nat_gateways and nat['State'] == 'available':
                findings["Unused NAT Gateways"].append(f"NAT Gateway: {nat['NatGatewayId']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check NAT Gateways: {str(e)}")

    # Check for unused Elastic Network Interfaces
    try:
        enis = ec2.describe_network_interfaces()
        for eni in enis['NetworkInterfaces']:
            if eni['Status'] == 'available':  # Not attached to anything
                findings["Unused Elastic Network Interfaces"].append(f"ENI ID: {eni['NetworkInterfaceId']}, VPC: {eni['VpcId']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Network Interfaces: {str(e)}")
        
    # Check for unused VPCs (no instances or other resources)
    try:
        vpcs = ec2.describe_vpcs()
        
        for vpc in vpcs['Vpcs']:
            # Check if VPC has instances
            instances_response = ec2.describe_instances(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
            )
            
            if not instances_response['Reservations']:
                # No instances, check for other resources
                has_resources = False
                
                # Check for load balancers in this VPC
                try:
                    elbv2 = session.client('elbv2')
                    lbs = elbv2.describe_load_balancers()
                    for lb in lbs['LoadBalancers']:
                        if vpc['VpcId'] in lb['VpcId']:
                            has_resources = True
                            break
                except:
                    pass
                
                # Check for RDS instances in this VPC
                if not has_resources:
                    try:
                        rds = session.client('rds')
                        db_instances = rds.describe_db_instances()
                        for db in db_instances['DBInstances']:
                            if vpc['VpcId'] in db['DBSubnetGroup']['VpcId']:
                                has_resources = True
                                break
                    except:
                        pass
                
                if not has_resources and not vpc.get('IsDefault', False):  # Don't report default VPCs
                    findings["Unused VPCs"].append(f"VPC ID: {vpc['VpcId']}, CIDR: {vpc.get('CidrBlock', 'Unknown')}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check VPCs: {str(e)}")

def check_serverless_resources(session, findings):
    # Check for unused Lambda functions (no invocations in the last 30 days)
    try:
        lam = session.client('lambda')
        cloudwatch = session.client('cloudwatch')
        
        functions = lam.list_functions()
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        
        for function in functions['Functions']:
            try:
                # Check if function was invoked recently
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[
                        {
                            'Name': 'FunctionName',
                            'Value': function['FunctionName']
                        }
                    ],
                    StartTime=thirty_days_ago,
                    EndTime=datetime.now(timezone.utc),
                    Period=2592000,  # 30 days in seconds
                    Statistics=['Sum']
                )
                
                if not response['Datapoints'] or response['Datapoints'][0]['Sum'] == 0:
                    findings["Unused Lambda Functions"].append(f"Function: {function['FunctionName']}, Runtime: {function['Runtime']}, Last Modified: {function['LastModified']}")
            except Exception:
                # Skip if we can't get metrics
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Lambda functions: {str(e)}")

    # Check for idle ECS services (no running tasks)
    try:
        ecs = session.client('ecs')
        
        # List all clusters
        clusters = ecs.list_clusters()
        
        for cluster_arn in clusters['clusterArns']:
            # List services in this cluster
            services = ecs.list_services(cluster=cluster_arn)
            
            for service_arn in services['serviceArns']:
                # Get service details
                service = ecs.describe_services(cluster=cluster_arn, services=[service_arn])
                
                if service['services'] and service['services'][0]['runningCount'] == 0:
                    service_name = service['services'][0]['serviceName']
                    findings["Idle ECS Services"].append(f"Service: {service_name}, Cluster: {cluster_arn.split('/')[-1]}, Desired Count: {service['services'][0]['desiredCount']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check ECS services: {str(e)}")

def check_iam_resources(session, findings):
    iam = session.client('iam')
    
    # Check for unused IAM roles (not used in the last 90 days)
    try:
        roles = iam.list_roles()
        
        ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
        
        for role in roles['Roles']:
            try:
                # Get the role's last used date
                role_last_used = iam.get_role(RoleName=role['RoleName'])
                
                if 'RoleLastUsed' in role_last_used['Role'] and 'LastUsedDate' in role_last_used['Role']['RoleLastUsed']:
                    last_used = role_last_used['Role']['RoleLastUsed']['LastUsedDate']
                    if last_used < ninety_days_ago:
                        findings["Unused IAM Roles"].append(f"Role: {role['RoleName']}, Last Used: {last_used}")
                else:
                    # If role has never been used and is older than 90 days
                    if role['CreateDate'] < ninety_days_ago:
                        findings["Unused IAM Roles"].append(f"Role: {role['RoleName']}, Never Used, Created: {role['CreateDate']}")
            except Exception:
                # Skip if we can't get role details
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check IAM roles: {str(e)}")

    # Check for old IAM access keys (older than 90 days)
    try:
        users = iam.list_users()
        
        ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
        
        for user in users['Users']:
            try:
                # Get access keys for this user
                access_keys = iam.list_access_keys(UserName=user['UserName'])
                
                for key in access_keys['AccessKeyMetadata']:
                    if key['CreateDate'] < ninety_days_ago and key['Status'] == 'Active':
                        findings["Unused IAM Access Keys"].append(f"User: {user['UserName']}, Access Key ID: {key['AccessKeyId']}, Created: {key['CreateDate']}")
            except Exception:
                # Skip if we can't get access key details
                continue
    except ClientError as e:
        findings["Errors"].append(f"Unable to check IAM access keys: {str(e)}")

def check_cloudformation_resources(session, findings):
    cfn = session.client('cloudformation')
    
    # Check for CloudFormation stacks with ROLLBACK_COMPLETE status
    try:
        stacks = cfn.list_stacks(StackStatusFilter=[
            'CREATE_FAILED', 'ROLLBACK_COMPLETE', 'DELETE_FAILED'
        ])
        
        for stack in stacks.get('StackSummaries', []):
            findings["Unused CloudFormation Stacks"].append(f"Stack: {stack['StackName']}, Status: {stack['StackStatus']}, Last Updated: {stack.get('LastUpdatedTime', stack['CreationTime'])}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check CloudFormation stacks: {str(e)}")

def check_elasticbeanstalk_resources(session, findings):
    eb = session.client('elasticbeanstalk')
    
    # Check for Elastic Beanstalk environments that are not running or healthy
    try:
        envs = eb.describe_environments()
        
        for env in envs['Environments']:
            if env['Status'] != 'Ready' or env['Health'] != 'Green':
                findings["Idle ElasticBeanstalk Environments"].append(f"Environment: {env['EnvironmentName']}, Application: {env['ApplicationName']}, Status: {env['Status']}, Health: {env['Health']}")
    except ClientError as e:
        findings["Errors"].append(f"Unable to check Elastic Beanstalk environments: {str(e)}")

def generate_summary(findings):
    summary = []
    for category, items in findings.items():
        if items:
            if category == "Errors":
                summary.append(f"- {len(items)} Error{'s' if len(items) > 1 else ''} encountered during scanning")
            else:
                if "Old" in category or "Unused" in category:
                    summary.append(f"- {len(items)} {category}")
                else:
                    summary.append(f"- {len(items)} {category}")
    
    return summary

def get_recommendations():
    recommendations = {
        "Cost Optimization": [
            "Release unassociated Elastic IPs to avoid unnecessary charges ($0.005/hr per unused IP)",
            "Delete orphaned EBS volumes or attach them to instances if needed",
            "Consider creating a snapshot lifecycle policy for automated management",
            "Evaluate stopped EC2 instances - terminate if no longer needed or consider using Instance Scheduler",
            "Consider removing unused AMIs and their associated snapshots",
            "Evaluate load balancers with no targets for potential cost savings",
            "Clean up empty S3 buckets or buckets with only old objects",
            "Review stopped RDS instances - either start them or take a final snapshot and delete",
            "Delete old manual RDS snapshots after review",
            "Consider reducing capacity or removing idle DynamoDB tables",
            "Remove unused NAT Gateways ($0.045/hr per gateway plus data charges)",
            "Delete unused VPCs and their associated resources",
            "Archive or remove unused Lambda functions",
            "Clean up failed/rolled back CloudFormation stacks"
        ],
        "Security Considerations": [
            "Regularly review old snapshots to ensure they don't contain sensitive data",
            "Remove unused IAM roles and access keys to minimize security risks",
            "Implement proper tagging strategy for better resource tracking and security",
            "Review security groups rules to ensure principle of least privilege",
            "Rotate access keys regularly even if they appear unused",
            "Consider enabling AWS Config to monitor resource configuration changes",
            "Ensure S3 buckets have appropriate access controls even if empty",
            "Review unused VPCs to ensure no unintended network paths exist",
            "Remove unused key pairs to follow security best practices"
        ],
        "Next Steps": [
            "Review the scan results with relevant teams",
            "Implement resource cleanup following change management processes",
            "Consider scheduling this scan to run regularly for ongoing cost optimization",
            "Address permission issues that caused errors during the scan",
            "Implement resource tagging standards to better track resource ownership",
            "Consider using AWS Cost Explorer to identify additional savings",
            "Evaluate using AWS Trusted Advisor for more comprehensive recommendations",
            "Create automated cleanup workflows for common unused resources"
        ]
    }
    return recommendations

def write_findings_to_file(findings, profile_name, account_id):
    # Generate filename with current date and time
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'aws_unused_resources_{current_time}.txt'
    summary = generate_summary(findings)
    recommendations = get_recommendations()

    with open(filename, 'w') as f:
        f.write(f"# AWS Unused Resources Report\n")
        f.write(f"Profile: {profile_name}\n")
        f.write(f"Account: {account_id}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## SUMMARY\n")
        if any(len(items) > 0 for items in findings.values()):
            f.write("The scan identified the following unused resources that may incur unnecessary costs:\n")
            for line in summary:
                f.write(f"{line}\n")
        else:
            f.write("No unused resources were found in this scan.\n")
        f.write("\n")

        f.write("## DETAILED FINDINGS\n\n")
        for category, items in findings.items():
            if items:
                f.write(f"{category}:\n")
                for item in items:
                    f.write(f"  - {item}\n")
                f.write("\n")

        f.write("## RECOMMENDATIONS\n\n")
        for category, recs in recommendations.items():
            f.write(f"{len(recs) > 0 and f'1. {category}:' or ''}\n")
            for i, rec in enumerate(recs):
                f.write(f"   - {rec}\n")
            f.write("\n")

    return filename

def main():
    profile_name = get_profile_name()
    session, account_id = confirm_profile(profile_name)
    
    if not session:
        print("Failed to create a valid AWS session. Exiting.")
        return

    print("\nScanning for unused resources. This may take several minutes...")
    findings = check_unused_resources(session)
    summary = generate_summary(findings)
    
    if any(findings.values()):
        print("\nUnused resources found:")
        for line in summary:
            print(line)
    else:
        print("\nNo unused resources found.")

    filename = write_findings_to_file(findings, profile_name, account_id)
    print(f"\nFindings have been written to {filename}")

if __name__ == "__main__":
    main()

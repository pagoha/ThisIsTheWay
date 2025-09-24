#!/usr/bin/env python3
import boto3
import botocore.session
import sys
import time
import csv
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError

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
                    if sel.isdigit():
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

def get_output_preferences():
    """Get user preferences for output formats"""
    print("\nOutput format options:")
    print("1. Text report only")
    print("2. CSV export only") 
    print("3. Both text report and CSV export")
    
    while True:
        choice = input("\nSelect output format (1-3, or press Enter for both): ").strip()
        
        if not choice or choice == "3":
            return True, True  # text, csv
        elif choice == "1":
            return True, False
        elif choice == "2":
            return False, True
        else:
            print("Invalid selection. Please choose 1, 2, or 3.")

def format_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def get_bucket_metrics(s3_client, cloudwatch_client, bucket_name, region):
    """Get CloudWatch metrics for bucket size and object count"""
    try:
        # Get bucket size in bytes
        size_response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=datetime.now(timezone.utc) - timedelta(days=2),
            EndTime=datetime.now(timezone.utc),
            Period=86400,  # 1 day
            Statistics=['Average']
        )
        
        bucket_size = 0
        if size_response['Datapoints']:
            bucket_size = int(size_response['Datapoints'][-1]['Average'])
        
        # Get object count
        count_response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='NumberOfObjects',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
            ],
            StartTime=datetime.now(timezone.utc) - timedelta(days=2),
            EndTime=datetime.now(timezone.utc),
            Period=86400,  # 1 day
            Statistics=['Average']
        )
        
        object_count = 0
        if count_response['Datapoints']:
            object_count = int(count_response['Datapoints'][-1]['Average'])
        
        return bucket_size, object_count
        
    except Exception as e:
        # If CloudWatch metrics aren't available, try to get basic info
        try:
            # Try to list a few objects to see if bucket has content
            response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            has_objects = 'Contents' in response
            return 0, 1 if has_objects else 0  # Return estimated count
        except Exception:
            return 0, 0

def get_bucket_last_modified(s3_client, bucket_name):
    """Get the last modified date of the most recent object in the bucket"""
    try:
        # List objects sorted by last modified (most recent first)
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            MaxKeys=1000  # Check up to 1000 objects for last modified
        )
        
        if 'Contents' not in response:
            return None  # Empty bucket
        
        # Find the most recently modified object
        latest_modified = None
        for obj in response['Contents']:
            if latest_modified is None or obj['LastModified'] > latest_modified:
                latest_modified = obj['LastModified']
        
        return latest_modified
        
    except Exception as e:
        return None

def get_bucket_storage_classes(s3_client, bucket_name):
    """Get storage class distribution for the bucket"""
    storage_classes = {}
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                for obj in page['Contents']:
                    storage_class = obj.get('StorageClass', 'STANDARD')
                    storage_classes[storage_class] = storage_classes.get(storage_class, 0) + 1
    except Exception:
        pass
    
    return storage_classes

def get_s3_buckets_for_account(account_info):
    """Get all S3 buckets for a single account"""
    session = account_info['session']
    account_id = account_info['account_id']
    profile_name = account_info['profile']
    
    s3_client = session.client('s3')
    
    print(f"\nAnalyzing account {account_id} ({profile_name})...")
    
    try:
        # Get all buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        print(f"  Found {len(buckets)} S3 buckets")
        
        # Initialize data structures
        bucket_details = []
        error_buckets = []
        today = datetime.now(timezone.utc)
        
        # Process each bucket
        for i, bucket in enumerate(buckets):
            if i > 0 and i % 10 == 0:
                print(f"  Processed {i}/{len(buckets)} buckets...")
                
            bucket_name = bucket['Name']
            bucket_created_date = bucket['CreationDate']
            bucket_age_days = (today - bucket_created_date).days
            
            try:
                # Get bucket region
                try:
                    region_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    region = region_response.get('LocationConstraint') or 'us-east-1'
                except Exception:
                    region = 'us-east-1'  # Default region
                
                # Create regional clients for metrics
                try:
                    regional_s3 = session.client('s3', region_name=region)
                    cloudwatch_client = session.client('cloudwatch', region_name=region)
                    bucket_size, object_count = get_bucket_metrics(regional_s3, cloudwatch_client, bucket_name, region)
                except Exception:
                    bucket_size, object_count = 0, 0
                
                # Get last modified date
                last_modified = get_bucket_last_modified(s3_client, bucket_name)
                
                # Get bucket versioning status
                try:
                    versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    versioning_status = versioning_response.get('Status', 'Disabled')
                except Exception:
                    versioning_status = 'Unknown'
                
                # Get bucket encryption
                try:
                    encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    encryption_enabled = True
                    encryption_type = "AES256/KMS"
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        encryption_enabled = False
                        encryption_type = "None"
                    else:
                        encryption_enabled = False
                        encryption_type = "Unknown"
                
                # Get bucket public access block
                try:
                    public_access_response = s3_client.get_public_access_block(Bucket=bucket_name)
                    public_access_config = public_access_response['PublicAccessBlockConfiguration']
                    is_public_blocked = all([
                        public_access_config.get('BlockPublicAcls', False),
                        public_access_config.get('IgnorePublicAcls', False),
                        public_access_config.get('BlockPublicPolicy', False),
                        public_access_config.get('RestrictPublicBuckets', False)
                    ])
                except Exception:
                    is_public_blocked = False
                
                # Get bucket lifecycle configuration
                try:
                    lifecycle_response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    has_lifecycle = True
                    lifecycle_rules = len(lifecycle_response.get('Rules', []))
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                        has_lifecycle = False
                        lifecycle_rules = 0
                    else:
                        has_lifecycle = False
                        lifecycle_rules = 0
                
                # Get storage class distribution (for smaller buckets)
                storage_classes = {}
                if object_count < 10000:  # Only analyze storage classes for smaller buckets
                    storage_classes = get_bucket_storage_classes(s3_client, bucket_name)
                
                # Calculate days since last modification
                days_since_modified = None
                if last_modified:
                    days_since_modified = (today - last_modified).days
                
                bucket_data = {
                    'AccountId': account_id,
                    'ProfileName': profile_name,
                    'BucketName': bucket_name,
                    'Created': bucket_created_date,
                    'AgeInDays': bucket_age_days,
                    'Region': region,
                    'Size': bucket_size,
                    'SizeFormatted': format_size(bucket_size),
                    'ObjectCount': object_count,
                    'LastModified': last_modified,
                    'DaysSinceModified': days_since_modified,
                    'VersioningStatus': versioning_status,
                    'EncryptionEnabled': encryption_enabled,
                    'EncryptionType': encryption_type,
                    'PublicAccessBlocked': is_public_blocked,
                    'HasLifecycle': has_lifecycle,
                    'LifecycleRules': lifecycle_rules,
                    'StorageClasses': storage_classes,
                    'IsEmpty': object_count == 0
                }
                
                bucket_details.append(bucket_data)
                
            except Exception as e:
                print(f"  Warning: Error processing bucket {bucket_name}: {e}")
                error_buckets.append({
                    'AccountId': account_id,
                    'ProfileName': profile_name,
                    'BucketName': bucket_name,
                    'Created': bucket_created_date,
                    'AgeInDays': bucket_age_days,
                    'Error': str(e)
                })
                continue
        
        print(f"  Successfully processed {len(buckets) - len(error_buckets)}/{len(buckets)} buckets")
        
        return {
            'bucket_details': bucket_details,
            'error_buckets': error_buckets,
            'total_buckets': len(buckets),
            'account_id': account_id,
            'profile_name': profile_name
        }
    
    except Exception as e:
        print(f"  Error retrieving S3 buckets for account {account_id}: {e}")
        return {
            'bucket_details': [],
            'error_buckets': [],
            'total_buckets': 0,
            'account_id': account_id,
            'profile_name': profile_name,
            'account_error': str(e)
        }

def consolidate_results(account_results):
    """Consolidate results from multiple accounts"""
    all_bucket_details = []
    all_error_buckets = []
    total_buckets = 0
    account_summaries = []
    
    for result in account_results:
        all_bucket_details.extend(result['bucket_details'])
        all_error_buckets.extend(result['error_buckets'])
        total_buckets += result['total_buckets']
        
        # Create account summary
        account_summary = {
            'account_id': result['account_id'],
            'profile_name': result['profile_name'],
            'total_buckets': result['total_buckets'],
            'bucket_count': len(result['bucket_details']),
            'error_count': len(result['error_buckets'])
        }
        
        if 'account_error' in result:
            account_summary['account_error'] = result['account_error']
        
        account_summaries.append(account_summary)
    
    return {
        'bucket_details': all_bucket_details,
        'error_buckets': all_error_buckets,
        'total_buckets': total_buckets,
        'account_summaries': account_summaries
    }

def save_csv_report(results, timestamp):
    """Save bucket details to CSV file"""
    csv_filename = f"s3_buckets_multi_account_report_{timestamp}.csv"
    
    bucket_details = results['bucket_details']
    error_buckets = results['error_buckets']
    
    try:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            # Define CSV headers (now includes AccountId and ProfileName)
            fieldnames = [
                'AccountId', 'ProfileName', 'BucketName', 'Region', 'CreationDate', 'AgeInDays', 
                'SizeBytes', 'SizeFormatted', 'ObjectCount', 'LastModified', 'DaysSinceModified', 
                'IsEmpty', 'VersioningStatus', 'EncryptionEnabled', 'EncryptionType', 
                'PublicAccessBlocked', 'HasLifecycle', 'LifecycleRules', 'StorageClasses', 
                'SecurityIssues', 'CostOptimization'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write bucket data
            for bucket in bucket_details:
                # Identify security issues
                security_issues = []
                if not bucket['EncryptionEnabled']:
                    security_issues.append('No Encryption')
                if not bucket['PublicAccessBlocked']:
                    security_issues.append('Public Access Not Blocked')
                
                # Identify cost optimization opportunities
                cost_optimizations = []
                if bucket['IsEmpty']:
                    cost_optimizations.append('Empty Bucket')
                if not bucket['HasLifecycle'] and not bucket['IsEmpty']:
                    cost_optimizations.append('No Lifecycle Policy')
                
                # Format storage classes as string
                storage_classes_str = ', '.join([f"{k}:{v}" for k, v in bucket['StorageClasses'].items()]) if bucket['StorageClasses'] else 'Unknown'
                
                row_data = {
                    'AccountId': bucket['AccountId'],
                    'ProfileName': bucket['ProfileName'],
                    'BucketName': bucket['BucketName'],
                    'Region': bucket['Region'],
                    'CreationDate': bucket['Created'].strftime('%Y-%m-%d %H:%M:%S'),
                    'AgeInDays': bucket['AgeInDays'],
                    'SizeBytes': bucket['Size'],
                    'SizeFormatted': bucket['SizeFormatted'],
                    'ObjectCount': bucket['ObjectCount'],
                    'LastModified': bucket['LastModified'].strftime('%Y-%m-%d %H:%M:%S') if bucket['LastModified'] else '',
                    'DaysSinceModified': bucket['DaysSinceModified'] if bucket['DaysSinceModified'] is not None else '',
                    'IsEmpty': bucket['IsEmpty'],
                    'VersioningStatus': bucket['VersioningStatus'],
                    'EncryptionEnabled': bucket['EncryptionEnabled'],
                    'EncryptionType': bucket['EncryptionType'],
                    'PublicAccessBlocked': bucket['PublicAccessBlocked'],
                    'HasLifecycle': bucket['HasLifecycle'],
                    'LifecycleRules': bucket['LifecycleRules'],
                    'StorageClasses': storage_classes_str,
                    'SecurityIssues': '; '.join(security_issues) if security_issues else 'None',
                    'CostOptimization': '; '.join(cost_optimizations) if cost_optimizations else 'None'
                }
                
                writer.writerow(row_data)
            
            # Write error buckets if any
            if error_buckets:
                for bucket in error_buckets:
                    row_data = {
                        'AccountId': bucket['AccountId'],
                        'ProfileName': bucket['ProfileName'],
                        'BucketName': bucket['BucketName'],
                        'Region': 'ERROR',
                        'CreationDate': bucket['Created'].strftime('%Y-%m-%d %H:%M:%S'),
                        'AgeInDays': bucket['AgeInDays'],
                        'SizeBytes': 0,
                        'SizeFormatted': '0 B',
                        'ObjectCount': 0,
                        'LastModified': '',
                        'DaysSinceModified': '',
                        'IsEmpty': True,
                        'VersioningStatus': 'ERROR',
                        'EncryptionEnabled': False,
                        'EncryptionType': 'ERROR',
                        'PublicAccessBlocked': False,
                        'HasLifecycle': False,
                        'LifecycleRules': 0,
                        'StorageClasses': f"ERROR: {bucket['Error']}",
                        'SecurityIssues': 'Analysis Failed',
                        'CostOptimization': 'Analysis Failed'
                    }
                    writer.writerow(row_data)
        
        return csv_filename
        
    except Exception as e:
        print(f"Error creating CSV file: {e}")
        return None

def display_multi_account_analysis(results, timestamp):
    """Display a formatted report of the multi-account S3 bucket analysis"""
    bucket_details = results['bucket_details']
    error_buckets = results['error_buckets']
    total_buckets = results['total_buckets']
    account_summaries = results['account_summaries']
    
    # Terminal width for better formatting
    terminal_width = 160
    
    # Helper function to create a formatted header
    def create_header(title):
        padding = (terminal_width - len(title)) // 2
        return "\n" + "=" * padding + " " + title + " " + "=" * padding
    
    # Helper function to create a section separator
    def create_separator(char="-"):
        return char * terminal_width
    
    # Calculate max column widths
    max_bucket_name_width = max(
        [len(bucket['BucketName']) for bucket in bucket_details] + [15]
    ) if bucket_details else 15
    
    # Create report header
    output = []
    output.append(create_separator("="))
    output.append("AWS S3 BUCKETS MULTI-ACCOUNT ANALYSIS REPORT".center(terminal_width))
    output.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(terminal_width))
    output.append(create_separator("="))
    
    # Account summaries
    output.append(create_header("ACCOUNT SUMMARIES"))
    
    total_accounts = len(account_summaries)
    successful_accounts = len([acc for acc in account_summaries if 'account_error' not in acc])
    
    output.append(f"Total Accounts Analyzed: {total_accounts}")
    output.append(f"Successful Account Analyses: {successful_accounts}")
    if total_accounts != successful_accounts:
        output.append(f"Failed Account Analyses: {total_accounts - successful_accounts}")
    
    output.append(f"\nPer-Account Summary:")
    for acc in account_summaries:
        if 'account_error' in acc:
            output.append(f"  [ERROR] {acc['profile_name']} ({acc['account_id']}): {acc['account_error']}")
        else:
            output.append(f"  [OK] {acc['profile_name']} ({acc['account_id']}): {acc['bucket_count']} buckets analyzed")
    
    # Overall summary
    output.append(create_header("OVERALL SUMMARY"))
    
    # Calculate totals across all accounts
    total_size = sum(bucket['Size'] for bucket in bucket_details)
    total_objects = sum(bucket['ObjectCount'] for bucket in bucket_details)
    
    output.append(f"Total S3 Buckets Across All Accounts: {total_buckets}")
    output.append(f"Successfully Analyzed Buckets: {len(bucket_details)}")
    output.append(f"Total Storage Used: {format_size(total_size)}")
    output.append(f"Total Objects: {total_objects:,}")
    
    # Categorize buckets across all accounts
    empty_buckets = [b for b in bucket_details if b['IsEmpty']]
    large_buckets = [b for b in bucket_details if b['Size'] > 1024*1024*1024]  # > 1GB
    unencrypted_buckets = [b for b in bucket_details if not b['EncryptionEnabled']]
    public_buckets = [b for b in bucket_details if not b['PublicAccessBlocked']]
    no_lifecycle_buckets = [b for b in bucket_details if not b['HasLifecycle'] and not b['IsEmpty']]
    
    output.append(f"\nCross-Account Bucket Categories:")
    output.append(f"  - Empty Buckets: {len(empty_buckets)}")
    output.append(f"  - Large Buckets (>1GB): {len(large_buckets)}")
    output.append(f"  - Unencrypted Buckets: {len(unencrypted_buckets)}")
    output.append(f"  - Buckets without Public Access Block: {len(public_buckets)}")
    output.append(f"  - Buckets without Lifecycle Policies: {len(no_lifecycle_buckets)}")
    
    # Regional and account distribution
    region_distribution = {}
    account_distribution = {}
    
    for bucket in bucket_details:
        region = bucket['Region']
        account = f"{bucket['ProfileName']} ({bucket['AccountId']})"
        
        region_distribution[region] = region_distribution.get(region, 0) + 1
        account_distribution[account] = account_distribution.get(account, 0) + 1
    
    output.append(f"\nRegional Distribution:")
    for region, count in sorted(region_distribution.items(), key=lambda x: x[1], reverse=True):
        output.append(f"  - {region}: {count} buckets")
    
    output.append(f"\nAccount Distribution:")
    for account, count in sorted(account_distribution.items(), key=lambda x: x[1], reverse=True):
        output.append(f"  - {account}: {count} buckets")
    
    # Security issues across accounts
    if unencrypted_buckets or public_buckets:
        output.append(create_header("CROSS-ACCOUNT SECURITY ISSUES"))
        
        if unencrypted_buckets:
            output.append(f"Unencrypted buckets ({len(unencrypted_buckets)}):")
            # Group by account
            unencrypted_by_account = {}
            for bucket in unencrypted_buckets:
                account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
                if account_key not in unencrypted_by_account:
                    unencrypted_by_account[account_key] = []
                unencrypted_by_account[account_key].append(bucket)
            
            for account, buckets in unencrypted_by_account.items():
                output.append(f"  {account}: {len(buckets)} unencrypted buckets")
                for bucket in buckets[:3]:  # Show first 3
                    output.append(f"    - {bucket['BucketName']} ({bucket['SizeFormatted']})")
                if len(buckets) > 3:
                    output.append(f"    ... and {len(buckets) - 3} more")
        
        if public_buckets:
            output.append(f"\nBuckets without public access block ({len(public_buckets)}):")
            # Group by account
            public_by_account = {}
            for bucket in public_buckets:
                account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
                if account_key not in public_by_account:
                    public_by_account[account_key] = []
                public_by_account[account_key].append(bucket)
            
            for account, buckets in public_by_account.items():
                output.append(f"  {account}: {len(buckets)} buckets without public access block")
                for bucket in buckets[:3]:  # Show first 3
                    output.append(f"    - {bucket['BucketName']} ({bucket['SizeFormatted']})")
                if len(buckets) > 3:
                    output.append(f"    ... and {len(buckets) - 3} more")
    
    # Top buckets by size across all accounts
    output.append(create_header("TOP 10 LARGEST BUCKETS (CROSS-ACCOUNT)"))
    
    if bucket_details:
        sorted_buckets = sorted(bucket_details, key=lambda x: x['Size'], reverse=True)[:10]
        
        header_format = f"{{:<{min(max_bucket_name_width, 30)}}} | {{:<15}} | {{:<12}} | {{:<15}} | {{:<25}} | {{:<15}}"
        output.append(header_format.format("Bucket Name", "Size", "Objects", "Region", "Account", "Last Modified"))
        output.append(create_separator("-"))
        
        for bucket in sorted_buckets:
            last_modified_str = bucket['LastModified'].strftime("%Y-%m-%d") if bucket['LastModified'] else "Never"
            account_display = f"{bucket['ProfileName']} ({bucket['AccountId'][:8]}...)"
            
            row = header_format.format(
                bucket['BucketName'][:29] + "..." if len(bucket['BucketName']) > 30 else bucket['BucketName'],
                bucket['SizeFormatted'],
                f"{bucket['ObjectCount']:,}",
                bucket['Region'],
                account_display[:24],
                last_modified_str
            )
            output.append(row)
    
    # Error summary
    if error_buckets:
        output.append(create_header("BUCKETS WITH ERRORS"))
        output.append(f"Found {len(error_buckets)} buckets that could not be fully analyzed\n")
        
        # Group errors by account
        errors_by_account = {}
        for bucket in error_buckets:
            account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
            if account_key not in errors_by_account:
                errors_by_account[account_key] = []
            errors_by_account[account_key].append(bucket)
        
        for account, buckets in errors_by_account.items():
            output.append(f"  {account}: {len(buckets)} buckets with errors")
    
    # Multi-account recommendations
    output.append(create_separator("="))
    output.append("MULTI-ACCOUNT RECOMMENDATIONS".center(terminal_width))
    output.append(create_separator("="))
    
    recommendations = []
    
    if empty_buckets:
        empty_by_account = {}
        for bucket in empty_buckets:
            account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
            empty_by_account[account_key] = empty_by_account.get(account_key, 0) + 1
        
        recommendations.append(f"1. Empty Buckets Cleanup:")
        recommendations.append(f"   - Total empty buckets across all accounts: {len(empty_buckets)}")
        for account, count in sorted(empty_by_account.items(), key=lambda x: x[1], reverse=True):
            recommendations.append(f"   - {account}: {count} empty buckets")
    
    if unencrypted_buckets:
        unenc_by_account = {}
        for bucket in unencrypted_buckets:
            account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
            unenc_by_account[account_key] = unenc_by_account.get(account_key, 0) + 1
        
        recommendations.append(f"\n{len(recommendations) + 1}. Encryption Security Issues:")
        recommendations.append(f"   - Total unencrypted buckets: {len(unencrypted_buckets)}")
        for account, count in sorted(unenc_by_account.items(), key=lambda x: x[1], reverse=True):
            recommendations.append(f"   - {account}: {count} unencrypted buckets")
    
    if public_buckets:
        pub_by_account = {}
        for bucket in public_buckets:
            account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
            pub_by_account[account_key] = pub_by_account.get(account_key, 0) + 1
        
        recommendations.append(f"\n{len(recommendations) + 1}. Public Access Security Issues:")
        recommendations.append(f"   - Total buckets without public access block: {len(public_buckets)}")
        for account, count in sorted(pub_by_account.items(), key=lambda x: x[1], reverse=True):
            recommendations.append(f"   - {account}: {count} buckets")
    
    if no_lifecycle_buckets:
        lifecycle_by_account = {}
        for bucket in no_lifecycle_buckets:
            account_key = f"{bucket['ProfileName']} ({bucket['AccountId']})"
            lifecycle_by_account[account_key] = lifecycle_by_account.get(account_key, 0) + 1
        
        recommendations.append(f"\n{len(recommendations) + 1}. Cost Optimization - Lifecycle Policies:")
        recommendations.append(f"   - Total buckets without lifecycle policies: {len(no_lifecycle_buckets)}")
        for account, count in sorted(lifecycle_by_account.items(), key=lambda x: x[1], reverse=True)[:5]:
            recommendations.append(f"   - {account}: {count} buckets")
    
    # Add organizational recommendations
    recommendations.extend([
        f"\n{len(recommendations) + 1}. Organizational Governance:",
        "   - Implement AWS Organizations SCPs for S3 security standards",
        "   - Use AWS Config rules for multi-account S3 compliance monitoring",
        "   - Consider S3 Storage Lens organization-level view for cost optimization",
        
        f"\n{len(recommendations) + 2}. Cross-Account Best Practices:",
        "   - Standardize S3 bucket naming conventions across accounts",
        "   - Implement consistent tagging strategy for cost allocation",
        "   - Use AWS Control Tower for centralized S3 governance",
        
        f"\n{len(recommendations) + 3}. Monitoring and Alerting:",
        "   - Set up CloudWatch cross-account dashboards for S3 metrics",
        "   - Implement AWS CloudTrail organization trail for S3 API monitoring",
        "   - Configure AWS Cost Anomaly Detection for S3 cost spikes"
    ])
    
    for rec in recommendations:
        output.append(rec)
    
    output.append("\n" + create_separator("="))
    
    # Print the report
    print("\n".join(output))
    
    return output

def save_text_report(results, timestamp):
    """Save results to text file"""
    text_filename = f"s3_buckets_multi_account_report_{timestamp}.txt"
    
    # Generate the report
    report_lines = display_multi_account_analysis(results, timestamp)
    
    # Save text report
    try:
        with open(text_filename, 'w', encoding='utf-8') as text_file:
            text_file.write("\n".join(report_lines))
        return text_filename
    except Exception as e:
        print(f"Error creating text file: {e}")
        return None

def main():
    try:
        print("\n" + "="*80)
        print("AWS S3 BUCKETS MULTI-ACCOUNT ANALYZER".center(80))
        print("="*80)
        print("\nThis script provides comprehensive S3 bucket analysis across multiple AWS accounts:")
        print("  1. Multi-account bucket inventory with sizes and object counts")
        print("  2. Cross-account security analysis (encryption, public access)")
        print("  3. Organization-wide cost optimization opportunities")
        print("  4. Regional distribution and lifecycle policies")
        print("  5. Cross-account governance recommendations")
        
        # Get AWS profiles and account information
        validated_accounts = get_profile_and_account_info()
        
        # Get output preferences
        generate_text, generate_csv = get_output_preferences()
        
        print(f"\nAnalyzing S3 buckets across {len(validated_accounts)} account(s)...")
        print("This may take several minutes depending on the number of accounts and buckets...")
        
        # Analyze each account
        account_results = []
        for account_info in validated_accounts:
            try:
                result = get_s3_buckets_for_account(account_info)
                account_results.append(result)
            except Exception as e:
                print(f"Failed to analyze account {account_info['account_id']}: {e}")
                # Add error result
                account_results.append({
                    'bucket_details': [],
                    'error_buckets': [],
                    'total_buckets': 0,
                    'account_id': account_info['account_id'],
                    'profile_name': account_info['profile'],
                    'account_error': str(e)
                })
        
        # Consolidate results from all accounts
        consolidated_results = consolidate_results(account_results)
        
        # Generate timestamp for file naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        files_created = []
        
        # Generate text report if requested
        if generate_text:
            text_file = save_text_report(consolidated_results, timestamp)
            if text_file:
                files_created.append(f"Text report: {text_file}")
        
        # Generate CSV report if requested  
        if generate_csv:
            csv_file = save_csv_report(consolidated_results, timestamp)
            if csv_file:
                files_created.append(f"CSV export: {csv_file}")
        
        # Display summary
        print(f"\n" + "="*80)
        print("ANALYSIS COMPLETE".center(80))
        print("="*80)
        
        print(f"\nSummary:")
        print(f"  - Accounts analyzed: {len(validated_accounts)}")
        print(f"  - Total buckets found: {consolidated_results['total_buckets']}")
        print(f"  - Successfully analyzed: {len(consolidated_results['bucket_details'])}")
        
        if consolidated_results['error_buckets']:
            print(f"  - Buckets with errors: {len(consolidated_results['error_buckets'])}")
        
        # Display what was created
        if files_created:
            print(f"\nFiles created:")
            for file_info in files_created:
                print(f"  - {file_info}")
        
        print(f"\nFor detailed analysis, review the generated report(s).")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

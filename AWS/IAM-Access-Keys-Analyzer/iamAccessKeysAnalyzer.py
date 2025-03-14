#!/usr/bin/env python3
import boto3
import botocore.session
import sys
import time
from datetime import datetime, timezone, timedelta

# Default threshold - 200 days
DAYS_THRESHOLD = 200

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

def get_all_users_with_access_keys(session, days_threshold):
    """Get all users with their access keys and detailed information"""
    iam = session.client('iam')
    
    print("Retrieving all IAM users and access keys... (this may take a while)")
    
    try:
        # Get all users
        users = []
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        print(f"Found {len(users)} IAM users")
        
        # Initialize data structures
        old_unused_keys = []
        old_used_keys = []
        today = datetime.now(timezone.utc)
        
        # Process each user to find their access keys
        for i, user in enumerate(users):
            if i > 0 and i % 10 == 0:
                print(f"Processed {i}/{len(users)} users...")
                
            username = user['UserName']
            
            try:
                # Get access keys for the user
                keys_response = iam.list_access_keys(UserName=username)
                access_keys = keys_response.get('AccessKeyMetadata', [])
                
                # Check each access key
                for key in access_keys:
                    access_key_id = key['AccessKeyId']
                    key_status = key['Status']
                    key_created_date = key['CreateDate']
                    
                    # Calculate age
                    key_age_days = (today - key_created_date).days
                    
                    # Only process keys older than threshold
                    if key_age_days > days_threshold:
                        # Get key last usage
                        last_used_response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
                        last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                        last_used_date = last_used_info.get('LastUsedDate')
                        
                        if not last_used_date:  # Never used
                            old_unused_keys.append({
                                'Username': username,
                                'AccessKeyId': access_key_id,
                                'Created': key_created_date,
                                'AgeInDays': key_age_days,
                                'Status': key_status
                            })
                        else:  # Used but check if used recently
                            days_since_last_use = (today - last_used_date).days
                            if days_since_last_use > days_threshold:
                                old_used_keys.append({
                                    'Username': username,
                                    'AccessKeyId': access_key_id,
                                    'Created': key_created_date,
                                    'AgeInDays': key_age_days,
                                    'LastUsed': last_used_date,
                                    'DaysSinceLastUse': days_since_last_use,
                                    'LastUsedService': last_used_info.get('ServiceName', 'N/A'),
                                    'LastUsedRegion': last_used_info.get('Region', 'N/A'),
                                    'Status': key_status
                                })
                
            except Exception as e:
                print(f"Warning: Error processing user {username}: {e}")
                continue
        
        print(f"Successfully processed all {len(users)} users")
        
        return {
            'old_unused_keys': old_unused_keys,
            'old_used_keys': old_used_keys
        }
    
    except Exception as e:
        print(f"Error retrieving users and access keys: {e}")
        sys.exit(1)

def display_key_analysis(results, days_threshold, account_id):
    """Display a formatted report of the access key analysis with improved readability"""
    old_unused_keys = results['old_unused_keys']
    old_used_keys = results['old_used_keys']
    
    # Terminal width for better formatting
    terminal_width = 140  # Increased to accommodate full text
    
    # Helper function to create a formatted header
    def create_header(title):
        padding = (terminal_width - len(title)) // 2
        return "\n" + "=" * padding + " " + title + " " + "=" * padding
    
    # Helper function to create a section separator
    def create_separator(char="-"):
        return char * terminal_width
    
    # Calculate max column widths based on actual data
    max_username_width = max(
        [len(key['Username']) for key in old_unused_keys + old_used_keys] + [10]
    )
    max_service_region_width = 10
    for key in old_used_keys:
        service = key.get('LastUsedService', 'N/A')
        region = key.get('LastUsedRegion', 'N/A')
        service_region = f"{service}/{region}"
        max_service_region_width = max(max_service_region_width, len(service_region))
    
    # Create report header
    output = []
    output.append(create_separator("="))
    output.append("AWS ACCESS KEY ANALYSIS REPORT".center(terminal_width))
    output.append(f"Account ID: {account_id}".center(terminal_width))
    output.append(f"Age Threshold: {days_threshold} days".center(terminal_width))
    output.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(terminal_width))
    output.append(create_separator("="))
    
    # Unused old keys section
    output.append(create_header("OLD UNUSED KEYS"))
    output.append(f"Found {len(old_unused_keys)} access keys older than {days_threshold} days that have never been used\n")
    
    if old_unused_keys:
        # Format the table header - now with dynamic width for username
        header_format = f"{{:<{max_username_width}}} | {{:<26}} | {{:<20}} | {{:<12}} | {{:<10}}"
        output.append(header_format.format("Username", "Access Key ID", "Creation Date", "Age (days)", "Status"))
        output.append(create_separator("-"))
        
        # Sort by age (oldest first)
        sorted_keys = sorted(old_unused_keys, key=lambda x: x['AgeInDays'], reverse=True)
        
        # Add each row with formatted data - no text truncation
        for key in sorted_keys:
            row = header_format.format(
                key['Username'],
                key['AccessKeyId'],
                key['Created'].strftime("%Y-%m-%d %H:%M:%S"),
                key['AgeInDays'],
                key['Status']
            )
            output.append(row)
    else:
        output.append("No old unused keys found.")
    
    # Old used keys section
    output.append(create_header("OLD USED KEYS"))
    output.append(f"Found {len(old_used_keys)} access keys not used in the last {days_threshold} days\n")
    
    if old_used_keys:
        # Format the table header with more columns - dynamic widths
        header_format = f"{{:<{max_username_width}}} | {{:<26}} | {{:<20}} | {{:<{max_service_region_width}}} | {{:<10}} | {{:<10}} | {{:<8}}"
        output.append(header_format.format(
            "Username", "Access Key ID", "Last Used Date", "Service/Region", "Age (days)", "Days Since", "Status"
        ))
        output.append(create_separator("-"))
        
        # Sort by days since last use (longest first)
        sorted_keys = sorted(old_used_keys, key=lambda x: x['DaysSinceLastUse'], reverse=True)
        
        # Add each row with formatted data - no text truncation
        for key in sorted_keys:
            service_region = f"{key['LastUsedService']}/{key['LastUsedRegion']}"
            row = header_format.format(
                key['Username'],
                key['AccessKeyId'], 
                key['LastUsed'].strftime("%Y-%m-%d %H:%M:%S"),
                service_region,
                key['AgeInDays'],
                key['DaysSinceLastUse'],
                key['Status']
            )
            output.append(row)
    else:
        output.append("No old used keys found.")
    
    # Summary and recommendations
    total_issues = len(old_unused_keys) + len(old_used_keys)
    output.append(create_separator("="))
    output.append("SUMMARY AND RECOMMENDATIONS".center(terminal_width))
    output.append(create_separator("="))
    
    if total_issues > 0:
        output.append(f"\nFound a total of {total_issues} access keys that require attention:")
        output.append(f"  - {len(old_unused_keys)} keys older than {days_threshold} days that have never been used")
        output.append(f"  - {len(old_used_keys)} keys not used in the last {days_threshold} days")
        
        output.append("\nRecommended actions:")
        output.append("  1. Delete unused keys that are no longer needed")
        output.append("  2. Rotate active keys that are older than 90 days")
        output.append("  3. Set up AWS Config rule 'iam-user-unused-credentials-check'")
        output.append("  4. Implement automated key rotation")
    else:
        output.append(f"\nNo access keys older than {days_threshold} days requiring attention were found.")
        output.append("\nBest practices:")
        output.append("  1. Continue to rotate keys regularly (at least every 90 days)")
        output.append("  2. Use IAM roles instead of access keys where possible")
        output.append("  3. Monitor access key usage with CloudTrail and CloudWatch")
    
    output.append("\n" + create_separator("="))
    
    # Print the report
    print("\n".join(output))
    
    # Return the output lines for file writing
    return output

def save_results_to_file(results, account_id, profile_name, days_threshold):
    """Save results to text file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    text_filename = f"access_keys_report_{account_id}_{timestamp}.txt"
    
    # Generate the report
    report_lines = display_key_analysis(results, days_threshold, account_id)
    
    # Save text report
    with open(text_filename, 'w') as text_file:
        text_file.write("\n".join(report_lines))
    
    return text_filename

def main():
    try:
        print("\n" + "="*80)
        print("AWS ACCESS KEY ANALYZER".center(80))
        print("="*80)
        print("\nThis script identifies:")
        print("  1. AWS access keys that are older than the threshold and never used")
        print("  2. AWS access keys that were last used more than the threshold days ago")
        
        # Get AWS profile and account ID
        session, account_id, profile_name = get_profile_and_account_info()
        
        # Allow custom threshold
        threshold_input = input(f"\nEnter age threshold in days (or press Enter for default {DAYS_THRESHOLD}): ")
        if threshold_input and threshold_input.isdigit():
            days_threshold = int(threshold_input)
        else:
            days_threshold = DAYS_THRESHOLD
        
        print(f"\nFetching and analyzing access keys older than {days_threshold} days...")
        
        # Get all users and their access keys directly
        results = get_all_users_with_access_keys(session, days_threshold)
        
        # Display the results without the display_key_analysis call here
        # because we'll call it in save_results_to_file
        
        # Save results to text file
        text_file = save_results_to_file(results, account_id, profile_name, days_threshold)
        
        print(f"\nDetailed text report saved to: {text_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AWS IAM Users and Roles Analyzer
Enhanced version with comprehensive analysis, policy detection, and multiple export formats
"""

import boto3
import botocore.session
import sys
import time
import csv
import os
import logging
import concurrent.futures
from threading import Lock
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

# Default configuration
DEFAULT_CONFIG = {
    'days_threshold': 200,
    'max_workers': 5,
    'retry_attempts': 3,
    'output_formats': ['txt', 'csv'],
    'exclude_patterns': [],
    'check_mfa': True,
    'analyze_policies': True,
    'dry_run': False
}

class IAMAnalyzer:
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG.copy()
        self.setup_logging()
        self.results_lock = Lock()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('iam_analyzer.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def get_user_configuration(self):
        """Prompt user for configuration options"""
        print("\n" + "="*60)
        print("CONFIGURATION OPTIONS".center(60))
        print("="*60)
        
        # Inactivity threshold
        threshold_input = input(f"Enter inactivity threshold in days (default {self.config['days_threshold']}): ")
        if threshold_input and threshold_input.isdigit():
            self.config['days_threshold'] = int(threshold_input)
        
        # Max workers
        workers_input = input(f"Enter max worker threads for parallel processing (default {self.config['max_workers']}): ")
        if workers_input and workers_input.isdigit() and int(workers_input) > 0:
            self.config['max_workers'] = int(workers_input)
        
        # Analyze policies
        policies_input = input("Analyze attached policies? (y/n, default y): ").lower()
        if policies_input in ['n', 'no']:
            self.config['analyze_policies'] = False
        
        # Output formats
        print("\nOutput format options:")
        print("1. Text report only")
        print("2. CSV files only") 
        print("3. Both text and CSV (default)")
        format_choice = input("Choose output format (1-3, default 3): ")
        
        if format_choice == '1':
            self.config['output_formats'] = ['txt']
        elif format_choice == '2':
            self.config['output_formats'] = ['csv']
        else:
            self.config['output_formats'] = ['txt', 'csv']
        
        # Exclude patterns
        exclude_input = input("Enter exclude patterns for usernames/roles (comma-separated, optional): ")
        if exclude_input:
            self.config['exclude_patterns'] = [p.strip() for p in exclude_input.split(',')]
        
        # Dry run
        dry_run_input = input("Dry run mode (skip confirmations)? (y/n, default n): ").lower()
        if dry_run_input in ['y', 'yes']:
            self.config['dry_run'] = True
        
        print(f"\nConfiguration Summary:")
        print(f"  - Inactivity threshold: {self.config['days_threshold']} days")
        print(f"  - Max worker threads: {self.config['max_workers']}")
        print(f"  - Check MFA status: {self.config['check_mfa']} (always enabled)")
        print(f"  - Analyze policies: {self.config['analyze_policies']}")
        print(f"  - Output formats: {', '.join(self.config['output_formats'])}")
        print(f"  - Exclude patterns: {self.config['exclude_patterns']}")
        print(f"  - Dry run mode: {self.config['dry_run']}")
    
    def make_api_call_with_retry(self, func, *args, **kwargs):
        """Make API calls with exponential backoff retry"""
        max_retries = self.config['retry_attempts']
        
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['Throttling', 'RequestLimitExceeded']:
                    wait_time = (2 ** attempt) + (time.time() % 1)
                    self.logger.warning(f"Rate limited, waiting {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                    continue
                else:
                    self.logger.error(f"API call failed: {e}")
                    raise
            except Exception as e:
                self.logger.error(f"Unexpected error in API call: {e}")
                if attempt == max_retries - 1:
                    raise
                time.sleep(1)
        
        raise Exception(f"Max retries ({max_retries}) exceeded")
    
    def get_profile_and_account_info(self):
        """Prompt for AWS profile and confirm account details"""
        session = botocore.session.Session()
        profiles = session.available_profiles
        
        if not profiles:
            self.logger.error("No AWS profiles found. Please configure AWS CLI first.")
            sys.exit(1)
        
        print("Available AWS profiles:")
        for i, profile in enumerate(profiles, 1):
            print(f"{i}. {profile}")
        
        # Profile selection logic
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
                self.logger.error(f"Error in profile selection: {e}")
        
        # Create session and validate
        try:
            session = boto3.Session(profile_name=profile_name)
            sts = session.client('sts')
            
            identity = self.make_api_call_with_retry(sts.get_caller_identity)
            account_id = identity['Account']
            iam_arn = identity['Arn']
            
            print("\nAWS Account Information:")
            print(f"Profile: {profile_name}")
            print(f"Account ID: {account_id}")
            print(f"IAM ARN: {iam_arn}")
            
            if not self.config['dry_run']:
                confirmation = input("\nIs this the correct account? (yes/no): ").lower()
                if confirmation not in ['y', 'yes']:
                    print("Aborting operation.")
                    sys.exit(0)
            
            return session, account_id, profile_name
            
        except Exception as e:
            self.logger.error(f"Error connecting to AWS with profile '{profile_name}': {e}")
            sys.exit(1)
    
    def check_required_permissions(self, iam):
        """Validate that we have the required IAM permissions"""
        required_actions = [
            'iam:ListUsers',
            'iam:ListRoles',
            'iam:ListAccessKeys',
            'iam:GetAccessKeyLastUsed',
            'iam:GetRole',
            'iam:ListMFADevices',
            'iam:ListAttachedUserPolicies',
            'iam:ListAttachedRolePolicies',
            'iam:ListUserPolicies',
            'iam:ListRolePolicies'
        ]
        
        try:
            # Try a simple list operation to check permissions
            self.make_api_call_with_retry(iam.list_users, MaxItems=1)
            self.logger.info("IAM permissions validated successfully")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.error("Insufficient IAM permissions. Required actions:")
                for action in required_actions:
                    self.logger.error(f"  - {action}")
                return False
            raise
    
    def analyze_policies(self, iam, username=None, role_name=None):
        """Analyze attached policies for users/roles"""
        policies = []
        risky_policies = []
        
        try:
            if username:
                # Get user policies
                attached = self.make_api_call_with_retry(
                    iam.list_attached_user_policies, UserName=username
                )
                inline = self.make_api_call_with_retry(
                    iam.list_user_policies, UserName=username
                )
                
                for policy in attached.get('AttachedPolicies', []):
                    policy['Type'] = 'Managed'
                    policies.append(policy)
                    # Check for risky policies
                    if any(keyword in policy['PolicyName'].lower() 
                           for keyword in ['admin', 'full', '*']):
                        risky_policies.append(policy['PolicyName'])
                
                for policy_name in inline.get('PolicyNames', []):
                    policy_info = {'PolicyName': policy_name, 'Type': 'Inline'}
                    policies.append(policy_info)
                    if any(keyword in policy_name.lower() 
                           for keyword in ['admin', 'full', '*']):
                        risky_policies.append(policy_name)
            
            elif role_name:
                # Get role policies
                attached = self.make_api_call_with_retry(
                    iam.list_attached_role_policies, RoleName=role_name
                )
                inline = self.make_api_call_with_retry(
                    iam.list_role_policies, RoleName=role_name
                )
                
                for policy in attached.get('AttachedPolicies', []):
                    policy['Type'] = 'Managed'
                    policies.append(policy)
                    if any(keyword in policy['PolicyName'].lower() 
                           for keyword in ['admin', 'full', '*']):
                        risky_policies.append(policy['PolicyName'])
                
                for policy_name in inline.get('PolicyNames', []):
                    policy_info = {'PolicyName': policy_name, 'Type': 'Inline'}
                    policies.append(policy_info)
                    if any(keyword in policy_name.lower() 
                           for keyword in ['admin', 'full', '*']):
                        risky_policies.append(policy_name)
        
        except Exception as e:
            self.logger.warning(f"Error analyzing policies: {e}")
        
        return policies, risky_policies
    
    def check_mfa_status(self, iam, username):
        """Check MFA status for a user"""
        try:
            mfa_devices = self.make_api_call_with_retry(
                iam.list_mfa_devices, UserName=username
            )
            return len(mfa_devices.get('MFADevices', [])) > 0
        except Exception as e:
            self.logger.warning(f"Error checking MFA for user {username}: {e}")
            return None
    
    def filter_by_tags(self, iam, resource_name, resource_type='user'):
        """Check resource tags for exclusion patterns"""
        try:
            if resource_type == 'user':
                tags_response = self.make_api_call_with_retry(
                    iam.list_user_tags, UserName=resource_name
                )
            else:
                tags_response = self.make_api_call_with_retry(
                    iam.list_role_tags, RoleName=resource_name
                )
            
            tag_dict = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
            
            # Skip if marked as system/service account
            if tag_dict.get('Type', '').lower() in ['system', 'service', 'automation']:
                return True
            
            # Check against exclude patterns
            for pattern in self.config['exclude_patterns']:
                if pattern and pattern.lower() in resource_name.lower():
                    return True
            
            return False
        except:
            return False
    
    def analyze_single_user(self, iam, user, days_threshold, today):
        """Analyze a single user"""
        username = user['UserName']
        user_created_date = user['CreateDate']
        user_age_days = (today - user_created_date).days
        
        # Skip if filtered
        if self.filter_by_tags(iam, username, 'user'):
            return None
        
        try:
            # Get user's password last used
            password_last_used = user.get('PasswordLastUsed')
            
            # Get user's access keys
            keys_response = self.make_api_call_with_retry(
                iam.list_access_keys, UserName=username
            )
            access_keys = keys_response.get('AccessKeyMetadata', [])
            
            # Check access key last usage
            latest_key_usage = None
            for key in access_keys:
                if key['Status'] == 'Active':
                    try:
                        last_used_response = self.make_api_call_with_retry(
                            iam.get_access_key_last_used, AccessKeyId=key['AccessKeyId']
                        )
                        last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                        key_last_used = last_used_info.get('LastUsedDate')
                        
                        if key_last_used and (not latest_key_usage or key_last_used > latest_key_usage):
                            latest_key_usage = key_last_used
                    except Exception:
                        continue
            
            # Determine last activity
            last_activity = None
            activity_type = "Never"
            
            if password_last_used:
                last_activity = password_last_used
                activity_type = "Console"
            
            if latest_key_usage:
                if not last_activity or latest_key_usage > last_activity:
                    last_activity = latest_key_usage
                    activity_type = "Access Key"
            
            # Calculate days since last activity
            days_since_activity = None
            if last_activity:
                days_since_activity = (today - last_activity).days
            
            # Always check MFA status
            mfa_enabled = self.check_mfa_status(iam, username)
            
            # Additional analysis
            policies = []
            risky_policies = []
            
            if self.config['analyze_policies']:
                policies, risky_policies = self.analyze_policies(iam, username=username)
            
            user_data = {
                'Username': username,
                'Created': user_created_date,
                'AgeInDays': user_age_days,
                'LastActivity': last_activity,
                'ActivityType': activity_type,
                'DaysSinceActivity': days_since_activity,
                'AccessKeys': len(access_keys),
                'ActiveAccessKeys': len([k for k in access_keys if k['Status'] == 'Active']),
                'MFAEnabled': mfa_enabled,
                'Policies': policies,
                'RiskyPolicies': risky_policies,
                'PolicyCount': len(policies),
                'is_inactive': not last_activity or days_since_activity > days_threshold
            }
            
            return user_data
            
        except Exception as e:
            self.logger.warning(f"Error processing user {username}: {e}")
            return None
    
    def analyze_single_role(self, iam, role, days_threshold, today):
        """Analyze a single role"""
        role_name = role['RoleName']
        role_created_date = role['CreateDate']
        role_age_days = (today - role_created_date).days
        role_path = role['Path']
        
        # Check if it's a service-linked role
        is_service_linked = (role_path.startswith('/service-role/') or 
                           role_path.startswith('/aws-service-role/'))
        
        # Skip if filtered
        if self.filter_by_tags(iam, role_name, 'role'):
            return None
        
        try:
            # Get role details including last used info
            role_details = self.make_api_call_with_retry(iam.get_role, RoleName=role_name)
            role_info = role_details['Role']
            
            # Get role last used info
            role_last_used_info = role_info.get('RoleLastUsed', {})
            last_used_date = role_last_used_info.get('LastUsedDate')
            last_used_region = role_last_used_info.get('Region', 'N/A')
            
            # Calculate days since last use
            days_since_use = None
            if last_used_date:
                days_since_use = (today - last_used_date).days
            
            # Additional analysis
            policies = []
            risky_policies = []
            
            if self.config['analyze_policies']:
                policies, risky_policies = self.analyze_policies(iam, role_name=role_name)
            
            role_data = {
                'RoleName': role_name,
                'Created': role_created_date,
                'AgeInDays': role_age_days,
                'LastUsed': last_used_date,
                'DaysSinceUse': days_since_use,
                'LastUsedRegion': last_used_region,
                'Path': role_path,
                'IsServiceLinked': is_service_linked,
                'Policies': policies,
                'RiskyPolicies': risky_policies,
                'PolicyCount': len(policies),
                'is_inactive': (not is_service_linked and 
                              (not last_used_date or days_since_use > days_threshold))
            }
            
            return role_data
            
        except Exception as e:
            self.logger.warning(f"Error processing role {role_name}: {e}")
            return None
    
    def get_all_users_and_roles(self, session, days_threshold):
        """Get all users and roles with their detailed information using parallel processing"""
        iam = session.client('iam')
        
        # Check permissions
        if not self.check_required_permissions(iam):
            sys.exit(1)
        
        self.logger.info("Retrieving all IAM users and roles...")
        
        try:
            # Get all users
            users = []
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            self.logger.info(f"Found {len(users)} IAM users")
            
            # Get all roles
            roles = []
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend(page['Roles'])
            
            self.logger.info(f"Found {len(roles)} IAM roles")
            
            # Initialize data structures
            inactive_users = []
            inactive_roles = []
            active_users = []
            active_roles = []
            today = datetime.now(timezone.utc)
            
            # Process users in parallel
            self.logger.info("Processing users...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                user_futures = {
                    executor.submit(self.analyze_single_user, iam, user, days_threshold, today): user 
                    for user in users
                }
                
                for i, future in enumerate(concurrent.futures.as_completed(user_futures)):
                    if i > 0 and i % 10 == 0:
                        self.logger.info(f"Processed {i}/{len(users)} users...")
                    
                    user_data = future.result()
                    if user_data:
                        if user_data['is_inactive']:
                            inactive_users.append(user_data)
                        else:
                            active_users.append(user_data)
            
            # Process roles in parallel
            self.logger.info("Processing roles...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
                role_futures = {
                    executor.submit(self.analyze_single_role, iam, role, days_threshold, today): role 
                    for role in roles
                }
                
                for i, future in enumerate(concurrent.futures.as_completed(role_futures)):
                    if i > 0 and i % 10 == 0:
                        self.logger.info(f"Processed {i}/{len(roles)} roles...")
                    
                    role_data = future.result()
                    if role_data:
                        if role_data['is_inactive']:
                            inactive_roles.append(role_data)
                        else:
                            active_roles.append(role_data)
            
            self.logger.info(f"Successfully processed all {len(users)} users and {len(roles)} roles")
            
            return {
                'inactive_users': inactive_users,
                'inactive_roles': inactive_roles,
                'active_users': active_users,
                'active_roles': active_roles,
                'total_users': len(users),
                'total_roles': len(roles)
            }
        
        except Exception as e:
            self.logger.error(f"Error retrieving users and roles: {e}")
            sys.exit(1)
    
    def display_iam_analysis(self, results, days_threshold, account_id):
        """Display a formatted report of the IAM analysis with improved readability"""
        inactive_users = results['inactive_users']
        inactive_roles = results['inactive_roles']
        active_users = results['active_users']
        active_roles = results['active_roles']
        total_users = results['total_users']
        total_roles = results['total_roles']
        
        # Terminal width for better formatting
        terminal_width = 160
        
        # Helper functions
        def create_header(title):
            padding = (terminal_width - len(title)) // 2
            return "\n" + "=" * padding + " " + title + " " + "=" * padding
        
        def create_separator(char="-"):
            return char * terminal_width
        
        # Calculate max column widths
        max_username_width = max(
            [len(user['Username']) for user in inactive_users + active_users] + [15]
        ) if (inactive_users or active_users) else 15
        
        max_rolename_width = max(
            [len(role['RoleName']) for role in inactive_roles + active_roles] + [15]
        ) if (inactive_roles or active_roles) else 15
        
        # Create report
        output = []
        output.append(create_separator("="))
        output.append("AWS IAM USERS AND ROLES ANALYSIS REPORT".center(terminal_width))
        output.append(f"Account ID: {account_id}".center(terminal_width))
        output.append(f"Inactivity Threshold: {days_threshold} days".center(terminal_width))
        output.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(terminal_width))
        output.append(create_separator("="))
        
        # Summary section
        output.append(create_header("SUMMARY"))
        output.append(f"Total IAM Users: {total_users}")
        output.append(f"  - Active Users (used within {days_threshold} days): {len(active_users)}")
        output.append(f"  - Inactive Users: {len(inactive_users)}")
        output.append(f"\nTotal IAM Roles: {total_roles}")
        output.append(f"  - Active Roles (used within {days_threshold} days): {len(active_roles)}")
        output.append(f"  - Inactive Roles (excluding service-linked): {len(inactive_roles)}")
        
        # Security summary
        users_without_mfa = len([u for u in inactive_users + active_users if u.get('MFAEnabled') == False])
        users_with_risky_policies = len([u for u in inactive_users + active_users if u.get('RiskyPolicies')])
        roles_with_risky_policies = len([r for r in inactive_roles + active_roles if r.get('RiskyPolicies')])
        
        output.append(f"\nSecurity Summary:")
        output.append(f"  - Users without MFA: {users_without_mfa}")
        output.append(f"  - Users with risky policies: {users_with_risky_policies}")
        output.append(f"  - Roles with risky policies: {roles_with_risky_policies}")
        
        # Inactive users section
        output.append(create_header("INACTIVE USERS"))
        output.append(f"Found {len(inactive_users)} users with no activity in the last {days_threshold} days\n")
        
        if inactive_users:
            # Sort by days since activity (longest first)
            sorted_users = sorted(inactive_users, key=lambda x: x['DaysSinceActivity'] if x['DaysSinceActivity'] else 99999, reverse=True)
            
            for user in sorted_users:
                output.append(f"Username: {user['Username']}")
                output.append(f"  Created: {user['Created'].strftime('%Y-%m-%d %H:%M:%S')}")
                output.append(f"  Age: {user['AgeInDays']} days")
                output.append(f"  Last Activity: {user['LastActivity'].strftime('%Y-%m-%d %H:%M:%S') if user['LastActivity'] else 'Never'}")
                output.append(f"  Activity Type: {user['ActivityType']}")
                output.append(f"  Days Since Activity: {user['DaysSinceActivity'] if user['DaysSinceActivity'] else 'N/A'}")
                output.append(f"  Access Keys: {user['ActiveAccessKeys']}/{user['AccessKeys']} (Active/Total)")
                output.append(f"  MFA Enabled: {'Yes' if user.get('MFAEnabled') else 'No' if user.get('MFAEnabled') == False else 'N/A'}")
                
                if self.config['analyze_policies']:
                    output.append(f"  Policy Count: {user.get('PolicyCount', 0)}")
                    if user.get('Policies'):
                        output.append("  Attached Policies:")
                        for policy in user['Policies']:
                            output.append(f"    - {policy.get('PolicyName', 'Unknown')} ({policy.get('Type', 'Unknown')})")
                    if user.get('RiskyPolicies'):
                        output.append(f"  Risky Policies: {', '.join(user['RiskyPolicies'])}")
                    else:
                        output.append("  Risky Policies: None")
                
                output.append("")  # Empty line between users
        else:
            output.append("No inactive users found.")
        
        # Inactive roles section
        output.append(create_header("INACTIVE ROLES"))
        output.append(f"Found {len(inactive_roles)} roles with no activity in the last {days_threshold} days (excluding service-linked roles)\n")
        
        if inactive_roles:
            # Sort by days since use (longest first)
            sorted_roles = sorted(inactive_roles, key=lambda x: x['DaysSinceUse'] if x['DaysSinceUse'] else 99999, reverse=True)
            
            for role in sorted_roles:
                output.append(f"Role Name: {role['RoleName']}")
                output.append(f"  Created: {role['Created'].strftime('%Y-%m-%d %H:%M:%S')}")
                output.append(f"  Age: {role['AgeInDays']} days")
                output.append(f"  Last Used: {role['LastUsed'].strftime('%Y-%m-%d %H:%M:%S') if role['LastUsed'] else 'Never'}")
                output.append(f"  Days Since Use: {role['DaysSinceUse'] if role['DaysSinceUse'] else 'N/A'}")
                output.append(f"  Last Used Region: {role['LastUsedRegion']}")
                output.append(f"  Path: {role['Path']}")
                output.append(f"  Service Linked: {'Yes' if role['IsServiceLinked'] else 'No'}")
                
                if self.config['analyze_policies']:
                    output.append(f"  Policy Count: {role.get('PolicyCount', 0)}")
                    if role.get('Policies'):
                        output.append("  Attached Policies:")
                        for policy in role['Policies']:
                            output.append(f"    - {policy.get('PolicyName', 'Unknown')} ({policy.get('Type', 'Unknown')})")
                    if role.get('RiskyPolicies'):
                        output.append(f"  Risky Policies: {', '.join(role['RiskyPolicies'])}")
                    else:
                        output.append("  Risky Policies: None")
                
                output.append("")  # Empty line between roles
        else:
            output.append("No inactive roles found.")
        
        # Policy details section - show ALL entities with risky policies
        if self.config['analyze_policies']:
            output.append(create_header("POLICY ANALYSIS"))
            
            # High-risk users
            high_risk_users = [u for u in inactive_users + active_users if u.get('RiskyPolicies')]
            if high_risk_users:
                output.append("\nUsers with potentially risky policies:")
                for user in high_risk_users:
                    policies_str = ", ".join(user.get('RiskyPolicies', []))
                    status = "INACTIVE" if user in inactive_users else "Active"
                    output.append(f"  - {user['Username']} ({status}): {policies_str}")
            else:
                output.append("\nNo users found with risky policies.")
            
            # High-risk roles
            high_risk_roles = [r for r in inactive_roles + active_roles if r.get('RiskyPolicies')]
            if high_risk_roles:
                output.append("\nRoles with potentially risky policies:")
                for role in high_risk_roles:
                    policies_str = ", ".join(role.get('RiskyPolicies', []))
                    status = "INACTIVE" if role in inactive_roles else "Active"
                    output.append(f"  - {role['RoleName']} ({status}): {policies_str}")
            else:
                output.append("\nNo roles found with risky policies.")
        
        # Recommendations section
        total_inactive = len(inactive_users) + len(inactive_roles)
        output.append(create_separator("="))
        output.append("SUMMARY AND RECOMMENDATIONS".center(terminal_width))
        output.append(create_separator("="))
        
        if total_inactive > 0:
            output.append(f"\nFound a total of {total_inactive} inactive IAM entities requiring attention:")
            output.append(f"  - {len(inactive_users)} inactive users")
            output.append(f"  - {len(inactive_roles)} inactive roles")
            
            output.append("\nRecommended actions:")
            output.append("  1. Review inactive users and consider disabling or deleting unused accounts")
            output.append("  2. Review inactive roles and remove those no longer needed")
            output.append("  3. Enable MFA for all users without it")
            output.append("  4. Review users and roles with administrative policies")
            output.append("  5. For active entities, ensure they follow principle of least privilege")
            output.append("  6. Set up AWS Config rules for automated IAM compliance monitoring")
            output.append("  7. Implement regular IAM access reviews")
            
            output.append("\nSecurity considerations:")
            output.append("  - Inactive users with access keys pose security risks")
            output.append("  - Unused roles may have excessive permissions")
            output.append("  - Users without MFA are vulnerable to credential compromise")
            output.append("  - Consider using AWS Organizations SCPs for additional controls")
        else:
            output.append(f"\nNo IAM entities inactive for more than {days_threshold} days were found.")
            output.append("\nBest practices:")
            output.append("  1. Continue regular IAM access reviews")
            output.append("  2. Use IAM roles instead of users for applications")
            output.append("  3. Enable CloudTrail for IAM activity monitoring")
            output.append("  4. Implement automated access certification processes")
            output.append("  5. Enforce MFA for all users")
            output.append("  6. Regularly audit policy attachments")
        
        output.append("\n" + create_separator("="))
        
        # Print the report
        print("\n".join(output))
        
        # Return the output lines for file writing
        return output
    
    def export_to_csv(self, results, filename_base):
        """Export results to CSV format with all columns preserved"""
        files_created = []
        
        # Export users
        users_filename = f"{filename_base}_users.csv"
        with open(users_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Username', 'Created', 'AgeInDays', 'LastActivity', 
                'ActivityType', 'DaysSinceActivity', 'AccessKeys', 'ActiveAccessKeys',
                'MFAEnabled', 'PolicyCount', 'RiskyPolicies', 'AllPolicies',
                'ManagedPolicies', 'InlinePolicies', 'Status'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Process inactive users
            for user in results['inactive_users']:
                managed_policies = []
                inline_policies = []
                
                for policy in user.get('Policies', []):
                    if policy.get('Type') == 'Managed':
                        managed_policies.append(policy.get('PolicyName', ''))
                    elif policy.get('Type') == 'Inline':
                        inline_policies.append(policy.get('PolicyName', ''))
                
                row = {
                    'Username': user['Username'],
                    'Created': user['Created'].strftime('%Y-%m-%d %H:%M:%S') if user['Created'] else '',
                    'AgeInDays': user['AgeInDays'],
                    'LastActivity': user['LastActivity'].strftime('%Y-%m-%d %H:%M:%S') if user['LastActivity'] else '',
                    'ActivityType': user['ActivityType'],
                    'DaysSinceActivity': user['DaysSinceActivity'] if user['DaysSinceActivity'] is not None else '',
                    'AccessKeys': user['AccessKeys'],
                    'ActiveAccessKeys': user['ActiveAccessKeys'],
                    'MFAEnabled': user.get('MFAEnabled', ''),
                    'PolicyCount': user.get('PolicyCount', 0),
                    'RiskyPolicies': '; '.join(user.get('RiskyPolicies', [])),
                    'AllPolicies': '; '.join([f"{p.get('PolicyName', '')} ({p.get('Type', '')})" for p in user.get('Policies', [])]),
                    'ManagedPolicies': '; '.join(managed_policies),
                    'InlinePolicies': '; '.join(inline_policies),
                    'Status': 'Inactive'
                }
                writer.writerow(row)
            
            # Process active users
            for user in results['active_users']:
                managed_policies = []
                inline_policies = []
                
                for policy in user.get('Policies', []):
                    if policy.get('Type') == 'Managed':
                        managed_policies.append(policy.get('PolicyName', ''))
                    elif policy.get('Type') == 'Inline':
                        inline_policies.append(policy.get('PolicyName', ''))
                
                row = {
                    'Username': user['Username'],
                    'Created': user['Created'].strftime('%Y-%m-%d %H:%M:%S') if user['Created'] else '',
                    'AgeInDays': user['AgeInDays'],
                    'LastActivity': user['LastActivity'].strftime('%Y-%m-%d %H:%M:%S') if user['LastActivity'] else '',
                    'ActivityType': user['ActivityType'],
                    'DaysSinceActivity': user['DaysSinceActivity'] if user['DaysSinceActivity'] is not None else '',
                    'AccessKeys': user['AccessKeys'],
                    'ActiveAccessKeys': user['ActiveAccessKeys'],
                    'MFAEnabled': user.get('MFAEnabled', ''),
                    'PolicyCount': user.get('PolicyCount', 0),
                    'RiskyPolicies': '; '.join(user.get('RiskyPolicies', [])),
                    'AllPolicies': '; '.join([f"{p.get('PolicyName', '')} ({p.get('Type', '')})" for p in user.get('Policies', [])]),
                    'ManagedPolicies': '; '.join(managed_policies),
                    'InlinePolicies': '; '.join(inline_policies),
                    'Status': 'Active'
                }
                writer.writerow(row)
        
        files_created.append(users_filename)
        
        # Export roles
        roles_filename = f"{filename_base}_roles.csv"
        with open(roles_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'RoleName', 'Created', 'AgeInDays', 'LastUsed', 'DaysSinceUse', 
                'LastUsedRegion', 'Path', 'IsServiceLinked', 'PolicyCount', 
                'RiskyPolicies', 'AllPolicies', 'ManagedPolicies', 'InlinePolicies', 'Status'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Process inactive roles
            for role in results['inactive_roles']:
                managed_policies = []
                inline_policies = []
                
                for policy in role.get('Policies', []):
                    if policy.get('Type') == 'Managed':
                        managed_policies.append(policy.get('PolicyName', ''))
                    elif policy.get('Type') == 'Inline':
                        inline_policies.append(policy.get('PolicyName', ''))
                
                row = {
                    'RoleName': role['RoleName'],
                    'Created': role['Created'].strftime('%Y-%m-%d %H:%M:%S') if role['Created'] else '',
                    'AgeInDays': role['AgeInDays'],
                    'LastUsed': role['LastUsed'].strftime('%Y-%m-%d %H:%M:%S') if role['LastUsed'] else '',
                    'DaysSinceUse': role['DaysSinceUse'] if role['DaysSinceUse'] is not None else '',
                    'LastUsedRegion': role['LastUsedRegion'],
                    'Path': role['Path'],
                    'IsServiceLinked': role['IsServiceLinked'],
                    'PolicyCount': role.get('PolicyCount', 0),
                    'RiskyPolicies': '; '.join(role.get('RiskyPolicies', [])),
                    'AllPolicies': '; '.join([f"{p.get('PolicyName', '')} ({p.get('Type', '')})" for p in role.get('Policies', [])]),
                    'ManagedPolicies': '; '.join(managed_policies),
                    'InlinePolicies': '; '.join(inline_policies),
                    'Status': 'Inactive'
                }
                writer.writerow(row)
            
            # Process active roles
            for role in results['active_roles']:
                managed_policies = []
                inline_policies = []
                
                for policy in role.get('Policies', []):
                    if policy.get('Type') == 'Managed':
                        managed_policies.append(policy.get('PolicyName', ''))
                    elif policy.get('Type') == 'Inline':
                        inline_policies.append(policy.get('PolicyName', ''))
                
                row = {
                    'RoleName': role['RoleName'],
                    'Created': role['Created'].strftime('%Y-%m-%d %H:%M:%S') if role['Created'] else '',
                    'AgeInDays': role['AgeInDays'],
                    'LastUsed': role['LastUsed'].strftime('%Y-%m-%d %H:%M:%S') if role['LastUsed'] else '',
                    'DaysSinceUse': role['DaysSinceUse'] if role['DaysSinceUse'] is not None else '',
                    'LastUsedRegion': role['LastUsedRegion'],
                    'Path': role['Path'],
                    'IsServiceLinked': role['IsServiceLinked'],
                    'PolicyCount': role.get('PolicyCount', 0),
                    'RiskyPolicies': '; '.join(role.get('RiskyPolicies', [])),
                    'AllPolicies': '; '.join([f"{p.get('PolicyName', '')} ({p.get('Type', '')})" for p in role.get('Policies', [])]),
                    'ManagedPolicies': '; '.join(managed_policies),
                    'InlinePolicies': '; '.join(inline_policies),
                    'Status': 'Active'
                }
                writer.writerow(row)
        
        files_created.append(roles_filename)
        return files_created
    
    def save_results_to_files(self, results, account_id, profile_name, days_threshold):
        """Save results to multiple file formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"iam_users_roles_report_{account_id}_{timestamp}"
        
        files_created = []
        
        # Create text report
        if 'txt' in self.config['output_formats']:
            text_filename = f"{filename_base}.txt"
            report_lines = self.display_iam_analysis(results, days_threshold, account_id)
            
            with open(text_filename, 'w', encoding='utf-8') as text_file:
                text_file.write("\n".join(report_lines))
            files_created.append(text_filename)
        
        # Create CSV exports
        if 'csv' in self.config['output_formats']:
            csv_files = self.export_to_csv(results, filename_base)
            files_created.extend(csv_files)
        
        return files_created

def main():
    try:
        print("\n" + "="*80)
        print("AWS IAM USERS AND ROLES ANALYZER - ENHANCED VERSION".center(80))
        print("="*80)
        print("\nThis enhanced script provides:")
        print("  1. Comprehensive IAM user and role activity analysis")
        print("  2. Policy attachment analysis with risk assessment")
        print("  3. MFA status checking (always enabled)")
        print("  4. Parallel processing for improved performance")
        print("  5. Multiple export formats (TXT, CSV)")
        print("  6. Configurable filtering and exclusions")
        print("  7. Enhanced security recommendations")
        print("  8. Complete policy listings without truncation")
        
        # Initialize analyzer
        analyzer = IAMAnalyzer()
        
        # Get user configuration
        analyzer.get_user_configuration()
        
        # Get AWS profile and account ID
        session, account_id, profile_name = analyzer.get_profile_and_account_info()
        
        if not analyzer.config['dry_run']:
            proceed = input("\nProceed with analysis? (y/n): ").lower()
            if proceed not in ['y', 'yes']:
                print("Analysis cancelled.")
                sys.exit(0)
        
        print(f"\n🔍 Analyzing IAM users and roles for inactivity over {analyzer.config['days_threshold']} days...")
        start_time = time.time()
        
        # Get all users and roles
        results = analyzer.get_all_users_and_roles(session, analyzer.config['days_threshold'])
        
        # Save results to files
        files_created = analyzer.save_results_to_files(results, account_id, profile_name, analyzer.config['days_threshold'])
        
        end_time = time.time()
        analysis_duration = end_time - start_time
        
        print(f"\n✅ Analysis completed in {analysis_duration:.2f} seconds")
        print(f"\nFiles created:")
        for file_path in files_created:
            file_size = os.path.getsize(file_path)
            print(f"  📄 {file_path} ({file_size:,} bytes)")
        
        # Summary statistics
        total_inactive = len(results['inactive_users']) + len(results['inactive_roles'])
        if total_inactive > 0:
            print(f"\n⚠️  Security Alert: Found {total_inactive} inactive IAM entities requiring review!")
        else:
            print(f"\n✅ No inactive IAM entities found (threshold: {analyzer.config['days_threshold']} days)")
        
        # Additional security alerts
        users_without_mfa = [u for u in results['inactive_users'] + results['active_users'] 
                           if u.get('MFAEnabled') == False]
        if users_without_mfa:
            print(f"🔒 MFA Alert: {len(users_without_mfa)} users without MFA enabled")
        
        if analyzer.config['analyze_policies']:
            risky_entities = ([u for u in results['inactive_users'] + results['active_users'] 
                             if u.get('RiskyPolicies')] + 
                           [r for r in results['inactive_roles'] + results['active_roles'] 
                            if r.get('RiskyPolicies')])
            if risky_entities:
                print(f"🚨 Policy Alert: {len(risky_entities)} entities with potentially risky policies")
        
        print(f"\n📊 Analysis complete. Review the generated reports for detailed findings.")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Operation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()

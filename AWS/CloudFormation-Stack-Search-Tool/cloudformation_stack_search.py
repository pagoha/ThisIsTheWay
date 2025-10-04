#!/usr/bin/env python3
"""
CloudFormation Stack Search Tool
Search CloudFormation stacks and StackSets by name pattern across multiple AWS profiles and regions
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
import re

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
    """Get list of all available AWS regions"""
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        return sorted(regions)
    except Exception as e:
        print(f"Error getting regions, using default list: {e}")
        # Fallback to common regions if API call fails
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
            'ca-central-1', 'sa-east-1'
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

class CloudFormationStackSearcher:
    def __init__(self, search_pattern: str = None, case_sensitive: bool = False, use_regex: bool = False):
        self.search_pattern = search_pattern
        self.case_sensitive = case_sensitive
        self.use_regex = use_regex
        self.regex_pattern = None
        
        # Compile regex pattern if needed
        if self.use_regex and self.search_pattern:
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                self.regex_pattern = re.compile(search_pattern, flags)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        
        self.results = {
            'stacks': [],
            'stacksets': [],
            'errors': []
        }
    
    def matches_pattern(self, text: str) -> bool:
        """Check if text matches the search pattern"""
        if not self.search_pattern:
            return True  # Empty pattern matches everything
            
        if self.use_regex:
            return bool(self.regex_pattern.search(text))
        elif self.case_sensitive:
            return self.search_pattern in text
        else:
            return self.search_pattern.lower() in text.lower()
    
    def get_search_parameters(self):
        """Get search parameters from user input"""
        
        print("=" * 70)
        print("CloudFormation Stack Search Tool")
        print("=" * 70)
        
        # Get search pattern (required in interactive mode)
        while not self.search_pattern:
            pattern = input("Enter search pattern (stack name contains): ").strip()
            if pattern:
                self.search_pattern = pattern
            else:
                print("Search pattern is required!")
        
        # Get case sensitivity preference
        case_sensitive = input("Case sensitive search? (y/N): ").strip().lower() == 'y'
        self.case_sensitive = case_sensitive
        
        # Get regex preference
        use_regex = input("Use regex pattern matching? (y/N): ").strip().lower() == 'y'
        self.use_regex = use_regex
        
        # Compile regex if needed
        if self.use_regex:
            try:
                flags = 0 if case_sensitive else re.IGNORECASE
                self.regex_pattern = re.compile(self.search_pattern, flags)
                print("✓ Valid regex pattern")
            except re.error as e:
                print(f"✗ Invalid regex pattern: {e}")
                sys.exit(1)
        
        # Display search configuration
        search_desc = f"'{self.search_pattern}' (case {'sensitive' if case_sensitive else 'insensitive'}"
        if use_regex:
            search_desc += ", regex enabled"
        search_desc += ")"
        
        print(f"\nSearching for stacks containing: {search_desc}")
    
    def check_cloudformation_stacks(self, session: boto3.Session, profile_name: str, account_id: str, region: str) -> List[Dict[str, Any]]:
        """Check CloudFormation stacks in a specific profile/account and region"""
        matching_stacks = []
        
        try:
            cf_client = session.client('cloudformation', region_name=region)
            
            # Get all stacks
            paginator = cf_client.get_paginator('list_stacks')
            
            for page in paginator.paginate(
                StackStatusFilter=[
                    'CREATE_IN_PROGRESS', 'CREATE_FAILED', 'CREATE_COMPLETE',
                    'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE',
                    'DELETE_IN_PROGRESS', 'DELETE_FAILED',
                    'UPDATE_IN_PROGRESS', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_IN_PROGRESS',
                    'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_ROLLBACK_COMPLETE', 'REVIEW_IN_PROGRESS',
                    'IMPORT_IN_PROGRESS', 'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_IN_PROGRESS',
                    'IMPORT_ROLLBACK_FAILED', 'IMPORT_ROLLBACK_COMPLETE'
                ]
            ):
                for stack in page['StackSummaries']:
                    stack_name = stack['StackName']
                    
                    # Check if stack name matches pattern
                    if self.matches_pattern(stack_name):
                        try:
                            # Get additional stack details
                            stack_details = cf_client.describe_stacks(StackName=stack_name)
                            stack_info = stack_details['Stacks'][0]
                            
                            # Get stack resources
                            resources = self.get_stack_resources(cf_client, stack_name)
                            
                            matching_stack = {
                                'profile_name': profile_name,
                                'account_id': account_id,
                                'region': region,
                                'stack_name': stack_name,
                                'stack_id': stack_info['StackId'],
                                'stack_status': stack_info['StackStatus'],
                                'creation_time': stack_info['CreationTime'].isoformat(),
                                'last_updated_time': stack_info.get('LastUpdatedTime', stack_info['CreationTime']).isoformat(),
                                'description': stack_info.get('Description', 'N/A'),
                                'resource_count': len(resources),
                                'drift_status': stack_info.get('DriftInformation', {}).get('StackDriftStatus', 'N/A'),
                                'tags': stack_info.get('Tags', []),
                                'capabilities': stack_info.get('Capabilities', []),
                                'stack_policy': 'Yes' if stack_info.get('StackPolicyBody') else 'No'
                            }
                            
                            # Check for StackSet association
                            tags = stack_info.get('Tags', [])
                            for tag in tags:
                                if tag['Key'] == 'aws:cloudformation:stack-set-name':
                                    matching_stack['stackset_name'] = tag['Value']
                                    matching_stack['is_stackset_instance'] = True
                                    break
                            else:
                                matching_stack['is_stackset_instance'] = False
                            
                            # Check for nested stacks
                            nested_stacks = [r for r in resources if r['ResourceType'] == 'AWS::CloudFormation::Stack']
                            matching_stack['nested_stack_count'] = len(nested_stacks)
                            
                            matching_stacks.append(matching_stack)
                            
                        except ClientError as e:
                            error_msg = f"Error getting details for stack {stack_name} in {profile_name}({account_id})/{region}: {e}"
                            safe_print(error_msg)
                            self.results['errors'].append({
                                'profile_name': profile_name,
                                'account_id': account_id,
                                'region': region,
                                'stack_name': stack_name,
                                'error_type': 'stack_details_failed',
                                'error_message': str(e)
                            })
        
        except ClientError as e:
            error_msg = f"Error accessing CloudFormation in {profile_name}({account_id}), region {region}: {e}"
            safe_print(error_msg)
            self.results['errors'].append({
                'profile_name': profile_name,
                'account_id': account_id,
                'region': region,
                'error_type': 'cloudformation_access_failed',
                'error_message': str(e)
            })
        except Exception as e:
            error_msg = f"Unexpected error in {profile_name}({account_id}), region {region}: {e}"
            safe_print(error_msg)
            self.results['errors'].append({
                'profile_name': profile_name,
                'account_id': account_id,
                'region': region,
                'error_type': 'unexpected_error',
                'error_message': str(e)
            })
        
        return matching_stacks
    
    def get_stack_resources(self, cf_client, stack_name: str) -> List[Dict]:
        """Get resources for a stack"""
        try:
            paginator = cf_client.get_paginator('list_stack_resources')
            resources = []
            
            for page in paginator.paginate(StackName=stack_name):
                resources.extend(page['StackResourceSummaries'])
            
            return resources
        except ClientError:
            return []
    
    def check_stacksets(self, session: boto3.Session, profile_name: str, account_id: str) -> List[Dict[str, Any]]:
        """Check CloudFormation StackSets"""
        matching_stacksets = []
        
        try:
            cf_client = session.client('cloudformation', region_name='us-east-1')
            
            paginator = cf_client.get_paginator('list_stack_sets')
            
            for page in paginator.paginate():
                for stackset in page['Summaries']:
                    stackset_name = stackset['StackSetName']
                    
                    if self.matches_pattern(stackset_name):
                        try:
                            # Get StackSet details
                            stackset_details = cf_client.describe_stack_set(StackSetName=stackset_name)
                            stackset_info = stackset_details['StackSet']
                            
                            # Get stack instances
                            instances_paginator = cf_client.get_paginator('list_stack_instances')
                            instances = []
                            
                            for instance_page in instances_paginator.paginate(StackSetName=stackset_name):
                                instances.extend(instance_page['Summaries'])
                            
                            # Get operation history
                            try:
                                operations_paginator = cf_client.get_paginator('list_stack_set_operations')
                                operations = []
                                for op_page in operations_paginator.paginate(StackSetName=stackset_name):
                                    operations.extend(op_page['Summaries'])
                                last_operation = operations[0] if operations else None
                            except:
                                last_operation = None
                            
                            matching_stackset = {
                                'profile_name': profile_name,
                                'account_id': account_id,
                                'stackset_name': stackset_name,
                                'stackset_id': stackset_info['StackSetId'],
                                'status': stackset_info['Status'],
                                'description': stackset_info.get('Description', 'N/A'),
                                'permission_model': stackset_info.get('PermissionModel', 'SELF_MANAGED'),
                                'instance_count': len(instances),
                                'regions': list(set([inst['Region'] for inst in instances])),
                                'accounts': list(set([inst['Account'] for inst in instances])),
                                'last_operation': {
                                    'operation_id': last_operation['OperationId'] if last_operation else None,
                                    'action': last_operation['Action'] if last_operation else None,
                                    'status': last_operation['Status'] if last_operation else None,
                                    'creation_timestamp': last_operation['CreationTimestamp'].isoformat() if last_operation else None
                                } if last_operation else None,
                                'instances': [
                                    {
                                        'account': inst['Account'],
                                        'region': inst['Region'],
                                        'status': inst['Status']
                                    } for inst in instances
                                ]
                            }
                            
                            matching_stacksets.append(matching_stackset)
                            
                        except ClientError as e:
                            error_msg = f"Error getting StackSet details for {stackset_name}: {e}"
                            safe_print(error_msg)
                            self.results['errors'].append({
                                'profile_name': profile_name,
                                'account_id': account_id,
                                'stackset_name': stackset_name,
                                'error_type': 'stackset_details_failed',
                                'error_message': str(e)
                            })
        
        except ClientError as e:
            if 'ValidationError' in str(e) or 'AccessDenied' in str(e):
                safe_print(f"StackSets not accessible from profile {profile_name}({account_id}) - likely not management account")
            else:
                error_msg = f"Error accessing StackSets in {profile_name}({account_id}): {e}"
                safe_print(error_msg)
                self.results['errors'].append({
                    'profile_name': profile_name,
                    'account_id': account_id,
                    'error_type': 'stacksets_access_failed',
                    'error_message': str(e)
                })
        
        return matching_stacksets
    
    def worker_function(self, account_info: dict, region: str, check_stacksets_flag: bool = False) -> tuple:
        """Worker function for threading"""
        profile_name = account_info['profile']
        account_id = account_info['account_id']
        session = account_info['session']
        
        safe_print(f"Checking profile {profile_name} (Account: {account_id}) in region {region}...")
        
        # Check regular stacks
        stacks = self.check_cloudformation_stacks(session, profile_name, account_id, region)
        
        # Check StackSets (only when flag is set to avoid duplicates)
        stacksets = []
        if check_stacksets_flag:
            stacksets = self.check_stacksets(session, profile_name, account_id)
        
        return profile_name, region, stacks, stacksets
    
    def export_to_csv(self, filename: str):
        """Export results to CSV"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export stacks
        if self.results['stacks']:
            stacks_file = f"{filename}_stacks_{timestamp}.csv"
            with open(stacks_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'profile_name', 'account_id', 'region', 'stack_name', 'stack_status', 
                    'creation_time', 'last_updated_time', 'description',
                    'resource_count', 'is_stackset_instance', 'stackset_name',
                    'nested_stack_count', 'drift_status', 'stack_policy'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for stack in self.results['stacks']:
                    row = {k: v for k, v in stack.items() if k in fieldnames}
                    writer.writerow(row)
            
            print(f"Stacks exported to: {stacks_file}")
        
        # Export StackSets
        if self.results['stacksets']:
            stacksets_file = f"{filename}_stacksets_{timestamp}.csv"
            with open(stacksets_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'profile_name', 'account_id', 'stackset_name', 'status', 'description',
                    'permission_model', 'instance_count'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for stackset in self.results['stacksets']:
                    row = {k: v for k, v in stackset.items() if k in fieldnames}
                    writer.writerow(row)
            
            print(f"StackSets exported to: {stacksets_file}")
    
    def export_to_json(self, filename: str):
        """Export results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"{filename}_{timestamp}.json"
        
        export_data = {
            'search_pattern': self.search_pattern,
            'case_sensitive': self.case_sensitive,
            'use_regex': self.use_regex,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_stacks': len(self.results['stacks']),
                'total_stacksets': len(self.results['stacksets']),
                'total_errors': len(self.results['errors'])
            },
            'results': self.results
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"Full results exported to: {json_file}")
    
    def display_results(self):
        """Display results in a formatted way"""
        print("\n" + "=" * 80)
        print("SEARCH RESULTS")
        print("=" * 80)
        
        # Determine search description
        if not self.search_pattern:
            search_desc = "all stacks"
        else:
            search_desc = f"stacks containing '{self.search_pattern}'"
            if self.use_regex:
                search_desc = f"stacks matching regex '{self.search_pattern}'"
        
        if self.results['stacks']:
            print(f"\nFound {len(self.results['stacks'])} CloudFormation {search_desc}:")
            print("-" * 80)
            
            for i, stack in enumerate(self.results['stacks'], 1):
                print(f"\n{i}. Stack Name: {stack['stack_name']}")
                print(f"   Profile: {stack['profile_name']}")
                print(f"   Account: {stack['account_id']}")
                print(f"   Region: {stack['region']}")
                print(f"   Status: {stack['stack_status']}")
                print(f"   Created: {stack['creation_time']}")
                print(f"   Resources: {stack['resource_count']}")
                print(f"   Description: {stack['description']}")
                
                if stack.get('is_stackset_instance'):
                    print(f"   StackSet Instance: Yes ({stack.get('stackset_name', 'Unknown')})")
                
                if stack.get('nested_stack_count', 0) > 0:
                    print(f"   Nested Stacks: {stack['nested_stack_count']}")
        else:
            print(f"\nNo CloudFormation {search_desc} found.")
        
        if self.results['stacksets']:
            stackset_desc = f"StackSets containing '{self.search_pattern}'" if self.search_pattern else "StackSets"
            if self.use_regex and self.search_pattern:
                stackset_desc = f"StackSets matching regex '{self.search_pattern}'"
                
            print(f"\nFound {len(self.results['stacksets'])} {stackset_desc}:")
            print("-" * 80)
            
            for i, stackset in enumerate(self.results['stacksets'], 1):
                print(f"\n{i}. StackSet Name: {stackset['stackset_name']}")
                print(f"   Profile: {stackset['profile_name']}")
                print(f"   Account: {stackset['account_id']}")
                print(f"   Status: {stackset['status']}")
                print(f"   Permission Model: {stackset['permission_model']}")
                print(f"   Description: {stackset['description']}")
                print(f"   Instance Count: {stackset['instance_count']}")
                print(f"   Deployed Regions: {', '.join(stackset['regions'])}")
                print(f"   Deployed Accounts: {len(stackset['accounts'])} accounts")
                
                if stackset.get('last_operation'):
                    op = stackset['last_operation']
                    print(f"   Last Operation: {op['action']} ({op['status']})")
        else:
            stackset_desc = f"StackSets containing '{self.search_pattern}'" if self.search_pattern else "StackSets"
            if self.use_regex and self.search_pattern:
                stackset_desc = f"StackSets matching regex '{self.search_pattern}'"
            print(f"\nNo {stackset_desc} found.")
        
        if self.results['errors']:
            print(f"\nEncountered {len(self.results['errors'])} error(s):")
            print("-" * 80)
            
            for i, error in enumerate(self.results['errors'], 1):
                print(f"\n{i}. Profile: {error.get('profile_name', 'N/A')}")
                print(f"   Account: {error.get('account_id', 'N/A')}")
                print(f"   Error Type: {error['error_type']}")
                print(f"   Message: {error['error_message']}")
        
        # Summary
        total_found = len(self.results['stacks']) + len(self.results['stacksets'])
        print(f"\n" + "=" * 80)
        if self.search_pattern:
            summary_pattern = f"'{self.search_pattern}'"
            if self.use_regex:
                summary_pattern += " (regex)"
            print(f"SUMMARY: Found {total_found} total resources matching {summary_pattern}")
        else:
            print(f"SUMMARY: Found {total_found} total resources")
        print(f"- CloudFormation Stacks: {len(self.results['stacks'])}")
        print(f"- StackSets: {len(self.results['stacksets'])}")
        print(f"- Errors: {len(self.results['errors'])}")
        print("=" * 80)
    
    def run_interactive(self):
        """Run the searcher in interactive mode"""
        # Get search parameters
        self.get_search_parameters()
        
        # Get validated account information
        validated_accounts = get_profile_and_account_info()
        
        # Get region selection
        selected_regions = get_region_selection()
        
        print(f"\nStarting search for resources...")
        print(f"Search pattern: '{self.search_pattern}' (case {'sensitive' if self.case_sensitive else 'insensitive'}{', regex' if self.use_regex else ''})")
        print(f"Profiles: {len(validated_accounts)} accounts")
        print(f"Regions: {len(selected_regions)} regions")
        print(f"Total combinations: {len(validated_accounts) * len(selected_regions)}")
        print("-" * 70)
        
        # Use ThreadPoolExecutor for concurrent execution
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks
            futures = []
            for account_info in validated_accounts:
                for i, region in enumerate(selected_regions):
                    # Only check StackSets for the first region per account to avoid duplicates
                    check_stacksets_flag = (i == 0)
                    future = executor.submit(self.worker_function, account_info, region, check_stacksets_flag)
                    futures.append(future)
            
            # Collect results
            completed = 0
            for future in as_completed(futures):
                try:
                    profile_name, region, stacks, stacksets = future.result()
                    self.results['stacks'].extend(stacks)
                    self.results['stacksets'].extend(stacksets)
                    completed += 1
                    if completed % 5 == 0:  # Progress indicator
                        print(f"Completed {completed}/{len(futures)} checks...")
                except Exception as e:
                    safe_print(f"Error in worker thread: {e}")
                    self.results['errors'].append({
                        'error_type': 'worker_thread_failed',
                        'error_message': str(e)
                    })
        
        print(f"Search completed! Processed {len(futures)} profile/region combinations.")
        
        # Display results
        self.display_results()
        
        # Ask about exports
        export_choice = input("\nExport results? (json/csv/both/n): ").strip().lower()
        if export_choice in ['json', 'csv', 'both']:
            # Create safe filename
            safe_pattern = re.sub(r'[^\w\-_]', '_', self.search_pattern) if self.search_pattern else "all_stacks"
            base_filename = f"cloudformation_search_{safe_pattern}"
            
            if export_choice in ['json', 'both']:
                self.export_to_json(base_filename)
            
            if export_choice in ['csv', 'both']:
                self.export_to_csv(base_filename)

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Search CloudFormation stacks and StackSets by name pattern across multiple AWS profiles and regions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python cloudformation_stack_search.py
  
  # Search for 'nops' in specific profiles and regions
  python cloudformation_stack_search.py --pattern nops --profiles prod staging --regions us-east-1 us-west-2
  
  # Case-sensitive search with regex
  python cloudformation_stack_search.py --pattern "^prod-.*" --case-sensitive --regex --profiles prod
  
  # Export results to files
  python cloudformation_stack_search.py --pattern datadog --export-json results --export-csv results
        """
    )
    
    parser.add_argument('--pattern', '-p', help='Search pattern for stack names')
    parser.add_argument('--case-sensitive', '-c', action='store_true', help='Case sensitive search (default: case insensitive)')
    parser.add_argument('--regex', action='store_true', help='Use regex pattern matching')
    parser.add_argument('--profiles', nargs='+', help='AWS Profile names to use (space-separated)')
    parser.add_argument('--regions', '-r', nargs='+', help='AWS Regions to search (space-separated)')
    parser.add_argument('--export-json', help='Export results to JSON file (specify base filename)')
    parser.add_argument('--export-csv', help='Export results to CSV files (specify base filename)')
    
    args = parser.parse_args()
    
    try:
        searcher = CloudFormationStackSearcher(
            search_pattern=args.pattern, 
            case_sensitive=args.case_sensitive,
            use_regex=args.regex
        )
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    if args.profiles and args.regions:
        # Non-interactive mode with specified profiles and regions
        if not args.pattern:
            print("Error: --pattern is required when using non-interactive mode")
            return
            
        print(f"Searching for '{args.pattern}' in profiles: {args.profiles}, regions: {args.regions}")
        
        # Validate profiles
        session = botocore.session.Session()
        available_profiles = session.available_profiles
        invalid_profiles = [p for p in args.profiles if p not in available_profiles]
        if invalid_profiles:
            print(f"Error: Invalid profiles: {invalid_profiles}")
            print(f"Available profiles: {available_profiles}")
            return
        
        # Validate regions
        available_regions = get_available_regions()
        invalid_regions = [r for r in args.regions if r not in available_regions]
        if invalid_regions:
            print(f"Error: Invalid regions: {invalid_regions}")
            print(f"Available regions: {available_regions}")
            return
        
        # Create account info for specified profiles
        validated_accounts = []
        for profile_name in args.profiles:
            try:
                session = boto3.Session(profile_name=profile_name)
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                validated_accounts.append({
                    'profile': profile_name,
                    'account_id': identity['Account'],
                    'iam_arn': identity['Arn'],
                    'session': session
                })
            except Exception as e:
                print(f"Error with profile {profile_name}: {e}")
                return
        
        # Execute search
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for account_info in validated_accounts:
                for i, region in enumerate(args.regions):
                    check_stacksets_flag = (i == 0)
                    future = executor.submit(searcher.worker_function, account_info, region, check_stacksets_flag)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    profile_name, region, stacks, stacksets = future.result()
                    searcher.results['stacks'].extend(stacks)
                    searcher.results['stacksets'].extend(stacksets)
                except Exception as e:
                    safe_print(f"Error in worker thread: {e}")
        
        # Display results
        searcher.display_results()
        
        # Export if requested
        if args.export_json:
            searcher.export_to_json(args.export_json)
        
        if args.export_csv:
            searcher.export_to_csv(args.export_csv)
    else:
        # Interactive mode
        searcher.run_interactive()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

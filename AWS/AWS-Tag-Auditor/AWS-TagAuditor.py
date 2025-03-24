#!/usr/bin/env python3
import boto3
import botocore.session
import sys
import csv
from datetime import datetime, timezone

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

def get_all_resources_with_tags(session):
    """Get all tagged resources across supported AWS services"""
    resources = []
    
    try:
        # Use Resource Groups Tagging API to find all tagged resources
        client = session.client('resourcegroupstaggingapi')
        paginator = client.get_paginator('get_resources')
        
        print("Retrieving all tagged resources... (this may take a while)")
        
        # Get all resources with any tags
        page_iterator = paginator.paginate()
        
        resource_count = 0
        for page in page_iterator:
            current_batch = page['ResourceTagMappingList']
            resource_count += len(current_batch)
            resources.extend(current_batch)
            if resource_count % 100 == 0:
                print(f"Retrieved {resource_count} resources so far...")
        
        print(f"Found {resource_count} tagged resources")
        
        return resources
        
    except Exception as e:
        print(f"Error retrieving tagged resources: {e}")
        sys.exit(1)

def analyze_resource_tags(resources):
    """Analyze resources and their tags"""
    # Track various metrics
    service_count = {}
    tag_key_count = {}
    untagged_resources = []
    resources_with_tags = []
    
    # Analyze each resource
    for resource in resources:
        arn = resource['ResourceARN']
        
        # Extract service name from ARN
        try:
            service = arn.split(':')[2]
            service_count[service] = service_count.get(service, 0) + 1
        except:
            service = "unknown"
        
        # Count tag keys and collect resource data
        tags = resource.get('Tags', [])
        
        if not tags:
            untagged_resources.append(arn)
        else:
            resources_with_tags.append({
                'ResourceARN': arn,
                'Service': service,
                'Tags': tags
            })
            
            # Count occurrences of each tag key
            for tag in tags:
                tag_key = tag['Key']
                tag_key_count[tag_key] = tag_key_count.get(tag_key, 0) + 1
    
    return {
        'service_count': service_count,
        'tag_key_count': tag_key_count,
        'untagged_resources': untagged_resources,
        'resources_with_tags': resources_with_tags,
        'total_resources': len(resources)
    }

def display_tag_analysis(analysis, account_id):
    """Display a formatted report of the tag analysis"""
    service_count = analysis['service_count']
    tag_key_count = analysis['tag_key_count']
    untagged_resources = analysis['untagged_resources']
    resources_with_tags = analysis['resources_with_tags']
    total_resources = analysis['total_resources']
    
    # Terminal width for better formatting
    terminal_width = 140
    
    # Helper function to create a formatted header
    def create_header(title):
        padding = (terminal_width - len(title)) // 2
        return "\n" + "=" * padding + " " + title + " " + "=" * padding
    
    # Helper function to create a section separator
    def create_separator(char="-"):
        return char * terminal_width
    
    # Create report header
    output = []
    output.append(create_separator("="))
    output.append("AWS TAG AUDIT REPORT".center(terminal_width))
    output.append(f"Account ID: {account_id}".center(terminal_width))
    output.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(terminal_width))
    output.append(create_separator("="))
    
    # Summary section
    output.append(create_header("SUMMARY"))
    output.append(f"Total resources analyzed: {total_resources}")
    output.append(f"Resources with tags: {len(resources_with_tags)}")
    output.append(f"Untagged resources: {len(untagged_resources)}")
    output.append(f"Unique tag keys found: {len(tag_key_count)}")
    
    # Services section
    output.append(create_header("SERVICES WITH TAGGED RESOURCES"))
    service_list = sorted(service_count.items(), key=lambda x: x[1], reverse=True)
    
    if service_list:
        # Format the table header
        header_format = "{:<30} | {:<10} | {:<10}"
        output.append(header_format.format("AWS Service", "Count", "Percentage"))
        output.append(create_separator("-"))
        
        # Add each service with count and percentage
        for service, count in service_list:
            percentage = (count / total_resources) * 100
            row = header_format.format(
                service,
                count,
                f"{percentage:.1f}%"
            )
            output.append(row)
    else:
        output.append("No tagged resources found.")
    
    # Tag keys section
    output.append(create_header("TAG KEY USAGE"))
    tag_key_list = sorted(tag_key_count.items(), key=lambda x: x[1], reverse=True)
    
    if tag_key_list:
        # Format the table header
        header_format = "{:<30} | {:<10} | {:<10}"
        output.append(header_format.format("Tag Key", "Count", "Percentage"))
        output.append(create_separator("-"))
        
        # Add each tag key with count and percentage
        for key, count in tag_key_list:
            percentage = (count / total_resources) * 100
            row = header_format.format(
                key if len(key) <= 30 else key[:27] + "...",
                count,
                f"{percentage:.1f}%"
            )
            output.append(row)
    else:
        output.append("No tag keys found.")
    
    # Recommendations section
    output.append(create_header("RECOMMENDATIONS"))
    
    tagged_percentage = (len(resources_with_tags) / total_resources) * 100 if total_resources > 0 else 0
    
    if tagged_percentage < 80:
        output.append("⚠️ Less than 80% of resources have tags. Consider implementing a tagging strategy.")
    
    if untagged_resources:
        if len(untagged_resources) <= 5:
            output.append("\nUntagged resources (sample):")
            for arn in untagged_resources:
                output.append(f"  - {arn}")
        else:
            output.append("\nUntagged resources (first 5):")
            for arn in untagged_resources[:5]:
                output.append(f"  - {arn}")
            output.append(f"  ... and {len(untagged_resources) - 5} more")
    
    # Best practices
    output.append("\nTagging Best Practices:")
    output.append("  1. Implement mandatory tags (e.g., 'Environment', 'Owner', 'Project', 'Cost-Center')")
    output.append("  2. Use AWS Tag Editor to apply tags in bulk")
    output.append("  3. Consider using AWS Config to enforce tagging policies")
    output.append("  4. Set up Tag Policies in AWS Organizations for consistency")
    
    output.append("\n" + create_separator("="))
    
    # Print the report
    print("\n".join(output))
    
    # Return the output lines for file writing
    return output

def save_results_to_file(resources, analysis, account_id, profile_name):
    """Save results to CSV and text report files"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"tag_audit_{account_id}_{timestamp}.csv"
    text_filename = f"tag_audit_report_{account_id}_{timestamp}.txt"
    
    # Save CSV file with all tagged resources
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['ResourceARN', 'ResourceType', 'Service', 'TagKey', 'TagValue']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for resource in analysis['resources_with_tags']:
            arn = resource['ResourceARN']
            service = resource['Service']
            resource_type = arn.split(':')[2] if ':' in arn else 'unknown'
            
            for tag in resource['Tags']:
                writer.writerow({
                    'ResourceARN': arn,
                    'ResourceType': resource_type,
                    'Service': service,
                    'TagKey': tag['Key'],
                    'TagValue': tag['Value']
                })
    
    # Generate the report
    report_lines = display_tag_analysis(analysis, account_id)
    
    # Save text report
    with open(text_filename, 'w', encoding='utf-8') as text_file:
        text_file.write("\n".join(report_lines))
    
    return csv_filename, text_filename

def main():
    try:
        print("\n" + "="*80)
        print("AWS TAG AUDITOR".center(80))
        print("="*80)
        print("\nThis script provides:")
        print("  1. A complete inventory of all tagged AWS resources")
        print("  2. Analysis of tag usage across your AWS account")
        print("  3. Recommendations for improving your tagging strategy")
        
        # Get AWS profile and account ID
        session, account_id, profile_name = get_profile_and_account_info()
        
        print("\nFetching and analyzing tagged resources...")
        
        # Get all tagged resources
        resources = get_all_resources_with_tags(session)
        
        # Analyze tag usage
        analysis = analyze_resource_tags(resources)
        
        # Save results to files
        csv_file, text_file = save_results_to_file(resources, analysis, account_id, profile_name)
        
        print(f"\nDetailed CSV output saved to: {csv_file}")
        print(f"Analysis report saved to: {text_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
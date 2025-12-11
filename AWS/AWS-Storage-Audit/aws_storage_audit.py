#!/usr/bin/env python3
"""
AWS Storage Analyzer
Analyzes storage usage across EC2, RDS, and DynamoDB in an AWS account.
"""

import boto3
import botocore.session
import csv
import sys
import time
from datetime import datetime
from collections import defaultdict
from botocore.exceptions import ClientError

# Try to import openpyxl for Excel support
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False
    print("Warning: openpyxl not installed. Excel export will not be available.")
    print("Install with: pip install openpyxl")

class StorageAnalyzer:
    def __init__(self):
        """Initialize the analyzer"""
        self.session = None
        self.regions = []
        self.results = []
        self.account_id = None
        self.account_alias = None
        self.profile_name = None
        self.output_prefix = None
        
    def get_profile_and_account_info(self):
        """Prompt for AWS profile and confirm account details"""
        session = botocore.session.Session()
        profiles = session.available_profiles
        
        if not profiles:
            print("Error: No AWS profiles found. Please configure AWS CLI first.")
            sys.exit(1)
        
        print("\n" + "="*80)
        print("AWS PROFILE SELECTION")
        print("="*80)
        print("\nAvailable AWS profiles:")
        for i, profile in enumerate(profiles, 1):
            print(f"  {i}. {profile}")
        
        # Profile selection logic
        while True:
            try:
                if len(profiles) == 1:
                    print(f"\nOnly one profile available, using '{profiles[0]}'")
                    profile_name = profiles[0]
                    break
                else:
                    selection = input("\nEnter profile number or name (or press Enter for default): ").strip()
                    
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
                print(f"Error in profile selection: {e}")
        
        # Create session and validate
        try:
            self.session = boto3.Session(profile_name=profile_name)
            self.profile_name = profile_name
            sts = self.session.client('sts')
            
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            iam_arn = identity['Arn']
            
            # Try to get account alias
            try:
                iam = self.session.client('iam')
                aliases = iam.list_account_aliases()
                if aliases['AccountAliases']:
                    self.account_alias = aliases['AccountAliases'][0]
            except:
                pass
            
            print("\n" + "="*80)
            print("AWS ACCOUNT INFORMATION")
            print("="*80)
            print(f"Profile:        {profile_name}")
            print(f"Account ID:     {self.account_id}")
            if self.account_alias:
                print(f"Account Alias:  {self.account_alias}")
            print(f"IAM ARN:        {iam_arn}")
            print("="*80)
            
            confirmation = input("\nIs this the correct account? (yes/no): ").lower()
            if confirmation not in ['y', 'yes']:
                print("\nAborting operation.")
                sys.exit(0)
            
            return True
            
        except Exception as e:
            print(f"\nError connecting to AWS with profile '{profile_name}': {e}")
            sys.exit(1)
    
    def setup_interactive(self):
        """Interactive setup for the analyzer"""
        print("\n" + "="*80)
        print("AWS STORAGE ANALYZER")
        print("="*80)
        print()
        
        # Get profile and account info first
        self.get_profile_and_account_info()
        
        print()
        
        # Region Selection
        print("="*80)
        print("REGION SELECTION")
        print("="*80)
        print("\nOptions:")
        print("  1. All regions (comprehensive but slower)")
        print("  2. Specific regions (faster)")
        print("  3. Current region only")
        
        choice = input("\nSelect an option [1-3] (default: 2): ").strip() or "2"
        
        if choice == "1":
            print("\nFetching all available regions...")
            self.regions = self._get_all_regions()
            print(f"✓ Will analyze {len(self.regions)} regions")
        elif choice == "3":
            current_region = self.session.region_name or 'us-east-1'
            self.regions = [current_region]
            print(f"✓ Will analyze current region: {current_region}")
        else:  # choice == "2" or default
            print("\nCommon regions:")
            common_regions = [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'
            ]
            for idx, region in enumerate(common_regions, 1):
                print(f"  {idx}. {region}")
            
            print("\nEnter region names separated by commas (e.g., us-east-1,us-west-2)")
            print("Or enter numbers from the list above (e.g., 1,4)")
            region_input = input("Regions: ").strip()
            
            if not region_input:
                self.regions = ['us-east-1']
                print("✓ Using default: us-east-1")
            else:
                # Check if input is numbers or region names
                if all(part.strip().isdigit() for part in region_input.split(',')):
                    # Numbers provided
                    indices = [int(x.strip()) - 1 for x in region_input.split(',')]
                    self.regions = [common_regions[i] for i in indices if 0 <= i < len(common_regions)]
                else:
                    # Region names provided
                    self.regions = [r.strip() for r in region_input.split(',')]
                
                print(f"✓ Will analyze {len(self.regions)} region(s): {', '.join(self.regions)}")
        
        print()
        
        # Output Options
        print("="*80)
        print("OUTPUT OPTIONS")
        print("="*80)
        print("\nOutput formats will be generated:")
        print("  ✓ Console output (always generated)")
        print("  ✓ Text file report")
        if EXCEL_AVAILABLE:
            print("  ✓ Excel workbook (single file with multiple tabs)")
        else:
            print("  ✗ Excel not available (install openpyxl for Excel support)")
        
        self.output_prefix = input("\nEnter output filename prefix (default: storage_analysis): ").strip() or "storage_analysis"
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_prefix = f"{self.output_prefix}_{timestamp}"
        
        print(f"✓ Output files will be saved with prefix: {self.output_prefix}")
        print()
        
        # Confirmation
        print("="*80)
        print("ANALYSIS CONFIGURATION SUMMARY")
        print("="*80)
        print(f"AWS Profile:     {self.profile_name}")
        print(f"AWS Account:     {self.account_id}" + (f" ({self.account_alias})" if self.account_alias else ""))
        print(f"Regions:         {', '.join(self.regions)}")
        print(f"Output Prefix:   {self.output_prefix}")
        print("="*80)
        print()
        
        confirm = input("Start analysis? (yes/no) [default: yes]: ").strip().lower() or 'yes'
        
        if confirm not in ['y', 'yes']:
            print("\nAnalysis cancelled.")
            sys.exit(0)
        
        print("\n" + "="*80)
        print("STARTING ANALYSIS...")
        print("="*80)
        print()
    
    def _get_all_regions(self):
        """Get all available AWS regions"""
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            regions = ec2.describe_regions()['Regions']
            return [region['RegionName'] for region in regions]
        except Exception as e:
            print(f"Error fetching regions: {str(e)}")
            return ['us-east-1']
    
    def analyze_ec2_storage(self, region):
        """Analyze EC2 EBS volume storage in a region"""
        print(f"  → Analyzing EC2 volumes in {region}...")
        ec2 = self.session.client('ec2', region_name=region)
        total_gb = 0
        volume_count = 0
        volumes_detail = []
        
        try:
            paginator = ec2.get_paginator('describe_volumes')
            for page in paginator.paginate():
                for volume in page['Volumes']:
                    size_gb = volume['Size']
                    total_gb += size_gb
                    volume_count += 1
                    
                    # Get volume name from tags
                    volume_name = ''
                    if 'Tags' in volume:
                        for tag in volume['Tags']:
                            if tag['Key'] == 'Name':
                                volume_name = tag['Value']
                                break
                    
                    volumes_detail.append({
                        'volume_id': volume['VolumeId'],
                        'name': volume_name,
                        'size_gb': size_gb,
                        'state': volume['State'],
                        'volume_type': volume['VolumeType'],
                        'availability_zone': volume['AvailabilityZone'],
                        'attached_to': volume['Attachments'][0]['InstanceId'] if volume['Attachments'] else 'Not attached'
                    })
            
            print(f"    ✓ Found {volume_count} volumes totaling {total_gb} GB")
            return total_gb, volume_count, volumes_detail
            
        except ClientError as e:
            print(f"    ✗ Error analyzing EC2 volumes: {e}")
            return 0, 0, []
    
    def analyze_rds_storage(self, region):
        """Analyze RDS storage in a region"""
        print(f"  → Analyzing RDS instances in {region}...")
        rds = self.session.client('rds', region_name=region)
        total_gb = 0
        instance_count = 0
        instances_detail = []
        
        try:
            paginator = rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    size_gb = db['AllocatedStorage']
                    total_gb += size_gb
                    instance_count += 1
                    
                    instances_detail.append({
                        'db_identifier': db['DBInstanceIdentifier'],
                        'engine': db['Engine'],
                        'engine_version': db['EngineVersion'],
                        'size_gb': size_gb,
                        'storage_type': db.get('StorageType', 'N/A'),
                        'status': db['DBInstanceStatus'],
                        'multi_az': db.get('MultiAZ', False)
                    })
            
            print(f"    ✓ Found {instance_count} RDS instances totaling {total_gb} GB")
            return total_gb, instance_count, instances_detail
            
        except ClientError as e:
            print(f"    ✗ Error analyzing RDS instances: {e}")
            return 0, 0, []
    
    def analyze_dynamodb_storage(self, region):
        """Analyze DynamoDB storage in a region"""
        print(f"  → Analyzing DynamoDB tables in {region}...")
        dynamodb = self.session.client('dynamodb', region_name=region)
        total_bytes = 0
        table_count = 0
        tables_detail = []
        
        try:
            paginator = dynamodb.get_paginator('list_tables')
            table_names = []
            for page in paginator.paginate():
                table_names.extend(page['TableNames'])
            
            for table_name in table_names:
                try:
                    table_info = dynamodb.describe_table(TableName=table_name)
                    table = table_info['Table']
                    size_bytes = table.get('TableSizeBytes', 0)
                    total_bytes += size_bytes
                    table_count += 1
                    
                    tables_detail.append({
                        'table_name': table_name,
                        'size_gb': round(size_bytes / (1024**3), 4),
                        'item_count': table.get('ItemCount', 0),
                        'status': table['TableStatus'],
                        'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                    })
                except Exception as e:
                    print(f"    ⚠ Warning: Could not describe table {table_name}: {e}")
            
            total_gb = round(total_bytes / (1024**3), 2)
            print(f"    ✓ Found {table_count} DynamoDB tables totaling {total_gb} GB")
            return total_gb, table_count, tables_detail
            
        except ClientError as e:
            print(f"    ✗ Error analyzing DynamoDB tables: {e}")
            return 0, 0, []
    
    def analyze_region(self, region):
        """Analyze storage in a specific region"""
        print(f"\n{'='*80}")
        print(f"Analyzing Region: {region}")
        print(f"{'='*80}")
        
        ec2_total, ec2_count, ec2_details = self.analyze_ec2_storage(region)
        rds_total, rds_count, rds_details = self.analyze_rds_storage(region)
        dynamo_total, dynamo_count, dynamo_details = self.analyze_dynamodb_storage(region)
        
        total_storage = ec2_total + rds_total + dynamo_total
        
        result = {
            'region': region,
            'ec2_storage_gb': ec2_total,
            'ec2_volume_count': ec2_count,
            'ec2_details': ec2_details,
            'rds_storage_gb': rds_total,
            'rds_instance_count': rds_count,
            'rds_details': rds_details,
            'dynamodb_storage_gb': dynamo_total,
            'dynamodb_table_count': dynamo_count,
            'dynamodb_details': dynamo_details,
            'total_storage_gb': total_storage
        }
        
        self.results.append(result)
        
        print(f"\n  Summary for {region}:")
        print(f"    EC2 Storage:      {ec2_total:,.2f} GB ({ec2_count} volumes)")
        print(f"    RDS Storage:      {rds_total:,.2f} GB ({rds_count} instances)")
        print(f"    DynamoDB Storage: {dynamo_total:,.2f} GB ({dynamo_count} tables)")
        print(f"    Total Storage:    {total_storage:,.2f} GB")
        
        return result
    
    def run_analysis(self):
        """Run the storage analysis across all configured regions"""
        for region in self.regions:
            try:
                self.analyze_region(region)
            except Exception as e:
                print(f"\n✗ Error analyzing region {region}: {e}")
                continue
        
        self.print_summary()
        self.export_results()
    
    def print_summary(self):
        """Print overall summary of storage analysis"""
        print("\n" + "="*80)
        print("OVERALL STORAGE SUMMARY")
        print("="*80)
        
        total_ec2 = sum(r['ec2_storage_gb'] for r in self.results)
        total_rds = sum(r['rds_storage_gb'] for r in self.results)
        total_dynamodb = sum(r['dynamodb_storage_gb'] for r in self.results)
        grand_total = sum(r['total_storage_gb'] for r in self.results)
        
        total_ec2_volumes = sum(r['ec2_volume_count'] for r in self.results)
        total_rds_instances = sum(r['rds_instance_count'] for r in self.results)
        total_dynamo_tables = sum(r['dynamodb_table_count'] for r in self.results)
        
        print(f"\nAccount: {self.account_id}" + (f" ({self.account_alias})" if self.account_alias else ""))
        print(f"Regions Analyzed: {len(self.regions)}")
        print(f"\n{'Service':<20} {'Storage (GB)':<20} {'Resource Count':<20}")
        print("-" * 60)
        print(f"{'EC2 (EBS)':<20} {total_ec2:>15,.2f}     {total_ec2_volumes:>15,}")
        print(f"{'RDS':<20} {total_rds:>15,.2f}     {total_rds_instances:>15,}")
        print(f"{'DynamoDB':<20} {total_dynamodb:>15,.2f}     {total_dynamo_tables:>15,}")
        print("-" * 60)
        print(f"{'TOTAL':<20} {grand_total:>15,.2f}")
        print()
        
        # Region breakdown
        if len(self.regions) > 1:
            print("\nStorage by Region:")
            print(f"{'Region':<20} {'Total Storage (GB)':<25}")
            print("-" * 45)
            for result in sorted(self.results, key=lambda x: x['total_storage_gb'], reverse=True):
                print(f"{result['region']:<20} {result['total_storage_gb']:>20,.2f}")
            print()
    
    def export_to_text(self):
        """Export results to text file"""
        filename = f"{self.output_prefix}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("="*80 + "\n")
                f.write("AWS STORAGE ANALYSIS REPORT\n")
                f.write("="*80 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Account: {self.account_id}")
                if self.account_alias:
                    f.write(f" ({self.account_alias})")
                f.write(f"\nProfile: {self.profile_name}\n")
                f.write(f"Regions: {', '.join(self.regions)}\n\n")
                
                # Overall Summary
                f.write("="*80 + "\n")
                f.write("OVERALL SUMMARY\n")
                f.write("="*80 + "\n\n")
                
                total_ec2 = sum(r['ec2_storage_gb'] for r in self.results)
                total_rds = sum(r['rds_storage_gb'] for r in self.results)
                total_dynamodb = sum(r['dynamodb_storage_gb'] for r in self.results)
                grand_total = sum(r['total_storage_gb'] for r in self.results)
                
                f.write(f"EC2 Storage Total (GB):      {total_ec2:,.2f}\n")
                f.write(f"RDS Storage Total (GB):      {total_rds:,.2f}\n")
                f.write(f"DynamoDB Storage Total (GB): {total_dynamodb:,.2f}\n")
                f.write(f"{'─'*40}\n")
                f.write(f"TOTAL STORAGE (GB):          {grand_total:,.2f}\n\n")
                
                # Regional Details
                for result in self.results:
                    f.write("\n" + "="*80 + "\n")
                    f.write(f"Region: {result['region']}\n")
                    f.write("="*80 + "\n\n")
                    
                    f.write(f"EC2 Storage:      {result['ec2_storage_gb']:,.2f} GB ({result['ec2_volume_count']} volumes)\n")
                    f.write(f"RDS Storage:      {result['rds_storage_gb']:,.2f} GB ({result['rds_instance_count']} instances)\n")
                    f.write(f"DynamoDB Storage: {result['dynamodb_storage_gb']:,.2f} GB ({result['dynamodb_table_count']} tables)\n")
                    f.write(f"Total:            {result['total_storage_gb']:,.2f} GB\n\n")
                    
                    # EC2 Details
                    if result['ec2_details']:
                        f.write("  EC2 Volumes:\n")
                        f.write("  " + "-"*76 + "\n")
                        for vol in result['ec2_details']:
                            f.write(f"    Volume ID: {vol['volume_id']}\n")
                            if vol['name']:
                                f.write(f"    Name:      {vol['name']}\n")
                            f.write(f"    Size:      {vol['size_gb']} GB\n")
                            f.write(f"    Type:      {vol['volume_type']}\n")
                            f.write(f"    State:     {vol['state']}\n")
                            f.write(f"    AZ:        {vol['availability_zone']}\n")
                            f.write(f"    Attached:  {vol['attached_to']}\n")
                            f.write("\n")
                    
                    # RDS Details
                    if result['rds_details']:
                        f.write("  RDS Instances:\n")
                        f.write("  " + "-"*76 + "\n")
                        for db in result['rds_details']:
                            f.write(f"    Identifier:  {db['db_identifier']}\n")
                            f.write(f"    Engine:      {db['engine']} {db['engine_version']}\n")
                            f.write(f"    Size:        {db['size_gb']} GB\n")
                            f.write(f"    Type:        {db['storage_type']}\n")
                            f.write(f"    Status:      {db['status']}\n")
                            f.write(f"    Multi-AZ:    {db['multi_az']}\n")
                            f.write("\n")
                    
                    # DynamoDB Details
                    if result['dynamodb_details']:
                        f.write("  DynamoDB Tables:\n")
                        f.write("  " + "-"*76 + "\n")
                        for table in result['dynamodb_details']:
                            f.write(f"    Table:        {table['table_name']}\n")
                            f.write(f"    Size:         {table['size_gb']} GB\n")
                            f.write(f"    Items:        {table['item_count']:,}\n")
                            f.write(f"    Status:       {table['status']}\n")
                            f.write(f"    Billing Mode: {table['billing_mode']}\n")
                            f.write("\n")
            
            print(f"✓ Text report exported to: {filename}")
            
        except Exception as e:
            print(f"✗ Error exporting to text file: {e}")
    
    def export_to_excel(self):
        """Export results to Excel workbook with multiple sheets"""
        if not EXCEL_AVAILABLE:
            print("✗ Excel export skipped (openpyxl not available)")
            return
        
        filename = f"{self.output_prefix}.xlsx"
        
        try:
            wb = Workbook()
            
            # Remove default sheet
            if 'Sheet' in wb.sheetnames:
                wb.remove(wb['Sheet'])
            
            # Styling
            header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            header_font = Font(color="FFFFFF", bold=True)
            border = Border(
                left=Side(style='thin'),
                right=Side(style='thin'),
                top=Side(style='thin'),
                bottom=Side(style='thin')
            )
            
            # Summary Sheet
            ws_summary = wb.create_sheet("Summary")
            
            # Header
            ws_summary['A1'] = "AWS Storage Analysis Summary"
            ws_summary['A1'].font = Font(size=14, bold=True)
            ws_summary['A2'] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            ws_summary['A3'] = f"Account: {self.account_id}" + (f" ({self.account_alias})" if self.account_alias else "")
            
            # Overall totals
            row = 5
            ws_summary[f'A{row}'] = "Service"
            ws_summary[f'B{row}'] = "Total Storage (GB)"
            ws_summary[f'C{row}'] = "Resource Count"
            
            for col in ['A', 'B', 'C']:
                ws_summary[f'{col}{row}'].fill = header_fill
                ws_summary[f'{col}{row}'].font = header_font
                ws_summary[f'{col}{row}'].border = border
            
            row += 1
            total_ec2 = sum(r['ec2_storage_gb'] for r in self.results)
            total_rds = sum(r['rds_storage_gb'] for r in self.results)
            total_dynamodb = sum(r['dynamodb_storage_gb'] for r in self.results)
            
            ws_summary[f'A{row}'] = "EC2 (EBS)"
            ws_summary[f'B{row}'] = total_ec2
            ws_summary[f'C{row}'] = sum(r['ec2_volume_count'] for r in self.results)
            
            row += 1
            ws_summary[f'A{row}'] = "RDS"
            ws_summary[f'B{row}'] = total_rds
            ws_summary[f'C{row}'] = sum(r['rds_instance_count'] for r in self.results)
            
            row += 1
            ws_summary[f'A{row}'] = "DynamoDB"
            ws_summary[f'B{row}'] = total_dynamodb
            ws_summary[f'C{row}'] = sum(r['dynamodb_table_count'] for r in self.results)
            
            row += 1
            ws_summary[f'A{row}'] = "TOTAL"
            ws_summary[f'A{row}'].font = Font(bold=True)
            ws_summary[f'B{row}'] = total_ec2 + total_rds + total_dynamodb
            ws_summary[f'B{row}'].font = Font(bold=True)
            
            # Regional breakdown
            row += 3
            ws_summary[f'A{row}'] = "Region"
            ws_summary[f'B{row}'] = "EC2 (GB)"
            ws_summary[f'C{row}'] = "RDS (GB)"
            ws_summary[f'D{row}'] = "DynamoDB (GB)"
            ws_summary[f'E{row}'] = "Total (GB)"
            
            for col in ['A', 'B', 'C', 'D', 'E']:
                ws_summary[f'{col}{row}'].fill = header_fill
                ws_summary[f'{col}{row}'].font = header_font
                ws_summary[f'{col}{row}'].border = border
            
            for result in self.results:
                row += 1
                ws_summary[f'A{row}'] = result['region']
                ws_summary[f'B{row}'] = result['ec2_storage_gb']
                ws_summary[f'C{row}'] = result['rds_storage_gb']
                ws_summary[f'D{row}'] = result['dynamodb_storage_gb']
                ws_summary[f'E{row}'] = result['total_storage_gb']
            
            # Auto-size columns
            for col in ['A', 'B', 'C', 'D', 'E']:
                ws_summary.column_dimensions[col].width = 20
            
            # EC2 Details Sheet
            ws_ec2 = wb.create_sheet("EC2 Volumes")
            headers = ['Region', 'Volume ID', 'Name', 'Size (GB)', 'Type', 'State', 'AZ', 'Attached To']
            ws_ec2.append(headers)
            
            for col_num, _ in enumerate(headers, 1):
                cell = ws_ec2.cell(1, col_num)
                cell.fill = header_fill
                cell.font = header_font
                cell.border = border
            
            for result in self.results:
                for vol in result['ec2_details']:
                    ws_ec2.append([
                        result['region'],
                        vol['volume_id'],
                        vol['name'],
                        vol['size_gb'],
                        vol['volume_type'],
                        vol['state'],
                        vol['availability_zone'],
                        vol['attached_to']
                    ])
            
            for col in ws_ec2.columns:
                ws_ec2.column_dimensions[col[0].column_letter].width = 18
            
            # RDS Details Sheet
            ws_rds = wb.create_sheet("RDS Instances")
            headers = ['Region', 'DB Identifier', 'Engine', 'Version', 'Size (GB)', 'Storage Type', 'Status', 'Multi-AZ']
            ws_rds.append(headers)
            
            for col_num, _ in enumerate(headers, 1):
                cell = ws_rds.cell(1, col_num)
                cell.fill = header_fill
                cell.font = header_font
                cell.border = border
            
            for result in self.results:
                for db in result['rds_details']:
                    ws_rds.append([
                        result['region'],
                        db['db_identifier'],
                        db['engine'],
                        db['engine_version'],
                        db['size_gb'],
                        db['storage_type'],
                        db['status'],
                        db['multi_az']
                    ])
            
            for col in ws_rds.columns:
                ws_rds.column_dimensions[col[0].column_letter].width = 18
            
            # DynamoDB Details Sheet
            ws_dynamo = wb.create_sheet("DynamoDB Tables")
            headers = ['Region', 'Table Name', 'Size (GB)', 'Item Count', 'Status', 'Billing Mode']
            ws_dynamo.append(headers)
            
            for col_num, _ in enumerate(headers, 1):
                cell = ws_dynamo.cell(1, col_num)
                cell.fill = header_fill
                cell.font = header_font
                cell.border = border
            
            for result in self.results:
                for table in result['dynamodb_details']:
                    ws_dynamo.append([
                        result['region'],
                        table['table_name'],
                        table['size_gb'],
                        table['item_count'],
                        table['status'],
                        table['billing_mode']
                    ])
            
            for col in ws_dynamo.columns:
                ws_dynamo.column_dimensions[col[0].column_letter].width = 20
            
            wb.save(filename)
            print(f"✓ Excel report exported to: {filename}")
            
        except Exception as e:
            print(f"✗ Error exporting to Excel: {e}")
    
    def export_results(self):
        """Export results to all configured formats"""
        print("\n" + "="*80)
        print("EXPORTING RESULTS")
        print("="*80)
        print()
        
        self.export_to_text()
        self.export_to_excel()
        
        print()


def main():
    """Main entry point"""
    analyzer = StorageAnalyzer()
    
    try:
        analyzer.setup_interactive()
        analyzer.run_analysis()
        
        print("="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)
        print()
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

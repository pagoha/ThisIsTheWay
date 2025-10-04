To use, first edit the file by inserting your AWS config profile, then run script in your PowerShell terminal by copying and pasting the whole script.

This script will output a text file showing a list of your EC2 instances, their names (if available), and their tags, with proper separation between instances for easy readablility. 

The output file will also show the total number of instances and region at bottom of the file.

# EC2 Instances Tags Report Generator

A PowerShell script that generates comprehensive CSV reports of EC2 instances across multiple AWS profiles and regions, including detailed tag information and instance metadata.

## Features

- 🔍 **Multi-Account Support** - Scan across multiple AWS profiles
- 🌍 **Multi-Region Support** - Query multiple regions simultaneously  
- 📊 **CSV Output** - Easy to analyze in Excel or other tools
- 🏷️ **Complete Tag Extraction** - Captures all instance tags
- 📈 **Instance Metadata** - Includes state, type, launch time, and more
- ⚡ **Error Handling** - Continues processing even if some profiles/regions fail
- 📝 **Summary Report** - Generates additional summary file with totals

## Prerequisites

- AWS CLI installed and configured
- PowerShell (Windows PowerShell or PowerShell Core)
- Valid AWS profiles configured in AWS CLI

## Configuration

Edit the script to specify your AWS profiles and regions:

```powershell
$profilesToScan = @("production", "staging", "development")  # Your AWS profiles
$regionsToScan = @("us-east-1", "us-west-2", "eu-west-1")   # Your target regions
```

## Usage

1. Clone or download the script
2. Update the `$profilesToScan` and `$regionsToScan` arrays
3. Run the script in PowerShell:
   ```powershell
   .\ec2-tags-report.ps1
   ```

## Output

The script generates two files:
- `EC2_Instances_Tags_Report_YYYYMMDD-HHMMSS.csv` - Detailed instance report
- `EC2_Summary_YYYYMMDD-HHMMSS.txt` - Summary with totals and metadata

### Sample CSV Output
```csv
"AWS Profile","Region","Instance ID","Instance Name","State","Instance Type","Launch Time","Environment","Owner","Cost Center","Tag: Application"
"production","us-east-1","i-0123456789abcdef0","WebServer-Prod","running","t3.medium","2024-01-15T10:30:00.000Z","Production","DevOps-Team","CC-12345","WebApp"
```

## CSV Columns

- **AWS Profile** - Source AWS profile/account
- **Region** - AWS region
- **Instance ID** - EC2 instance identifier
- **Instance Name** - Value from 'Name' tag
- **State** - Current instance state (running, stopped, etc.)
- **Instance Type** - EC2 instance size/type
- **Launch Time** - When the instance was launched
- **Environment/Owner/Cost Center** - Common tags promoted to dedicated columns
- **Tag: [TagName]** - All other tags as individual columns

## Benefits

- **Inventory Management** - Complete visibility across all accounts and regions
- **Cost Analysis** - Easy filtering and sorting by cost centers, owners, environments
- **Compliance Reporting** - Track tagging compliance across your infrastructure
- **Capacity Planning** - Analyze instance types and distribution
- **Multi-Account Governance** - Centralized reporting for multiple AWS accounts

## License

MIT License - Feel free to modify and distribute as needed.

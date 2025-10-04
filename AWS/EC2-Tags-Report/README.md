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

**Step 1:** Check your available AWS profiles by running:
```powershell
aws configure list-profiles
```

**Step 2:** Edit the script to specify your AWS profiles and regions BEFORE running:

```powershell
$profilesToScan = @("PROFILE1", "PROFILE2", "PROFILE3")  # Replace with your actual AWS profile names
$regionsToScan = @("us-east-1", "us-west-2", "eu-west-1")   # Replace with your target regions
```

**IMPORTANT:** You must edit the script to replace `PROFILE1`, `PROFILE2`, `PROFILE3` with your actual AWS profile names and specify your desired regions BEFORE running.

## Usage

**Option 1: Copy and Paste (Quick Start)**
1. Run `aws configure list-profiles` to see your available profiles
2. Copy the entire script code
3. **Edit the `$profilesToScan` and `$regionsToScan` arrays** with your actual profile names and regions
4. Open PowerShell
5. Paste the modified code directly into the PowerShell session
6. Press Enter to execute

**Option 2: Save as File**
1. Run `aws configure list-profiles` to see your available profiles
2. Save the script as `EC2-Tags-Report.ps1`
3. **Edit the `$profilesToScan` and `$regionsToScan` arrays** with your actual profile names and regions
4. Run the script in PowerShell:
   ```powershell
   .\EC2-Tags-Report.ps1
   ```

## Output

The script generates two files:
- `EC2_Instances_Tags_Report_YYYYMMDD-HHMMSS.csv` - Detailed instance report
- `EC2_Summary_YYYYMMDD-HHMMSS.txt` - Summary with totals and metadata

### Sample CSV Output
```csv
"AWS Profile","Region","Instance ID","Instance Name","State","Instance Type","Launch Time","Environment","Owner","Cost Center","Tag: Application"
"PROFILE1","us-east-1","i-0123456789abcdef0","WebServer-Prod","running","t3.medium","2024-01-15T10:30:00.000Z","Production","DevOps-Team","CC-12345","WebApp"
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


Made with ❤️ by pagoha

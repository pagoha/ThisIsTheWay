# VPC Flow Logs Checker 🔍

This Python script (`vpcFlowLogsChecker.py`) performs a comprehensive VPC analysis across AWS accounts. It lists all VPCs and checks their Flow Logs status (ACTIVE, INACTIVE, or NOT CONFIGURED), providing detailed information on each VPC and its associated Flow Logs configuration.

## ✨ Features

### 🔐 AWS Credentials/Profile Selection:
- Lists all available AWS profiles
- Allows selection by number or name
- Uses default profile if none selected

### ✅ Account Confirmation:
- Shows account ID and IAM ARN before proceeding
- Requires explicit confirmation to continue

### 🔍 VPC Analysis:
- Lists all VPCs in the account
- Checks for VPC Flow Logs status (ACTIVE, INACTIVE, NOT CONFIGURED)
- Shows detailed information about each VPC and its Flow Logs

### 📊 Comprehensive Reporting:
- Displays a formatted terminal report
- Provides summary statistics
- Includes recommendations based on findings
- Exports both text and CSV reports with timestamps and account ID

### ⚠️ Error Handling:
- Comprehensive error handling throughout
- Graceful handling of keyboard interrupts

## 📋 Requirements

- Python 3.6+
- Required packages:
  - boto3
  - botocore
  - pandas
  - tabulate
- AWS CLI configured with at least one profile

## 🚀 Installation

Install the required Python packages:

```bash
pip install boto3 botocore pandas tabulate
```

## 📝 Usage

Simply download then run the script from the command line:

```bash
./vpcFlowLogsChecker.py
```
or
```bash
python3 vpcFlowLogsChecker.py
```

Make sure to change directory to where you downloaded the file before running the script.

## 🔄 How It Works

1. The script lists available AWS profiles from your AWS credentials
2. You select the profile to use (or it uses the only available one)
3. It displays and asks you to confirm the AWS account information
4. The script:
   - Retrieves all VPCs in the selected account
   - Checks flow log configuration for each VPC
   - Generates a detailed report with the status of each VPC
   - Provides summary statistics and recommendations
   - Saves results to both text and CSV files for further analysis

## 📂 Output Files

The script generates two output files with a timestamp and account ID in the filename:
- `vpc_flow_logs_status_ACCOUNT-ID_TIMESTAMP.txt`: A formatted text report
- `vpc_flow_logs_status_ACCOUNT-ID_TIMESTAMP.csv`: Raw data in CSV format for further processing

## 📺 Example Output

Below is an example of the Terminal Output during execution:
```
================================================================================
                          AWS VPC FLOW LOGS CHECKER                          
================================================================================

This script identifies:
  1. VPCs with Flow Logs enabled and active
  2. VPCs with Flow Logs configured but inactive
  3. VPCs without Flow Logs configured

Available AWS profiles:
1. default
2. development
3. production

Enter profile number or name (or press Enter for default): 3

AWS Account Information:
Profile: production
Account ID: 123456789012
IAM ARN: arn:aws:iam::123456789012:user/security-admin

Is this the correct account? (yes/no): yes

Fetching and analyzing VPC Flow Logs status...
Gathering VPC information...
Found 8 VPCs
Processing VPC flow logs status...

========================================================================================================
                                    VPC FLOW LOGS STATUS REPORT                                    
                                   Account ID: 123456789012                                   
                              Generated at: 2025-03-21 13:19:15                              
========================================================================================================

+----------------+--------------------+----------------+----------------+---------------------+-----------------------------------------------+--------------------------------------+
| VPC ID         | VPC Name           | CIDR Block     | Flow Logs      | Log Destination Type | Log Destination                              | Flow Log ID                           |
+----------------+--------------------+----------------+----------------+---------------------+-----------------------------------------------+--------------------------------------+
| vpc-a1b2c3d4e5 | Production-VPC     | 10.0.0.0/16    | ACTIVE         | cloud-watch-logs    | arn:aws:logs:us-east-1:123456789012:log-group | fl-abcdef01234567890                 |
| vpc-f6g7h8i9j0 | Staging-VPC        | 10.1.0.0/16    | ACTIVE         | s3                  | arn:aws:s3:::flow-logs-bucket/staging        | fl-123456abcdef78901                 |
| vpc-k1l2m3n4o5 | Development-VPC    | 10.2.0.0/16    | NOT CONFIGURED | N/A                 | N/A                                           | N/A                                  |
| vpc-p6q7r8s9t0 | Test-VPC           | 172.16.0.0/16  | INACTIVE       | cloud-watch-logs    | arn:aws:logs:us-east-1:123456789012:log-group | fl-abcdef98765432109                 |
| vpc-u1v2w3x4y5 | Management-VPC     | 192.168.0.0/16 | ACTIVE         | cloud-watch-logs    | arn:aws:logs:us-east-1:123456789012:log-group | fl-mnopqr78901234567                 |
| vpc-z6a7b8c9d0 | Sandbox-VPC        | 10.3.0.0/16    | NOT CONFIGURED | N/A                 | N/A                                           | N/A                                  |
| vpc-e1f2g3h4i5 | DataProcessing-VPC | 10.4.0.0/16    | ACTIVE         | s3                  | arn:aws:s3:::flow-logs-bucket/data           | fl-567890abcdefghij1                 |
| vpc-j6k7l8m9n0 | Legacy-VPC         | 192.169.0.0/16 | NOT CONFIGURED | N/A                 | N/A                                           | N/A                                  |
+----------------+--------------------+----------------+----------------+---------------------+-----------------------------------------------+--------------------------------------+

SUMMARY:
------------------------------------------------------------------------------------------------------------------------
Total VPCs: 8
VPCs with Active Flow Logs: 4
VPCs with Inactive Flow Logs: 1
VPCs without Flow Logs: 3

RECOMMENDATIONS:
------------------------------------------------------------------------------------------------------------------------
• Consider enabling Flow Logs for the 3 VPCs that don't have them
  Flow Logs help with network monitoring, troubleshooting, and security analysis
• Review the 1 VPCs with inactive Flow Logs and consider activating them

========================================================================================================

Detailed text report saved to: vpc_flow_logs_status_123456789012_20250321_131915.txt
CSV data saved to: vpc_flow_logs_status_123456789012_20250321_131915.csv
```

---

Made with ❤️ by [pagoha]

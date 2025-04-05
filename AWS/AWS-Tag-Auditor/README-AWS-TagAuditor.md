# 🏷️ AWS Tag Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=flat&logo=amazon-aws&logoColor=white)](https://aws.amazon.com/)

## 📋 Overview

AWS Tag Auditor is a powerful Python utility that provides comprehensive analysis of resource tagging across your AWS environments. Proper tagging is essential for cost allocation, security governance, and operational management. This tool helps you understand your current tagging status and identify areas for improvement.

## ✨ Features

- 🔍 **Complete Inventory**: Collects all tagged resources across your AWS account
- 📊 **Detailed Analysis**: Provides statistics on tag usage and distribution
- 📂 **Service Breakdown**: Shows tag coverage by AWS service
- 📝 **CSV Export**: Exports detailed tag information for all resources
- 📈 **Recommendations**: Suggests improvements to your tagging strategy
- 🔒 **Account Verification**: Confirms the target account before proceeding
- 🧩 **Profile Support**: Works with your existing AWS CLI profiles

## 🚀 Installation

### Prerequisites

- Python 3.6 or higher
- AWS CLI configured with appropriate credentials
- Required Python packages:
  - boto3
  - botocore

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/aws-tag-auditor.git
   cd aws-tag-auditor
   ```
   
Install required dependencies:


pip install -r requirements.txt
Make the script executable:


chmod +x aws_tag_auditor.py

## 🛠️ Usage

Simply run the script from your terminal:

```bash
./aws_tag_auditor.py
```
The script will:

- 📝 Display available AWS profiles and prompt you to select one
- 🔐 Show account information and ask for confirmation
- 🔄 Retrieve all tagged resources across your account
- 📊 Analyze tag usage and generate reports
- 💾 Save results to both CSV and text files

## 📊 Sample Output

Console Display
```
================================================================================
                                AWS TAG AUDITOR
================================================================================

This script provides:
  1. A complete inventory of all tagged AWS resources
  2. Analysis of tag usage across your AWS account
  3. Recommendations for improving your tagging strategy

Available AWS profiles:
1. default
2. production
3. development

Enter profile number or name (or press Enter for default): 2

AWS Account Information:
Profile: production
Account ID: 123456789012
IAM ARN: arn:aws:iam::123456789012:user/admin

Is this the correct account? (yes/no): yes

Fetching and analyzing tagged resources...
Retrieving all tagged resources... (this may take a while)
Retrieved 100 resources so far...
Retrieved 200 resources so far...
Found 342 tagged resources

Detailed CSV output saved to: tag_audit_123456789012_20250321_172530.csv
Analysis report saved to: tag_audit_report_123456789012_20250321_172530.txt
```
The generated report includes:
- 📈 Summary statistics: Total resources, tagged vs. untagged counts
- 🏢 Service breakdown: Which AWS services have tagged resources
- 🔑 Tag key usage: Most commonly used tag keys across your infrastructure
- ⚠️ Untagged resources: Examples of resources missing tags
- 💡 Best practices: Recommendations for improving your tagging strategy

## 📑 Output Files
The script generates two files:

CSV Export (tag_audit_[account-id]_[timestamp].csv):
- Complete inventory of all tagged resources
- Includes resource ARNs, services, tag keys and values
- Useful for detailed analysis in spreadsheet software

Text Report (tag_audit_report_[account-id]_[timestamp].txt):
- Formatted summary of tag analysis
--Service and tag key statistics
--Recommendations and best practices


Text Report Example (tag_audit_report_123456789012_20250321_172530.txt)
```
====================================================================================================
                                        AWS TAG AUDIT REPORT
                                      Account ID: 123456789012
                               Generated at: 2025-03-21 17:25:30
====================================================================================================

==================================== SUMMARY ====================================

Total resources analyzed: 342
Resources with tags: 312
Untagged resources: 30
Unique tag keys found: 18

========================= SERVICES WITH TAGGED RESOURCES =========================
AWS Service                    | Count     | Percentage
---------------------------------------------------------------------------------------------
ec2                            | 124       | 36.3%
s3                             | 78        | 22.8%
lambda                         | 53        | 15.5%
rds                            | 27        | 7.9%
dynamodb                       | 21        | 6.1%
cloudformation                 | 19        | 5.6%
iam                            | 12        | 3.5%
cloudfront                     | 8         | 2.3%

================================= TAG KEY USAGE =================================
Tag Key                        | Count     | Percentage
---------------------------------------------------------------------------------------------
Name                           | 289       | 84.5%
Environment                    | 245       | 71.6%
Project                        | 221       | 64.6%
Department                     | 183       | 53.5%
Owner                          | 176       | 51.5%
CostCenter                     | 153       | 44.7%
Application                    | 124       | 36.3%
CreatedBy                      | 98        | 28.7%
CreatedDate                    | 87        | 25.4%
ManagedBy                      | 76        | 22.2%
Team                           | 65        | 19.0%
Security                       | 42        | 12.3%
Stage                          | 39        | 11.4%
Backup                         | 37        | 10.8%
StackId                        | 19        | 5.6%
AutomatedBy                    | 15        | 4.4%
ComplianceStatus               | 12        | 3.5%
DataClassification             | 9         | 2.6%

============================== RECOMMENDATIONS ==============================

Untagged resources (first 5):
  - arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456789a
  - arn:aws:s3:::untagged-bucket-example-1
  - arn:aws:lambda:us-east-1:123456789012:function:untagged-function
  - arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc123def456789a
  - arn:aws:rds:us-east-1:123456789012:db:untagged-db-instance
  ... and 25 more

Tagging Best Practices:
  1. Implement mandatory tags (e.g., 'Environment', 'Owner', 'Project', 'Cost-Center')
  2. Use AWS Tag Editor to apply tags in bulk
  3. Consider using AWS Config to enforce tagging policies
  4. Set up Tag Policies in AWS Organizations for consistency

====================================================================================================
```

## 🔧 AWS Permissions Required
The script requires the following AWS permissions:
```
tag:GetResources
tag:GetTagKeys
sts:GetCallerIdentity
```
Sample IAM policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "tag:GetResources",
                "tag:GetTagKeys",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## ⚠️ Limitations
- The AWS Resource Groups Tagging API has service-specific limitations
- Very large AWS accounts may experience longer execution times
- Some resource types might not be discoverable via the Tagging API



Created with ❤️ by [pagoha]

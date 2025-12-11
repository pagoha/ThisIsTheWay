# AWS Storage Audit

A comprehensive storage analysis and inventory tool for AWS accounts. Generate executive-level reports with detailed breakdowns of your AWS storage infrastructure across all regions.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![AWS](https://img.shields.io/badge/AWS-Boto3-orange)

## 🎯 Overview

AWS Storage Audit provides a complete view of your storage utilization across multiple AWS services, helping you:

- **Identify cost optimization opportunities** - Find unattached volumes and oversized resources
- **Ensure backup compliance** - Validate backup coverage and efficiency
- **Plan capacity** - Understand storage distribution across regions and services
- **Generate executive reports** - Professional Excel and text reports ready for leadership

## 📊 Currently Audits

- ✅ **EC2 EBS Volumes** - Block storage for compute instances
- ✅ **RDS Database Instances** - Relational database storage
- ✅ **DynamoDB Tables** - NoSQL database storage
- ✅ **AWS Backup Recovery Points** - Backup storage with source tracking

## 🚀 Planned Coverage

- 🔜 **S3 Buckets** - Object storage
- 🔜 **EFS File Systems** - Elastic file storage
- 🔜 **FSx File Systems** - Managed file storage
- 🔜 **Glacier Vaults** - Archive storage
- 🔜 **Storage Gateway** - Hybrid storage

## 📋 Requirements

```bash
Python 3.7+
boto3
openpyxl (optional, for Excel export)
```

## 🔧 Installation

1. **Download the script**
   
   Download `aws_storage_audit.py` to your local machine.

2. **Install dependencies**
   ```bash
   pip install boto3 openpyxl
   ```

3. **Configure AWS credentials**
   ```bash
   aws configure
   # OR set up named profiles
   aws configure --profile production
   ```

## 💻 Usage

### Interactive Mode (Recommended)

Simply run the script and follow the prompts:

```bash
python3 aws_storage_audit.py
```

The interactive wizard will guide you through:
1. AWS profile selection with account verification
2. Region selection (all regions, specific regions, or current region)
3. Output format configuration
4. Confirmation before starting the audit

### Example Session

```
================================================================================
AWS STORAGE AUDIT
================================================================================

AWS PROFILE SELECTION
================================================================================

Available AWS profiles:
  1. default
  2. production
  3. development

Enter profile number or name (or press Enter for default): 2

AWS ACCOUNT INFORMATION
================================================================================
Profile:        production
Account ID:     123456789012
Account Alias:  my-company-prod
IAM ARN:        arn:aws:iam::123456789012:user/admin
================================================================================

Is this the correct account? (yes/no): yes

REGION SELECTION
================================================================================

Options:
  1. All regions (comprehensive but slower)
  2. Specific regions (faster)
  3. Current region only

Select an option [1-3] (default: 2): 2

Common regions:
  1. us-east-1
  2. us-east-2
  3. us-west-1
  4. us-west-2
  5. eu-west-1
  6. eu-central-1
  7. ap-southeast-1
  8. ap-northeast-1

Regions: 1,2,5

✓ Will audit 3 region(s): us-east-1, us-east-2, eu-west-1

OUTPUT OPTIONS
================================================================================

Output formats will be generated:
  ✓ Console output (always generated)
  ✓ Text file report
  ✓ Excel workbook (single file with multiple tabs)

Enter output filename prefix (default: storage_audit): monthly_audit

✓ Output files will be saved with prefix: monthly_audit_20250612_143052

AUDIT CONFIGURATION SUMMARY
================================================================================
AWS Profile:     production
AWS Account:     123456789012 (my-company-prod)
Regions:         us-east-1, us-east-2, eu-west-1
Output Prefix:   monthly_audit_20250612_143052
================================================================================

Start audit? (yes/no) [default: yes]: yes
```

## 📈 Output Examples

### Console Output

```
================================================================================
OVERALL STORAGE SUMMARY
================================================================================

Account: 123456789012 (my-company-prod)
Regions Audited: 3

Service                   Storage (GB)         Resource Count      
-----------------------------------------------------------------
EC2 (EBS)                       2,450.00                      87
RDS                             1,200.00                      12
DynamoDB                           45.50                      23
AWS Backup (stored)               980.00                     145
AWS Backup (source)             3,695.50
-----------------------------------------------------------------
TOTAL (Active Storage)          3,695.50
TOTAL (inc. Backups)            4,675.50

Backup Efficiency: 26.5% (backup size vs source size)

Storage by Region:
Region               Active (GB)          Backup (GB)          Total (GB)          
--------------------------------------------------------------------------------
us-east-1                  2,890.00              750.00            3,640.00
us-west-2                    580.50              180.00              760.50
eu-west-1                    225.00               50.00              275.00
```

### Excel Report - Executive Summary Tab

![Executive Summary](docs/images/executive-summary.png)

The Executive Summary includes:
- **Report Header** - Generated date, account info, regions audited
- **Storage Overview** - Service-by-service breakdown with resource counts
- **Key Metrics** - Backup efficiency, total regions, resource counts
- **Storage by Region** - Regional distribution breakdown
- **Detailed Analysis Tabs** - Descriptions of all tabs and their purpose
- **Key Insights & Recommendations** - Automated findings and actionable recommendations

### Excel Report - Detailed Tabs

#### EC2 Volumes Tab
| Region | Volume ID | Name | Size (GB) | Type | State | AZ | Attached To |
|--------|-----------|------|-----------|------|-------|----|-----------| 
| us-east-1 | vol-0abc123 | prod-web-01 | 100 | gp3 | in-use | us-east-1a | i-0xyz789 |
| us-east-1 | vol-0def456 | | 50 | gp2 | available | us-east-1b | Not attached |

#### RDS Instances Tab
| Region | DB Identifier | Engine | Version | Size (GB) | Storage Type | Status | Multi-AZ |
|--------|---------------|--------|---------|-----------|--------------|--------|----------|
| us-east-1 | prod-mysql-01 | mysql | 8.0.32 | 500 | gp3 | available | true |

#### DynamoDB Tables Tab
| Region | Table Name | Size (GB) | Item Count | Status | Billing Mode |
|--------|------------|-----------|------------|--------|--------------|
| us-east-1 | users-prod | 12.45 | 1,245,890 | ACTIVE | PAY_PER_REQUEST |

#### AWS Backups Tab
| Region | Vault Name | Resource Type | Resource ID | Source Size (GB) | Backup Size (GB) | Creation Date | Status | Retention |
|--------|------------|---------------|-------------|------------------|------------------|---------------|--------|-----------|
| us-east-1 | Default | EBS | vol-0abc123 | 100.00 | 28.50 | 2025-06-12T02:00:00 | COMPLETED | 30 |

#### Backup Vaults Tab
| Region | Vault Name | Backup Count | Backup Size (GB) | Source Size (GB) |
|--------|------------|--------------|------------------|------------------|
| us-east-1 | Default | 87 | 456.30 | 1,890.00 |
| us-east-1 | Production-Vault | 58 | 523.70 | 1,805.50 |

### Text Report

```
================================================================================
AWS STORAGE AUDIT REPORT
================================================================================

Generated: 2025-06-12 14:30:52
Account: 123456789012 (my-company-prod)
Profile: production
Regions: us-east-1, us-east-2, eu-west-1

================================================================================
OVERALL SUMMARY
================================================================================

EC2 Storage Total (GB):              2,450.00
RDS Storage Total (GB):              1,200.00
DynamoDB Storage Total (GB):            45.50
AWS Backup Storage Total (GB):         980.00
AWS Backup Source Storage (GB):      3,695.50
────────────────────────────────────────
TOTAL ACTIVE STORAGE (GB):           3,695.50
TOTAL WITH BACKUPS (GB):             4,675.50

================================================================================
Region: us-east-1
================================================================================

EC2 Storage:      2,150.00 GB (67 volumes)
RDS Storage:        900.00 GB (8 instances)
DynamoDB Storage:    35.20 GB (18 tables)
AWS Backups:        750.00 GB (98 recovery points)
Backup Source:    3,085.20 GB
Total:            3,085.20 GB

  EC2 Volumes:
  ----------------------------------------------------------------------------
    Volume ID: vol-0abc123def456
    Name:      prod-web-01
    Size:      100 GB
    Type:      gp3
    State:     in-use
    AZ:        us-east-1a
    Attached:  i-0xyz789abc123

    Volume ID: vol-0def456abc789
    Size:      50 GB
    Type:      gp2
    State:     available
    AZ:        us-east-1b
    Attached:  Not attached
```

## 🎨 Features

### Executive-Ready Reports
- Professional formatting with color-coded sections
- Clear visual hierarchy
- Summary metrics at a glance
- Detailed drill-down capabilities

### Automated Insights
The tool automatically identifies:
- ✅ Unattached EBS volumes wasting costs
- ✅ Backup efficiency and compression ratios
- ✅ Under-protected resources (low backup coverage)
- ✅ Regional concentration risks
- ✅ Service-specific optimization opportunities

### Multi-Region Support
- Audit all AWS regions simultaneously
- Select specific regions for faster scans
- Regional distribution analysis
- Cross-region storage comparison

### Flexible Output Formats
- **Console** - Real-time progress and summary
- **Excel** - Multi-tab workbook with formatting
- **Text** - Detailed plain-text report

### Safe & Auditable
- Read-only operations (no modifications made)
- Account confirmation before execution
- Complete audit trail in output files
- Timestamped reports for version control

## 🔒 Permissions Required

The tool requires read-only permissions for the following services:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "rds:DescribeDBInstances",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "backup:ListBackupVaults",
        "backup:ListRecoveryPointsByBackupVault",
        "iam:ListAccountAliases",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🐛 Troubleshooting

### "No AWS profiles found"
- Run `aws configure` to set up credentials
- Ensure `~/.aws/credentials` and `~/.aws/config` exist

### "Access Denied" errors
- Verify IAM permissions (see Permissions Required section)
- Check if you're using the correct AWS profile
- Ensure the profile has access to the selected regions

### Excel export fails
- Install openpyxl: `pip install openpyxl`
- Text report will still be generated

### Backup data shows 0 GB
- Verify AWS Backup permissions
- Check if backup vaults exist in selected regions
- Some vaults may require additional access permissions

## 📝 Examples & Use Cases

### Monthly Cost Optimization Review
```bash
python3 aws_storage_audit.py
# Select all regions
# Review "Key Insights" for unattached volumes
# Check backup efficiency ratios
```

### Disaster Recovery Audit
```bash
python3 aws_storage_audit.py
# Select production regions
# Review "Backup Vaults" tab for coverage
# Validate backup retention policies
```

### Capacity Planning
```bash
python3 aws_storage_audit.py
# Run monthly and track trends
# Compare regional growth rates
# Forecast future storage needs
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) - AWS SDK for Python
- Excel reports powered by [openpyxl](https://openpyxl.readthedocs.io/)
- Inspired by the need for better AWS storage visibility

## 📊 Screenshots

### Terminal Output
```
================================================================================
Auditing Region: us-east-1
================================================================================
  → Auditing EC2 volumes in us-east-1...
    ✓ Found 67 volumes totaling 2150 GB
  → Auditing RDS instances in us-east-1...
    ✓ Found 8 RDS instances totaling 900 GB
  → Auditing DynamoDB tables in us-east-1...
    ✓ Found 18 DynamoDB tables totaling 35.20 GB
  → Auditing AWS Backups in us-east-1...
    ✓ Found 98 backups in 2 vaults
      Backup Storage: 750.00 GB
      Source Storage: 3,085.20 GB
```

---

Made with ❤️ by [pagoha](https://github.com/pagoha)

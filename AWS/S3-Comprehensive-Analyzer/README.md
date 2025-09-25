# AWS S3 Comprehensive Multi-Account Analyzer 🪣

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-boto3-orange)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![License](https://img.shields.io/badge/License-MIT-green)](https://opensource.org/license/mit)

A comprehensive Python tool that analyzes AWS S3 buckets across multiple accounts to provide detailed insights into storage usage, security configurations, cost optimization opportunities, and organizational governance recommendations.

## 📋 Overview

The AWS S3 Comprehensive Multi-Account Analyzer performs deep analysis across your AWS organization for:
- 🏢 **Multi-account bucket inventory** with comprehensive metrics and storage details
- 🔒 **Cross-account security analysis** including encryption status and public access configurations
- 💰 **Organization-wide cost optimization** identification and lifecycle policy recommendations
- 🌍 **Regional distribution analysis** and storage class optimization opportunities
- 📊 **Governance recommendations** for enterprise-scale S3 management

The script generates detailed reports that help maintain security compliance, optimize costs, and implement best practices across your entire AWS organization.

## ✨ Features

- 🔄 **Interactive multi-account selection** from your configured AWS profiles
- 🏗️ **Comprehensive bucket analysis** including size, object count, and last modified dates
- 🛡️ **Security configuration audit** (encryption, versioning, public access blocks)
- 💾 **Lifecycle policy assessment** and cost optimization recommendations
- 📈 **CloudWatch metrics integration** for accurate storage and object counts
- 📊 **Dual output formats** - detailed text reports and structured CSV exports
- 🏢 **Enterprise-scale analysis** with cross-account aggregation and comparison
- 🎯 **Intelligent categorization** of buckets by risk level and optimization potential

## 🚀 Prerequisites

### Python Requirements
- Python 3.6 or higher
- AWS SDK for Python (boto3) library

To install the required Python packages:
```bash
pip install boto3
```

### AWS Credentials Setup
- The script uses AWS CLI credentials and configuration for multi-account access
- Before running the script, ensure you have AWS CLI installed and configured for each target account:

```bash
# Configure multiple AWS profiles
aws configure --profile account1
aws configure --profile account2
aws configure --profile production
```

Example credentials file structure:
```
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

[account1]
aws_access_key_id = ACCOUNT1_ACCESS_KEY
aws_secret_access_key = ACCOUNT1_SECRET_KEY

[production]
aws_access_key_id = PROD_ACCESS_KEY
aws_secret_access_key = PROD_SECRET_KEY
```

### Required IAM Permissions
Each profile/account must have these IAM permissions:
- s3:ListBucket
- s3:ListAllMyBuckets
- s3:GetBucketLocation
- s3:GetBucketVersioning
- s3:GetBucketEncryption
- s3:GetPublicAccessBlock
- s3:GetLifecycleConfiguration
- s3:ListObjects (for detailed analysis)
- cloudwatch:GetMetricStatistics
- sts:GetCallerIdentity

Example comprehensive policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:ListAllMyBuckets",
                "s3:GetBucket*",
                "s3:ListObjects"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:GetMetricStatistics",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## 📝 Usage

### Linux/MacOS:
Make the script executable and run:
```bash
chmod +x S3-Comprehensive-Analyzer.py
./S3-Comprehensive-Analyzer.py
```

### Windows (PowerShell):
Run the script directly:
```bash
python S3-Comprehensive-Analyzer.py
```

### Interactive Usage Flow
Follow the guided prompts:

1. **Account Selection**: Choose from available AWS profiles
   ```
   Available AWS profiles:
   1. default
   2. production  
   3. staging
   4. development
   
   Enter profile numbers (1,2,3), names (prod,staging), or 'all'
   ```

2. **Output Format Selection**: Choose your preferred report format
   ```
   Output format options:
   1. Text report only
   2. CSV export only
   3. Both text report and CSV export
   ```

3. **Account Validation**: Confirm account access and proceed with analysis

### Sample Report Output
The generated multi-account report provides comprehensive insights:

```
==========================================================================================================
                            AWS S3 BUCKETS MULTI-ACCOUNT ANALYSIS REPORT                            
                                  Generated at: 2023-04-15 14:32:19                                  
==========================================================================================================

===================================== ACCOUNT SUMMARIES =====================================
Total Accounts Analyzed: 3
Successful Account Analyses: 3

Per-Account Summary:
  [OK] production (123456789012): 45 buckets analyzed  
  [OK] staging (234567890123): 23 buckets analyzed
  [OK] development (345678901234): 12 buckets analyzed

===================================== OVERALL SUMMARY ======================================
Total S3 Buckets Across All Accounts: 80
Successfully Analyzed Buckets: 80
Total Storage Used: 2.5 TB
Total Objects: 1,234,567

Cross-Account Bucket Categories:
  - Empty Buckets: 15
  - Large Buckets (>1GB): 25
  - Unencrypted Buckets: 8
  - Buckets without Public Access Block: 3
  - Buckets without Lifecycle Policies: 35

Regional Distribution:
  - us-east-1: 35 buckets
  - us-west-2: 25 buckets
  - eu-west-1: 20 buckets

=============================== CROSS-ACCOUNT SECURITY ISSUES ===============================
Unencrypted buckets (8):
  production (123456789012): 5 unencrypted buckets
    - legacy-backups-prod (45.2 GB)
    - temp-data-store (2.1 GB)
    - logs-archive-old (156 MB)
  
Buckets without public access block (3):
  development (345678901234): 3 buckets without public access block
    - test-public-website (12 MB)
    - dev-static-assets (234 MB)

========================== TOP 10 LARGEST BUCKETS (CROSS-ACCOUNT) ===========================
Bucket Name                    | Size            | Objects     | Region    | Account              | Last Modified
------------------------------------------------------------------------------------------------------------
data-warehouse-prod           | 850.5 GB        | 125,432     | us-east-1 | production (12345...) | 2023-04-14
backup-archives-main          | 425.8 GB        | 89,234      | us-west-2 | production (12345...) | 2023-04-13
analytics-raw-data           | 234.7 GB        | 456,789     | us-east-1 | staging (23456...)    | 2023-04-15

==========================================================================================================
                                MULTI-ACCOUNT RECOMMENDATIONS                                
==========================================================================================================

1. Empty Buckets Cleanup:
   - Total empty buckets across all accounts: 15
   - production (123456789012): 8 empty buckets
   - staging (234567890123): 4 empty buckets
   - development (345678901234): 3 empty buckets

2. Encryption Security Issues:
   - Total unencrypted buckets: 8
   - production (123456789012): 5 unencrypted buckets
   - staging (234567890123): 3 unencrypted buckets

3. Cost Optimization - Lifecycle Policies:
   - Total buckets without lifecycle policies: 35
   - production (123456789012): 18 buckets
   - staging (234567890123): 12 buckets

4. Organizational Governance:
   - Implement AWS Organizations SCPs for S3 security standards
   - Use AWS Config rules for multi-account S3 compliance monitoring
   - Consider S3 Storage Lens organization-level view for cost optimization

5. Cross-Account Best Practices:
   - Standardize S3 bucket naming conventions across accounts
   - Implement consistent tagging strategy for cost allocation
   - Use AWS Control Tower for centralized S3 governance

==========================================================================================================
```

## 🔒 Security Considerations

- **Multi-account permissions**: Requires read access to S3 and CloudWatch across target accounts
- **Sensitive data**: Reports contain bucket names, sizes, and configuration details
- **Data handling**: No object-level data is accessed, only metadata and configurations
- **Report security**: Consider encryption and access controls for generated reports

## 🌟 Best Practices

- **Regular analysis**: Run monthly or quarterly for organization-wide S3 governance
- **Automated integration**: Incorporate into CI/CD pipelines for compliance monitoring
- **Cost tracking**: Use reports to identify optimization opportunities and track storage growth
- **Security auditing**: Leverage security findings for compliance and risk management
- **Organizational governance**: Implement findings as part of cloud governance strategy

## 🔧 Troubleshooting Common Issues

### Cross-Account Access Denied:
```
Error: An error occurred (AccessDenied) when calling the ListBuckets operation
```
**Solution**: Verify each AWS profile has the required S3 permissions and valid credentials.

### CloudWatch Metrics Unavailable:
```
Warning: CloudWatch metrics not available for bucket: example-bucket
```
**Solution**: CloudWatch S3 metrics may take 24-48 hours to become available for new buckets.

### Large Account Timeouts:
```
Warning: Timeout occurred while analyzing account with 500+ buckets
```
**Solution**: Consider analyzing accounts individually or implementing pagination for very large environments.

### Region Access Issues:
```
Error: Could not determine bucket region for: global-bucket-name
```
**Solution**: Ensure the analyzing role has access to all regions where buckets are located.

### Memory Issues with Large Datasets:
```
Error: MemoryError during analysis of account with 10,000+ buckets
```
**Solution**: Run analysis on accounts individually or use a machine with more available memory.

## 💼 Use Cases

- **Enterprise Cloud Governance**: Maintain S3 compliance across complex multi-account organizations
- **Cost Optimization**: Identify storage optimization opportunities at organizational scale
- **Security Auditing**: Regular security posture assessment across all AWS accounts
- **Migration Planning**: Assess current state before large-scale S3 migrations or restructuring
- **Compliance Reporting**: Generate evidence for SOC, PCI, and other compliance frameworks
- **Operational Excellence**: Implement AWS Well-Architected Framework recommendations at scale

## 📊 Output Formats

### Text Report
- Comprehensive formatted analysis with cross-account insights
- Security findings and recommendations
- Visual tables and summaries
- Executive summary for stakeholder reporting

### CSV Export
Structured data export including:
- AccountId, ProfileName, BucketName
- Size metrics, object counts, regional information
- Security configurations (encryption, public access, versioning)
- Cost optimization flags and recommendations
- Lifecycle policy status and storage class distribution

## 🏢 Enterprise Features

- **Multi-account aggregation**: Consolidates data across unlimited AWS accounts
- **Organizational insights**: Cross-account patterns and anomaly detection
- **Governance recommendations**: Enterprise-scale best practices and policies
- **Scalable architecture**: Handles organizations with thousands of buckets
- **Compliance focus**: Designed for audit and regulatory reporting requirements

## 📄 License
MIT License

Made with ❤️ by [pagoha]

---

*This tool is designed for AWS professionals managing complex, multi-account environments who need comprehensive S3 visibility and governance capabilities.*

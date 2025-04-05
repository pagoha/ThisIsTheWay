# 🔍 AWS Unused Resources Scanner

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://www.python.org/)
[![AWS SDK](https://img.shields.io/badge/AWS%20SDK-boto3-orange)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![License](https://img.shields.io/badge/License-MIT-green)](https://opensource.org/license/mit)

A comprehensive scanner to identify unused and potentially costly AWS resources across your accounts.

## 📋 Overview

This tool scans your AWS account for unused resources that might be generating unnecessary costs or creating potential security concerns. It produces a detailed report with:

- A comprehensive summary of findings
- Detailed listings of each unused resource
- Recommendations based on cost optimization and security best practices

## 🔍 Resources Scanned

The scanner checks for unused resources across multiple AWS services:

### 💻 Compute & Storage
- EC2 Instances (stopped)
- EBS Volumes (orphaned)
- AMIs (unused)
- EC2 Key Pairs (unused)
- EBS Snapshots (old/unused)

### 🔄 Networking
- Elastic IPs (unassociated)
- Security Groups (unused)
- NAT Gateways (unused)
- Elastic Network Interfaces (unattached)
- VPCs (empty)
- Load Balancers (idle)

### 🗄️ Storage & Databases
- S3 Buckets (empty)
- S3 Buckets (with old objects)
- RDS Instances (stopped)
- RDS Snapshots (old)
- DynamoDB Tables (idle)
- ElastiCache Clusters (idle)

### ⚙️ Serverless & Containers
- Lambda Functions (unused)
- ECS Services (idle)

### 🔐 Security & Management
- IAM Roles (unused)
- IAM Access Keys (old)
- CloudFormation Stacks (failed/rolled back)
- Elastic Beanstalk Environments (idle)


## ⚙️ Installation

```
Requirements
- Python 3.6+
- AWS credentials configured (either as environment variables, in ~/.aws/credentials, or via an IAM role)
- The following IAM permissions:
-- Read-only permissions for each service being scanned
-- sts:GetCallerIdentity permission
```

Clone this repository:
```bash
git clone https://github.com/yourusername/aws-unused-resources-scanner.git
cd aws-unused-resources-scanner
```
Install required dependencies:
```
pip install boto3
```

## 📝 IAM Permissions
The scanner requires read-only permissions for the services it's checking. A sample IAM policy is provided below:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:ListBucket*",
                "s3:GetBucket*",
                "s3:List*",
                "rds:Describe*",
                "elasticache:Describe*",
                "dynamodb:List*",
                "dynamodb:Describe*",
                "iam:List*",
                "iam:Get*",
                "lambda:List*",
                "lambda:Get*",
                "ecs:List*",
                "ecs:Describe*",
                "elb:Describe*",
                "elasticbeanstalk:Describe*",
                "cloudwatch:GetMetric*",
                "cloudformation:ListStacks",
                "cloudformation:DescribeStacks",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🚀 Usage
When you run the AWSUnusedResourcesChecker.py script, here's the step-by-step flow and the prompts you'll encounter:

Script Launch: You start by running the script with either:
```
python AWSUnusedResourcesChecker.py
```
or specifying a profile:
```
python AWSUnusedResourcesChecker.py --profile your-profile-name
```
AWS Profile Selection:

If you didn't specify a profile with the --profile flag, you'll see this prompt:
```
Enter the AWS profile name to use: 
```
You should enter the name of an AWS profile configured in your ~/.aws/credentials file

Profile Confirmation:

The script will attempt to validate your credentials and show you information about the AWS account:
```
Using AWS profile: your-profile-name
Account: 123456789012
User ARN: arn:aws:iam::123456789012:user/your-username
Scanning Progress:
```

You'll see a message that scanning has begun:
```
Scanning for unused resources. This may take several minutes...
There are no further prompts during the scanning process, but it may take a few minutes to complete depending on the size of your AWS account
```
Results Summary:

When scanning is complete, you'll see a summary of what was found:
```
Unused resources found:
- 2 Unassociated Elastic IPs
- 3 Orphaned EBS Volumes
- 4 Old EBS Snapshots
- 2 Stopped EC2 Instances
...
```
Or if nothing was found:
```
No unused resources found.
```
Report Generation:

The script will automatically generate a detailed report file:
```
Findings have been written to aws_unused_resources_20250322_155236.txt
```
The filename includes the current date and time
There are no other interactive prompts during execution. The only input required from the user is the AWS profile name if it wasn't provided as a command-line argument.

If there are any permission issues or other errors during the scanning process, these will be captured in the final report under the "Errors" section, but they won't interrupt the scanning process.

## 📊 Sample Report
```
# AWS Unused Resources Report
Profile: development-account
Account: 123456789012
Date: 2025-03-22 15:52:36

## SUMMARY
The scan identified the following unused resources that may incur unnecessary costs:
- 2 Unassociated Elastic IPs
- 3 Orphaned EBS Volumes
- 4 Old EBS Snapshots
- 2 Stopped EC2 Instances
- 1 Unused AMIs
- 3 S3 Buckets with Old Objects
- 2 Idle DynamoDB Tables

## DETAILED FINDINGS

Unassociated Elastic IPs:
  - Elastic IP: 52.23.194.12
  - Elastic IP: 34.201.45.89

Orphaned EBS Volumes:
  - Volume ID: vol-0a1b2c3d4e5f67890, Size: 100 GB, Created: 2024-10-15 08:23:45+00:00
  - Volume ID: vol-0123456789abcdef0, Size: 50 GB, Created: 2024-11-02 14:32:09+00:00
  - Volume ID: vol-abcdef0123456789, Size: 200 GB, Created: 2024-09-28 22:15:37+00:00

Old EBS Snapshots:
  - Snapshot ID: snap-0a1b2c3d4e5f67890, Size: 100 GB, Created: 2024-12-15 08:23:45+00:00
  - Snapshot ID: snap-0123456789abcdef0, Size: 50 GB, Created: 2024-10-17 14:32:09+00:00
  - Snapshot ID: snap-abcdef0123456789, Size: 200 GB, Created: 2024-11-23 22:15:37+00:00
  - Snapshot ID: snap-fedcba9876543210, Size: 80 GB, Created: 2024-09-28 11:05:22+00:00

Stopped EC2 Instances:
  - Instance ID: i-0a1b2c3d4e5f67890, Name: test-server, Type: t3.medium
  - Instance ID: i-0123456789abcdef0, Name: dev-environment, Type: t3.large

Unused AMIs:
  - AMI ID: ami-0a1b2c3d4e5f67890, Name: old-application-image, Created: 2024-08-15 10:23:45

S3 Buckets with Old Objects:
  - Bucket: dev-assets-bucket, Last Modified: 2024-11-10 09:12:33+00:00
  - Bucket: legacy-data-backup, Last Modified: 2024-10-05 14:27:19+00:00
  - Bucket: temporary-file-storage, Last Modified: 2024-09-18 22:45:08+00:00

Idle DynamoDB Tables:
  - Table: user_sessions, Size: 25678912 bytes, Items: 12450
  - Table: event_logs, Size: 156782345 bytes, Items: 87632

## RECOMMENDATIONS

1. Cost Optimization:
   - Release unassociated Elastic IPs to avoid unnecessary charges ($0.005/hr per unused IP)
   - Delete orphaned EBS volumes or attach them to instances if needed
   - Consider creating a snapshot lifecycle policy for automated management
   - Evaluate stopped EC2 instances - terminate if no longer needed or consider using Instance Scheduler
   - Consider removing unused AMIs and their associated snapshots
   - Clean up empty S3 buckets or buckets with only old objects
   - Consider reducing capacity or removing idle DynamoDB tables

2. Security Considerations:
   - Regularly review old snapshots to ensure they don't contain sensitive data
   - Implement proper tagging strategy for better resource tracking and security
   - Review security groups rules to ensure principle of least privilege
   - Consider enabling AWS Config to monitor resource configuration changes
   - Ensure S3 buckets have appropriate access controls even if empty

3. Next Steps:
   - Review the scan results with relevant teams
   - Implement resource cleanup following change management processes
   - Consider scheduling this scan to run regularly for ongoing cost optimization
   - Implement resource tagging standards to better track resource ownership
   - Consider using AWS Cost Explorer to identify additional savings
```  

## 🔒 Security Notes
- This tool only performs read-only operations on your AWS account
- No modifications are made to any resources
- Reports are saved locally and not transmitted anywhere
- Consider using a dedicated IAM user/role with read-only permissions for running this tool

## 💡 Benefits
- Cost Optimization: Identify resources that are costing money but providing no value
- Security Enhancement: Discover potential security risks like old access keys or unused IAM roles
- Environment Cleanup: Maintain a clean, well-organized environment by removing unused resources
- Resource Management: Better understand and optimize your AWS infrastructure

## ⚠️ Disclaimer
Always review the resources identified before deletion, as some might be intentionally kept in an "unused" state for valid business reasons.

## 🛠️ Contributing
Contributions are welcome!

## 📄 License
MIT License

Made with ❤️ by [pagoha]

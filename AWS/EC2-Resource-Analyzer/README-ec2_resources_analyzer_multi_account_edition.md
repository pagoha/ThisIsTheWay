# 🚀 AWS EC2 Resources Analyzer - Multi-Account Edition

A comprehensive tool to analyze EC2 instances across multiple AWS accounts and regions. This script provides a detailed inventory of your EC2 resources, including instance details, networking configuration, storage, security groups, load balancer associations, CloudWatch alarms, and more.

## ✨ Features

- **🔄 Multi-Account Support**: Automatically discovers and allows selection of AWS profiles
- **🌎 Multi-Region Scanning**: Scan default regions or specify custom regions
- **⚡ Parallel Processing**: Configurable number of concurrent tasks for faster scanning
- **📊 Comprehensive Data Collection**:
  - Basic instance information (ID, name, state, type)
  - Network details (VPC, subnet, public/private IPs, security groups)
  - Storage information (EBS volumes and snapshots)
  - AMI details
  - Instance tags
  - Network interfaces
  - Elastic IPs
  - Load balancer associations
  - CloudWatch alarms
  - AWS Backup information
- **📁 CSV Export**: All details exported to a timestamped CSV file

## 📋 Prerequisites

- Python 3.6+
- AWS credentials configured (via `~/.aws/credentials` or environment variables)
- Required Python packages:
pip install boto3 pandas configparser


## 🔧 Usage

Simply run the script:

python ec2_resources_analyzer.py


### 💬 Interactive Prompts
```
When running the script, you'll encounter these interactive prompts:

1. **Profile Selection**:
Available AWS profiles:

development
production
testing
sandbox
Select profiles to use (comma-separated numbers, 'all' for all profiles, or 'q' to quit):

2,3


2. **Region Selection**:
Default regions: us-east-1, us-west-2 Use default regions? (y/n, default: y): n Enter the AWS regions separated by commas (e.g., us-east-1,us-west-2): us-east-1,eu-west-1,ap-southeast-2


3. **Concurrency Configuration**:
Enter maximum parallel tasks (default: 10): 6
```

### 📝 Example Run
```
AWS EC2 Resources Analyzer - Multi-Account Edition
Available AWS profiles:

1. development
2. production
3. testing
4. sandbox
Select profiles to use (comma-separated numbers, 'all' for all profiles, or 'q' to quit):

2,3

Selected 2 AWS accounts:

production (123456789012)
testing (210987654321)
Default regions: us-east-1, us-west-2
Use default regions? (y/n, default: y): n
Enter the AWS regions separated by commas (e.g., us-east-1,us-west-2): us-east-1,eu-west-1,ap-southeast-2

Selected regions: us-east-1, eu-west-1, ap-southeast-2

Gathering EC2 instance details for 2 accounts across 3 regions

Enter maximum parallel tasks (default: 10): 6

Processing production (123456789012) in region us-east-1...
Processing testing (210987654321) in region us-east-1...
Processing production (123456789012) in region eu-west-1...
Processing testing (210987654321) in region eu-west-1...
Processing production (123456789012) in region ap-southeast-2...
Processing testing (210987654321) in region ap-southeast-2...

Found 37 instances across all accounts and regions

EC2 instance details from all accounts exported to ec2_resources_analyzer_multi_account_20250322_143045.csv
```

## 📊 Output Format

The script generates a detailed CSV file containing all EC2 instance information across selected accounts and regions. Here's a sample of what the report contains:

| Account | Account ID | Region | Instance ID | Name | State | Instance Type | Public IP | Private IP | Launch Time | VPC ID | Subnet ID | AMI ID | AMI Name | Security Groups | EBS Volumes | Associated Snapshots | Elastic IPs | Network Interfaces | Associated Backups | Load Balancer Targets | CloudWatch Alarms | Tags |
|---------|------------|--------|------------|------|-------|--------------|-----------|------------|-------------|--------|-----------|--------|----------|-----------------|-------------|---------------------|-------------|-------------------|-------------------|----------------------|-------------------|------|
| production (123456789012) | 123456789012 | us-east-1 | i-0a1b2c3d4e5f6g7h8 | web-server-01 | running | t3.medium | 54.123.45.67 | 10.0.1.15 | 2024-11-05 15:30:22+00:00 | vpc-12345678 | subnet-abcdef12 | ami-0abc12345def | amzn2-ami-hvm-2.0.20240301.0-x86_64 | sg-0a1b2c3d (web-servers) | vol-0a1b2c3d (100 GB, gp3) | snap-0a1b2c3d (Volume: vol-0a1b2c3d, 2025-03-18 08:15:00+00:00) | 54.123.45.67 (eipalloc-0a1b2c3d) | eni-0a1b2c3d (10.0.1.15) | No backups | prod-web-tg (arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/prod-web-tg/abcdef1234567890) | CPUAlarmHigh, StatusCheckFailed | Name: web-server-01 &#124; Environment: prod &#124; Service: web |
| production (123456789012) | 123456789012 | us-east-1 | i-1a2b3c4d5e6f7g8h9 | db-server-01 | running | r5.large | N/A | 10.0.2.25 | 2024-10-12 03:45:11+00:00 | vpc-12345678 | subnet-12345def | ami-0def45678abc | amzn2-ami-hvm-2.0.20240301.0-x86_64 | sg-1a2b3c4d (db-servers) | vol-1a2b3c4d (500 GB, io2) | snap-1a2b3c4d (Volume: vol-1a2b3c4d, 2025-03-21 02:00:00+00:00) | N/A | eni-1a2b3c4d (10.0.2.25) | arn:aws:backup:us-east-1:123456789012:recovery-point:abcdef (2025-03-21T02:00:00Z) | N/A | DBHighMemoryUsage, DBHighCPU | Name: db-server-01 &#124; Environment: prod &#124; Service: database &#124; BackupSchedule: daily |
| testing (210987654321) | 210987654321 | eu-west-1 | i-2a3b4c5d6e7f8g9h0 | test-api-server | running | t3.large | 18.45.67.89 | 172.16.1.45 | 2025-02-18 09:12:33+00:00 | vpc-87654321 | subnet-21fedcba | ami-9876abcd | ubuntu-focal-20.04-amd64-server | sg-2a3b4c5d (api-servers) | vol-2a3b4c5d (80 GB, gp2) | No snapshots | 18.45.67.89 (eipalloc-2a3b4c5d) | eni-2a3b4c5d (172.16.1.45) | No backups | test-api-tg (arn:aws:elasticloadbalancing:eu-west-1:210987654321:targetgroup/test-api-tg/0987654321abcdef) | No alarms | Name: test-api-server &#124; Environment: test &#124; Owner: DevTeam |

## 🎯 Use Cases

- **📚 Resource Inventory**: Complete account-wide view of all EC2 instances
- **✅ Compliance Auditing**: Details on security groups, encryption, and backups
- **💰 Cost Optimization**: Identify instance types, unused instances, etc.
- **🛡️ Disaster Recovery Planning**: See which instances have backups and snapshots
- **🔒 Security Assessment**: Understand network exposure via public IPs and security groups

## ⚠️ Limitations

- The script requires appropriate IAM permissions across all accounts to access EC2, ELB, CloudWatch, and AWS Backup services
- For large environments with many instances, the scan may take some time to complete
- The AWS Backup information may be limited depending on IAM permissions

## 📄 License

[MIT License](LICENSE)

## 👥 Contributing

Contributions are welcome!

## 👨‍💻 Author

Made with ❤️ by [pagoha]

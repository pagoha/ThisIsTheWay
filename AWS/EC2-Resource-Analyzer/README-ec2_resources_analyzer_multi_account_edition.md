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

Below is a sample output from the AWS EC2 Resources Analyzer - Multi-Account Edition script (showing key columns for readability):

| Account | Account ID | Region | Instance ID | Name | State | Instance Type | Tag_Environment | Tag_Owner | Tag_Project |
|---------|------------|--------|------------|------|-------|---------------|----------------|-----------|------------|
| dev (123456789012) | 123456789012 | us-east-1 | i-0abc123def456789 | web-server-01 | running | t3.medium | production | devops-team | website |
| dev (123456789012) | 123456789012 | us-east-1 | i-1def456ghi789012 | db-server-01 | running | r5.large | production | db-team | database |
| prod (987654321098) | 987654321098 | us-west-2 | i-9xyz876wvu54321 | api-server-03 | stopped | c5.xlarge | staging | dev-team | api |
| prod (987654321098) | 987654321098 | us-west-2 | i-3abc456def789012 | cache-01 | running | r6g.xlarge | production | infra-team | cache |

## Complete Data Export

The actual CSV export includes many more columns with detailed information about each instance:

- Basic instance details (ID, type, state, etc.)
- Individual columns for each tag (Tag_Name, Tag_Environment, Tag_Project, etc.)
- AMI information (ID, name)
- Networking details (IPs, VPC, subnet, security groups)
- Storage information (EBS volumes and snapshots)
- Associated resources (Elastic IPs, load balancer targets)
- Monitoring and backup data (CloudWatch alarms, AWS Backup recovery points)

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

MIT License

## 👥 Contributing

Contributions are welcome!



Made with ❤️ by [pagoha]

# EC2 Resource Analyzer

![Version](https://img.shields.io/badge/version-Jan%202025-blue)
![Language](https://img.shields.io/badge/language-Python-green)
![AWS](https://img.shields.io/badge/AWS-EC2%20Analysis-orange)

A comprehensive AWS EC2 resource analysis tool that collects detailed information about EC2 instances and their associated resources in a specified AWS region.

## 📋 Overview

This tool provides a detailed inventory of EC2 resources for:
- Infrastructure auditing
- Compliance monitoring
- Cost optimization
- Resource management

## 🚀 Features

### Core Capabilities

- **EC2 Instance Details**: Instance ID, State, Type, IPs, Launch Time, VPC/Subnet IDs, Tags
- **AMI Information**: AMI ID, AMI Name for each instance
- **Security Groups**: Complete listing of all associated security groups
- **Storage Resources**: 
  - EBS Volumes with ID, size, and type
  - Snapshots linked to attached volumes
- **Network Configuration**:
  - Elastic IPs associated with instances
  - Network interfaces with IDs and IP addresses
- **Backup & Recovery**: AWS Backup recovery points linked to the instance
- **Load Balancing**: Identification of ALB/NLB target registrations
- **Monitoring**: Associated CloudWatch alarms for CPU utilization metrics

### Output & Processing

- Structured data compilation with relationship mapping
- CSV export with region and timestamp in filename
- Interactive region selection via command prompt

## 📦 Prerequisites

```bash
pip install boto3 pandas
```

## 🔧 Usage

Run the script and follow the prompts:
python EC2_Resource_Analyzer.py

When prompted, enter your target AWS region (e.g., us-east-1).

## 📊 Output
The script exports all collected data to a CSV file with naming format:
ec2_resource_analysis_{region}_{timestamp}.csv

It would look similar to this:
```
| Instance ID        | State   | Instance Type | Public IP     | Private IP | Launch Time            | VPC ID             | Subnet ID            | Tags                          | AMI ID              | AMI Name                  | Security Groups                    | EBS Volumes                      | Associated Snapshots             | Elastic IPs                      | Network Interfaces              | Associated Backups               | Load Balancer Targets           | CloudWatch Alarms               |
|--------------------|---------|---------------|---------------|------------|------------------------|--------------------|-----------------------|-------------------------------|---------------------|---------------------------|------------------------------------|---------------------------------|----------------------------------|----------------------------------|----------------------------------|----------------------------------|----------------------------------|----------------------------------|
| i-0abc123def456789a | running | t3.medium    | 54.211.123.45 | 10.0.1.25 | 2024-09-15 14:32:10   | vpc-0a1b2c3d4e5f6789 | subnet-0123abcd4567efgh | Name:WebServer,Env:Production | ami-0abcdef1234567890 | amzn2-ami-hvm-5.10-x86_64 | sg-01234abcdef56789 (web-server) | vol-01a2b...7890 (100 GB, gp3) | snap-0a1b2...7890 (2025-03-23)   | 54.211.123.45 (eip-0abc123def) | eni-01234...789 (10.0.1.25)    | arn:aws:backup:...5o6p (03-22) | web-app-tg (arn:aws:elb:...890) | CPU-High, StatusCheckFailed     |
| i-0def456789abc123b | running | m5.large     | N/A           | 10.0.3.45 | 2025-01-10 09:15:22   | vpc-0a1b2c3d4e5f6789 | subnet-9876fedc5432abcd | Name:AppServer,Env:Production | ami-0fedcba9876543210 | custom-app-server-v1.2.3  | sg-abcdef1234567890 (app-server) | vol-abcde...890 (120 GB, gp3)  | snap-9876...dcba (2025-03-20)    | N/A                            | eni-abcdef...890 (10.0.3.45)   | arn:aws:backup:...9o (03-21)   | app-tg (arn:aws:elb:...def)     | MemoryUtilization-High          |
| i-0123456789abcdef0 | stopped | r5.xlarge    | N/A           | 10.0.2.30 | 2024-11-05 22:05:33   | vpc-0a1b2c3d4e5f6789 | subnet-1234abcd5678efgh | Name:DBServer,Env:Staging     | ami-0123456789abcdef0 | postgres-custom-image-12.9 | sg-0123456789abcdef0 (db-server) | vol-01234...f0 (200 GB, gp3)   | snap-01234...f0 (2025-03-24)     | N/A                            | eni-01234...f0 (10.0.2.30)     | Error: Access denied            | No alarms                       | No alarms                       |

```

## 🔍 How It Works
Connection: Establishes connection to AWS services using boto3
Data Collection: Gathers information about EC2 instances and related resources
Association: Links resources to their parent EC2 instances
Export: Formats and exports all data to CSV

## ⚙️ AWS Services Utilized
Amazon EC2
Amazon EBS
AWS Backup
Elastic Load Balancing
Amazon CloudWatch

## 🛡️ Security Note
Ensure your AWS credentials have appropriate read-only permissions to the required services.

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

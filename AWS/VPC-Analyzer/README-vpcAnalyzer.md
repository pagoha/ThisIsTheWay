# 🌐 AWS VPC Analyzer

## 📝 Description

[vpcAnalyzer.py] is a comprehensive Python script designed to provide detailed information about AWS VPC (Virtual Private Cloud) environments and their associated networking components. This tool is invaluable for AWS administrators, DevOps engineers, and cloud architects who need to audit, document, or troubleshoot their AWS network infrastructure.

## ✨ Features

- 🔄 Interactive AWS profile selection
- 🔒 Account verification for security
- 📊 Comprehensive data gathering on VPC components including:
  - VPCs
  - Subnets
  - Route Tables
  - Internet Gateways
  - NAT Gateways
  - VPC Peering Connections
  - VPC Endpoints
  - Network ACLs
  - Security Groups
  - Flow Logs
  - EC2 Instances within subnets
- 🏷️ Display of resource names alongside AWS resource IDs
- 📋 Formatted console output for easy reading
- 📄 Text file output for complete report archiving
- 📊 JSON file output for programmatic analysis

## 🔧 Prerequisites

- Python 3.6+
- AWS CLI configured with appropriate credentials
- boto3 library

## 🚀 Installation

1. Clone this repository:

2. Install required Python packages:
```
pip install boto3
```

3. Ensure your AWS CLI is configured with the necessary credentials:
```
aws configure
```

## 💻 Usage

Run the script from the command line:
```
python vpcAnalyzer.py
```

Follow the interactive prompts to select your AWS profile and confirm the account details.

## 📂 Output

The script generates two files:

1. `vpc_report_ACCOUNTID_TIMESTAMP.txt`: A human-readable text report of all VPC information.
2. `vpc_information_ACCOUNTID_TIMESTAMP.json`: A JSON file containing structured data of all VPC information.

Both files are named with the AWS account ID and a timestamp for easy identification and versioning.

## Sample Output of AWS VPC Info Report
```
================================================================================
                        AWS VPC INFORMATION REPORT
                          Account ID: 123456789012
             Generated at: 2023-05-21 15:30:45
================================================================================

===================== VPC: Main-Production-VPC (vpc-0a1b2c3d4e5f67890) =====================
CIDR Block: 10.0.0.0/16
State: available
Is Default: False
Instance Tenancy: default
DHCP Options ID: dopt-0a1b2c3d4e5f67890
DNS Support: Enabled
DNS Hostnames: Enabled

DHCP Options:
  domain-name-servers: AmazonProvidedDNS
  domain-name: ec2.internal

VPC Tags:
  - Name: Main-Production-VPC
  - Environment: Production
  - Project: E-commerce Platform

Internet Gateway: Main-IGW (igw-0a1b2c3d4e5f67890)

NAT Gateways (2):
  1. NAT Gateway: NAT-GW-AZ1 (nat-0a1b2c3d4e5f67890)
     State: available
     Subnet ID: subnet-0a1b2c3d4e5f67890
     Public IP: 34.xxx.xxx.xxx
     Private IP: 10.0.1.123
  2. NAT Gateway: NAT-GW-AZ2 (nat-1a2b3c4d5e6f78901)
     State: available
     Subnet ID: subnet-1a2b3c4d5e6f78901
     Public IP: 52.xxx.xxx.xxx
     Private IP: 10.0.2.123

VPC Endpoints (1):
  1. Endpoint: S3-Gateway (vpce-0a1b2c3d4e5f67890)
     Type: Gateway
     Service Name: com.amazonaws.us-west-2.s3
     State: available

VPC Peering Connections (1):
  1. Peering: Prod-to-Dev-Peering (pcx-0a1b2c3d4e5f67890)
     Status: active
     Accepter VPC: vpc-1a2b3c4d5e6f78901 (172.31.0.0/16)
     Requester VPC: vpc-0a1b2c3d4e5f67890 (10.0.0.0/16)

VPC Flow Logs (1):
  1. Flow Log ID: fl-0a1b2c3d4e5f67890
     Log Destination: arn:aws:s3:::vpc-flow-logs-bucket/AWSLogs/123456789012/
     Log Format: ${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}
     Traffic Type: ALL
     Deliver Logs Status: ACTIVE

Network ACLs (2):
  1. Network ACL: Main-NACL (acl-0a1b2c3d4e5f67890)
     Is Default: true
     Inbound Rules (2):
       - Rule #100: 0.0.0.0/0 -1 * allow
       - Rule #32767: 0.0.0.0/0 -1 * deny
     Outbound Rules (2):
       - Rule #100: 0.0.0.0/0 -1 * allow
       - Rule #32767: 0.0.0.0/0 -1 * deny
     Associated Subnets:
       - subnet-0a1b2c3d4e5f67890
       - subnet-1a2b3c4d5e6f78901
  2. Network ACL: Restricted-NACL (acl-1a2b3c4d5e6f78901)
     Is Default: false
     Inbound Rules (3):
       - Rule #100: 10.0.0.0/8 -1 * allow
       - Rule #200: 0.0.0.0/0 tcp 443 allow
       - Rule #32767: 0.0.0.0/0 -1 * deny
     Outbound Rules (2):
       - Rule #100: 0.0.0.0/0 -1 * allow
       - Rule #32767: 0.0.0.0/0 -1 * deny
     Associated Subnets:
       - subnet-2a3b4c5d6e7f89012

Security Groups (3):
  1. Web-Servers-SG (sg-0a1b2c3d4e5f67890)
     Description: Security group for web servers
     Inbound Rules: 2
     Outbound Rules: 1
  2. App-Servers-SG (sg-1a2b3c4d5e6f78901)
     Description: Security group for application servers
     Inbound Rules: 3
     Outbound Rules: 1
  3. Database-SG (sg-2a3b4c5d6e7f89012)
     Description: Security group for database instances
     Inbound Rules: 1
     Outbound Rules: 1

---------------------------------- SUBNETS ----------------------------------

  1. Subnet: Public-Subnet-AZ1 (subnet-0a1b2c3d4e5f67890)
     CIDR Block: 10.0.1.0/24
     Availability Zone: us-west-2a (usw2-az1)
     State: available
     Available IPs: 251
     Auto-assign Public IP: Yes
     Default for AZ: No
     IPv6 CIDR Blocks:
       - 2600:1f16:831:2101::/64 (associated)
     Auto-assign IPv6: Yes
     Tags:
       - Tier: Public
       - AZ: us-west-2a
     Network ACL: Main-NACL (acl-0a1b2c3d4e5f67890)
     Route Table: Public-RT (rtb-0a1b2c3d4e5f67890)
     Routes:
       1. Destination: 0.0.0.0/0 (IPv4)
          Target: igw-0a1b2c3d4e5f67890 (Internet Gateway)
          State: active
          Origin: CreateRoute
       2. Destination: 10.0.0.0/16 (IPv4)
          Target: local (Local)
          State: active
          Origin: CreateRouteTable
       3. Destination: ::/0 (IPv6)
          Target: igw-0a1b2c3d4e5f67890 (Internet Gateway)
          State: active
          Origin: CreateRoute
     Instances (2):
       1. Web-Server-1 (i-0a1b2c3d4e5f67890)
          Type: t3.medium
          Private IP: 10.0.1.10
          Public IP: 34.xxx.xxx.xxx
          State: running
       2. Web-Server-2 (i-1a2b3c4d5e6f78901)
          Type: t3.medium
          Private IP: 10.0.1.11
          Public IP: 52.xxx.xxx.xxx
          State: running

  2. Subnet: Private-Subnet-AZ1 (subnet-1a2b3c4d5e6f78901)
     CIDR Block: 10.0.2.0/24
     Availability Zone: us-west-2a (usw2-az1)
     State: available
     Available IPs: 251
     Auto-assign Public IP: No
     Default for AZ: No
     Tags:
       - Tier: Private
       - AZ: us-west-2a
     Network ACL: Main-NACL (acl-0a1b2c3d4e5f67890)
     Route Table: Private-RT-AZ1 (rtb-1a2b3c4d5e6f78901)
     Routes:
       1. Destination: 0.0.0.0/0 (IPv4)
          Target: nat-0a1b2c3d4e5f67890 (NAT Gateway)
          State: active
          Origin: CreateRoute
       2. Destination: 10.0.0.0/16 (IPv4)
          Target: local (Local)
          State: active
          Origin: CreateRouteTable
     Instances (1):
       1. App-Server-1 (i-2a3b4c5d6e7f89012)
          Type: c5.large
          Private IP: 10.0.2.10
          State: running

  [Additional subnets would be listed here...]

================================================================================
```

This sample report showcases:
- General VPC information including CIDR blocks, DNS settings, and tags.
- Internet Gateway details.
- NAT Gateways with their states and IP addresses.
- VPC Endpoints.
- VPC Peering Connections.
- Flow Logs configuration.
- Network ACLs with their inbound and outbound rules.
- Security Groups summary.
- Detailed Subnet information including:
- CIDR blocks and IPv6 information
- Availability Zone
- Network ACL association
- Route Table details with routes
- EC2 instances within the subnet

The actual report would be more extensive, especially for accounts with multiple VPCs or more complex networking setups. The JSON output would contain all of this information in a structured format, making it easy to parse and analyze programmatically.

## 📄 License
MIT License

## 👥 Contributing
Contributions are welcome!

Made with ❤️ by [pagoha]

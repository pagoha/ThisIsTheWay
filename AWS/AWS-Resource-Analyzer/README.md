# AWS Resource Analyzer

A comprehensive AWS resource inventory and analysis tool that discovers and catalogs AWS resources across multiple accounts and regions. Built for cloud infrastructure auditing, security assessments, cost optimization, and compliance reporting at enterprise scale.

## Overview

The AWS Resource Analyzer provides a unified, detailed view of your AWS infrastructure by scanning multiple AWS accounts and regions simultaneously. It inventories **31 different AWS resource types** across all major service categories and presents results in multiple formats for analysis, reporting, and optimization.

## Features

- **🔍 Comprehensive Coverage**: 31 AWS resource types across compute, storage, networking, security, and management services
- **🏢 Multi-Account Support**: Scan across multiple AWS profiles simultaneously with validation
- **🌍 Multi-Region Coverage**: Support for all AWS regions including US Gov regions (`us-gov-east-1`, `us-gov-west-1`)
- **⚡ Parallel Execution**: Multi-threaded scanning for fast results across large infrastructures
- **📊 Multiple Output Formats**: Table, JSON, and CSV output with detailed resource information
- **🖥️ Interactive & CLI Modes**: User-friendly interactive selection or full command-line automation
- **💰 Cost Optimization Focus**: Identifies unattached resources, oversized instances, and potential savings
- **🔒 Security & Compliance**: Security groups, IAM analysis, encryption keys, and audit trails
- **📈 Summary Analytics**: Resource counts, trends, and optimization recommendations

## Supported AWS Resources (31 Types)

### **Compute & Container Services**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **EC2** | Instances (Name, ID, Type, State) | ✅ Instance right-sizing |
| **Lambda** | Functions (Name, Runtime, State, Size) | ✅ Function optimization |
| **ECS** | Clusters (Name, Status, Tasks, Services) | ✅ Container utilization |
| **EKS** | Kubernetes Clusters (Name, Status, Version) | ✅ Cluster optimization |
| **Auto Scaling** | Groups (Min/Max/Desired/Current capacity) | ✅ Scaling optimization |

### **Storage Services**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **EBS** | Volumes (Name, ID, Size, Type, Attachment Status) | ✅ **Unattached volume cleanup** |
| **EBS Snapshots** | Snapshots (ID, Age, Size, Source Volume) | ✅ **Old snapshot cleanup** |
| **S3** | Buckets (Name, Creation Date, Region) | ✅ Lifecycle optimization |
| **EFS** | File Systems (Name, ID, State, Size) | ✅ Usage optimization |

### **Database Services**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **RDS** | Instances (ID, Class, Status, Engine, Storage) | ✅ Instance right-sizing |
| **RDS Snapshots** | Snapshots (ID, Age, Size, Source DB) | ✅ **Snapshot cleanup** |
| **DynamoDB** | Tables (Name, Status, Billing Mode, Items) | ✅ Capacity optimization |
| **ElastiCache** | Clusters (ID, Engine, Status, Node Type) | ✅ **Cluster utilization** |

### **Networking & Content Delivery**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **VPC** | Virtual Private Clouds (Name, ID, CIDR, State) | ✅ Unused VPC cleanup |
| **Subnets** | Subnets (Name, ID, VPC, CIDR, AZ, Type) | ✅ Network optimization |
| **Security Groups** | Groups (Name, ID, VPC, Rule Counts) | 🔒 Security analysis |
| **Route Tables** | Tables (Name, ID, VPC, Routes, Associations) | 🔒 Network security |
| **Internet Gateways** | Gateways (Name, ID, Attachments) | ✅ Unused gateway cleanup |
| **NAT Gateways** | Gateways (Name, ID, State, Subnet, Type) | ✅ **High-cost resource** |
| **Elastic IPs** | Addresses (IP, Allocation ID, Attachment Status) | ✅ **Unattached IP cleanup** |
| **Load Balancers** | ALB/NLB (Name, Type, State, Target Groups) | ✅ **Unused LB cleanup** |
| **Classic Load Balancers** | CLB (Name, Scheme, Instances, AZs) | ✅ **Legacy LB cleanup** |
| **CloudFront** | Distributions (ID, Domain, Status, Origin) | ✅ Distribution optimization |
| **Route 53** | Hosted Zones (Domain, ID, Type, Records) | ✅ DNS optimization |

### **Application Integration**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **API Gateway** | APIs (Name, ID, Type, Created Date) | ✅ **Unused API cleanup** |
| **SNS** | Topics (Name, ARN, Subscription Count) | ✅ Usage optimization |
| **SQS** | Queues (Name, URL, Messages, Configuration) | ✅ Queue optimization |

### **Management & Governance**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **CloudFormation** | Stacks (Name, Status) | 🔒 Infrastructure tracking |
| **CloudTrail** | Trails (Name, Type, Status, S3 Bucket) | 🔒 Audit compliance |
| **CloudWatch Logs** | Log Groups (Name, Retention, Size) | ✅ **Log retention costs** |
| **CloudWatch Alarms** | Alarms (Name, State, Metric, Actions) | ✅ Monitoring optimization |

### **Security & Identity**
| Service | Resources Inventoried | Cost Optimization Value |
|---------|----------------------|-------------------------|
| **IAM Users** | Users (Name, ID, Created, Last Used) | 🔒 Access management |
| **IAM Roles** | Roles (Name, Created, Description) | 🔒 Permission analysis |
| **IAM Policies** | Custom Policies (Name, ID, Attachments) | 🔒 Policy optimization |
| **KMS** | Customer Keys (Description, ID, Usage, State) | 🔒 Encryption management |

**Legend**: ✅ = Cost Optimization Focus | 🔒 = Security & Compliance Focus

## Prerequisites

- **Python 3.6+**
- **AWS CLI** configured with appropriate profiles
- **Required Python packages**:
  ```bash
  pip install boto3 tabulate
  ```

## Installation

1. **Download the script**:
   ```bash
   curl -O https://raw.githubusercontent.com/your-org/aws-resource-analyzer/main/aws_resource_analyzer.py
   chmod +x aws_resource_analyzer.py
   ```

2. **Install dependencies**:
   ```bash
   pip install boto3 tabulate
   ```

3. **Verify AWS CLI configuration**:
   ```bash
   aws configure list-profiles
   ```

## Usage

### Interactive Mode (Recommended)

Run the tool interactively for guided profile and region selection:

```bash
python3 aws_resource_analyzer.py
```

**Example Interactive Session:**
```
Available AWS profiles:
1. default
2. production  
3. staging
4. govcloud-east

Profile selection options:
- Enter profile numbers separated by commas (e.g., 1,3,5)
- Enter ranges with dashes (e.g., 1-5)
- Enter profile names separated by commas (e.g., prod,staging,dev)
- Enter 'all' to select all profiles
- Press Enter to select default profile only

Enter your selection: 2,3

Validating 2 profile(s)...
[OK] production: Account 123456789012
[OK] staging: Account 123456789013

Found 2 valid account(s):
  - Profile: production | Account: 123456789012
  - Profile: staging | Account: 123456789013

Proceed with analysis of these 2 account(s)? (yes/no): yes

Available AWS Regions (24 total):
------------------------------------------------------------
 1. af-south-1           2. ap-east-1            3. ap-northeast-1
 4. ap-northeast-2       5. ap-northeast-3       6. ap-south-1
 7. ap-southeast-1       8. ap-southeast-2       9. ca-central-1
10. eu-central-1        11. eu-north-1          12. eu-south-1
13. eu-west-1           14. eu-west-2           15. eu-west-3
16. me-south-1          17. sa-east-1           18. us-east-1
19. us-east-2           20. us-gov-east-1       21. us-gov-west-1
22. us-west-1           23. us-west-2           24. us-west-3

Region selection options:
- Enter region numbers separated by commas (e.g., 1,5,10)
- Enter ranges with dashes (e.g., 1-5)
- Enter region names separated by commas (e.g., us-east-1,eu-west-1)
- Enter 'all' to select all regions
- Enter 'common' for common regions (us-east-1, us-west-2, eu-west-1)
- Enter 'gov' for US Gov regions (us-gov-east-1, us-gov-west-1)
- Press Enter to select us-east-1 only

Enter your selection: common

Selected 5 region(s):
  - us-east-1
  - us-west-2
  - eu-west-1
  - ap-southeast-1
  - ap-northeast-1

Starting comprehensive inventory across 2 account(s) and 5 region(s)...
Resource types (31): cloudformation, ec2, security_groups, vpc, subnets, route_tables...
Using 10 threads for parallel execution

✅ Completed 1/10: production (123456789012) - us-east-1
✅ Completed 2/10: staging (123456789013) - us-east-1
✅ Completed 3/10: production (123456789012) - us-west-2
...
```

### Command Line Mode

Use command-line arguments for automated execution:

```bash
# Quick scan of specific profiles and regions
python3 aws_resource_analyzer.py --profiles prod,staging --regions us-east-1,us-west-2

# Cost optimization focus - high-impact resources
python3 aws_resource_analyzer.py --resources "nat_gateways,load_balancers,ebs_snapshots,rds_snapshots,eip,elasticache"

# Security audit focus
python3 aws_resource_analyzer.py --resources "security_groups,iam,kms,cloudtrail"

# US Government regions only
python3 aws_resource_analyzer.py --profiles govcloud-profile --regions gov

# Export comprehensive results to JSON
python3 aws_resource_analyzer.py --profiles prod --output-format json --output-file inventory.json

# Network infrastructure analysis
python3 aws_resource_analyzer.py --resources "vpc,subnets,security_groups,route_tables,nat_gateways,load_balancers"

# Storage and backup analysis
python3 aws_resource_analyzer.py --resources "ebs,ebs_snapshots,s3,rds,rds_snapshots,efs"

# Scan all regions with higher thread count for large environments
python3 aws_resource_analyzer.py --profiles prod --regions all --threads 20
```

### Resource Type Selection

**List all available resource types:**
```bash
python3 aws_resource_analyzer.py --list-resources
```

**Resource Categories:**
```bash
# Compute resources
--resources "ec2,lambda,ecs,eks,auto_scaling_groups"

# Storage resources  
--resources "ebs,ebs_snapshots,s3,efs"

# Database resources
--resources "rds,rds_snapshots,dynamodb,elasticache"

# Networking resources
--resources "vpc,subnets,security_groups,route_tables,internet_gateways,nat_gateways,eip,load_balancers"

# Application services
--resources "api_gateway,sns,sqs,cloudfront,route53"

# Management & governance
--resources "cloudformation,cloudtrail,cloudwatch_logs,cloudwatch_alarms"

# Security & identity
--resources "iam,kms"
```

### Command Line Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--profiles` | Comma-separated AWS profiles | Interactive | `prod,staging,dev` |
| `--regions` | Regions (`all`, `common`, `gov`, or specific) | Interactive | `us-east-1,eu-west-1` |
| `--resources` | Resource types (`all` or specific types) | `all` | `ec2,rds,s3` |
| `--output-format` | Output format: `table`, `json`, `csv` | `table` | `json` |
| `--output-file` | File path to save results | stdout | `inventory.json` |
| `--threads` | Parallel execution threads | `10` | `20` |
| `--list-resources` | Show all available resource types | - | - |

## Sample Output

### Table Format (Default)
```
📍 Profile: production | Account: 123456789012 | Region: us-east-1
================================================================================

CloudFormation Stacks:
┌─────────────────────────┬─────────────────┐
│ StackName               │ StackStatus     │
├─────────────────────────┼─────────────────┤
│ web-application-stack   │ CREATE_COMPLETE │
│ database-stack          │ UPDATE_COMPLETE │
│ monitoring-stack        │ CREATE_COMPLETE │
└─────────────────────────┴─────────────────┘

EC2 Instances:
┌──────────────────┬─────────────────────┬─────────────┬─────────┐
│ Name             │ InstanceId          │ InstanceType│ State   │
├──────────────────┼─────────────────────┼─────────────┼─────────┤
│ web-server-1     │ i-0123456789abcdef0 │ t3.medium   │ running │
│ web-server-2     │ i-0987654321fedcba0 │ t3.medium   │ running │
│ database-server  │ i-0abcdef123456789  │ r5.large    │ running │
└──────────────────┴─────────────────────┴─────────────┴─────────┘

NAT Gateways:
┌─────────────┬─────────────────────────┬───────────┬─────────────────────────┬────────┐
│ Name        │ NatGatewayId            │ State     │ SubnetId                │ Type   │
├─────────────┼─────────────────────────┼───────────┼─────────────────────────┼────────┤
│ prod-nat-1  │ nat-0123456789abcdef0   │ available │ subnet-0123456789abcdef │ public │
│ prod-nat-2  │ nat-0987654321fedcba0   │ available │ subnet-0987654321fedcba │ public │
└─────────────┴─────────────────────────┴───────────┴─────────────────────────┴────────┘

Elastic IPs:
┌──────────────┬─────────────────────────┬────────────┬─────────────────────┐
│ PublicIp     │ AllocationId            │ Status     │ AttachedTo          │
├──────────────┼─────────────────────────┼────────────┼─────────────────────┤
│ 54.123.45.67 │ eipalloc-0123456789abc  │ Attached   │ nat-0123456789abcdef│
│ 54.123.45.68 │ eipalloc-0987654321fed  │ Unattached │ N/A                 │
└──────────────┴─────────────────────────┴────────────┴─────────────────────┘
```

### JSON Format
```json
{
  "timestamp": "2024-01-15T10:30:45.123456+00:00",
  "results": [
    {
      "profile": "production",
      "account_id": "123456789012",
      "region": "us-east-1", 
      "resources": {
        "ec2": [
          ["web-server-1", "i-0123456789abcdef0", "t3.medium", "running"],
          ["web-server-2", "i-0987654321fedcba0", "t3.medium", "running"]
        ],
        "nat_gateways": [
          ["prod-nat-1", "nat-0123456789abcdef0", "available", "subnet-0123456789abcdef", "public"]
        ],
        "eip": [
          ["54.123.45.67", "eipalloc-0123456789abc", "Attached", "nat-0123456789abcdef"],
          ["54.123.45.68", "eipalloc-0987654321fed", "Unattached", "N/A"]
        ]
      }
    }
  ]
}
```

### Summary Analytics
```
================================================================================
INVENTORY SUMMARY
================================================================================
Total resources discovered: 1,247
Account-region combinations processed: 10

Top resource types by count:
  Security Groups: 156
  Subnets: 89
  EBS Volumes: 78
  Lambda Functions: 67
  CloudWatch Log Groups: 54
  EC2 Instances: 45
  EBS Snapshots: 34
  Route Tables: 28
  Load Balancers: 23
  RDS Instances: 12

================================================================================
Inventory completed successfully!
================================================================================
```

## Cost Optimization Use Cases

### 1. **High-Impact Cost Cleanup**
```bash
# Focus on expensive resources that are often left unused
python3 aws_resource_analyzer.py \
  --resources "nat_gateways,load_balancers,classic_load_balancers,elasticache" \
  --output-format csv --output-file high_cost_resources.csv
```

**Potential Monthly Savings:**
- Unused NAT Gateway: **$32-45/month each**
- Unused Load Balancer: **$16-25/month each**  
- Unused ElastiCache cluster: **$50-500+/month each**

### 2. **Storage Optimization**
```bash
# Identify storage waste and cleanup opportunities
python3 aws_resource_analyzer.py \
  --resources "ebs,ebs_snapshots,rds_snapshots,cloudwatch_logs" \
  --regions common
```

**Look for:**
- Unattached EBS volumes
- Old snapshots (>30 days)
- Log groups with long retention
- Large unused storage

### 3. **Network Cost Analysis**
```bash
# Analyze network resources and data transfer costs
python3 aws_resource_analyzer.py \
  --resources "nat_gateways,eip,load_balancers,cloudfront" \
  --profiles prod,staging
```

**Optimization Opportunities:**
- Unattached Elastic IPs (**$3.65/month each**)
- Unused load balancers
- NAT Gateway utilization
- CloudFront distribution optimization

## Security & Compliance Use Cases

### 1. **Security Posture Assessment**
```bash
# Comprehensive security resource inventory
python3 aws_resource_analyzer.py \
  --resources "iam,security_groups,kms,cloudtrail" \
  --output-format json --output-file security_audit.json
```

### 2. **Network Security Analysis**
```bash
# Network security and access control review
python3 aws_resource_analyzer.py \
  --resources "security_groups,route_tables,internet_gateways,nat_gateways" \
  --regions all
```

### 3. **Access Management Review**
```bash
# Identity and access management audit
python3 aws_resource_analyzer.py \
  --resources "iam" --profiles prod,staging,dev \
  --output-format csv --output-file iam_audit.csv
```

## US Government Cloud Support

Full support for AWS GovCloud regions with specialized shortcuts:

```bash
# US Gov regions only
python3 aws_resource_analyzer.py --profiles govcloud-profile --regions gov

# Mixed commercial and gov cloud analysis  
python3 aws_resource_analyzer.py --profiles commercial,govcloud --regions us-east-1,us-gov-west-1

# Gov cloud compliance focus
python3 aws_resource_analyzer.py --profiles govcloud --regions gov \
  --resources "cloudtrail,kms,iam,security_groups"
```

**Gov Cloud Considerations:**
- Separate AWS credentials required
- Limited service availability in some regions
- Compliance-focused resource analysis
- Different pricing models

## Performance & Scalability

### Large Environment Optimization
```bash
# High-performance scanning for large infrastructures
python3 aws_resource_analyzer.py \
  --profiles prod,staging,dev,qa \
  --regions all \
  --threads 25 \
  --output-format json \
  --output-file comprehensive_inventory.json
```

### Targeted Resource Scans
```bash
# Focus on specific resource types for faster execution
python3 aws_resource_analyzer.py \
  --resources "ec2,rds,s3" \
  --regions common \
  --threads 15
```

**Performance Tips:**
- Use specific resource filters for faster scans
- Increase thread count for large environments (`--threads 20-30`)
- Use region shortcuts (`common`, `gov`) to reduce scope
- Export to JSON/CSV for post-processing analysis

## IAM Permissions Required

Ensure your AWS profiles have the following minimum permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "autoscaling:DescribeAutoScalingGroups",
                "cloudformation:ListStacks",
                "cloudfront:ListDistributions",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudwatch:DescribeAlarms",
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeRouteTables",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeNatGateways",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                "ec2:DescribeAddresses",
                "ecs:ListClusters",
                "ecs:DescribeClusters",
                "efs:DescribeFileSystems",
                "eks:ListClusters",
                "eks:DescribeCluster",
                "elasticache:DescribeReplicationGroups",
                "elasticache:DescribeCacheClusters",
                "elb:DescribeLoadBalancers",
                "elbv2:DescribeLoadBalancers",
                "elbv2:DescribeTargetGroups",
                "apigateway:GET",
                "apigatewayv2:GET",
                "iam:ListUsers",
                "iam:ListRoles", 
                "iam:ListPolicies",
                "kms:ListKeys",
                "kms:DescribeKey",
                "lambda:ListFunctions",
                "logs:DescribeLogGroups",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSnapshots",
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "sns:ListTopics",
                "sns:ListSubscriptionsByTopic",
                "sqs:ListQueues",
                "sqs:GetQueueAttributes",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Error Handling & Troubleshooting

The tool gracefully handles common scenarios:

- **Invalid AWS profiles**: Validation with clear error messages
- **Insufficient permissions**: Service-level error reporting
- **Network connectivity issues**: Automatic retry with exponential backoff
- **Service unavailability**: Regional service availability detection
- **Rate limiting**: Built-in throttling and retry logic

**Common Issues:**
```bash
# Profile configuration issues
aws configure list-profiles
aws sts get-caller-identity --profile your-profile-name

# Permission issues
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCOUNT:user/USERNAME \
  --action-names ec2:DescribeInstances --policy-input-list file://policy.json

# Region access issues  
aws ec2 describe-regions --profile your-profile-name
```

## Enterprise Features

### Automation & Integration
- **CI/CD Integration**: JSON output for automated processing
- **Scheduled Scanning**: Cron-compatible for regular inventory updates
- **Change Detection**: Compare outputs over time for drift analysis
- **Cost Tracking**: Resource count trends for capacity planning

### Reporting & Analytics
- **Executive Dashboards**: Summary statistics and trend analysis
- **Compliance Reports**: Security and governance resource states
- **Cost Optimization Reports**: Identify savings opportunities
- **Security Posture**: Risk assessment across accounts

### Multi-Tenant Support
- **Account Isolation**: Per-profile resource segregation
- **Cross-Account Analysis**: Consolidated multi-account views
- **Department/Team Views**: Filter by tags and naming conventions
- **Access Controls**: Role-based scanning permissions

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`


**Areas for contribution:**
- Additional AWS service support
- Performance optimizations
- Enhanced reporting features
- Integration with other tools

## Changelog

### v2.0.0 (Current)
- ✅ **31 resource types** (expanded from 14)
- ✅ **Cost optimization focus** with unattached resource detection
- ✅ **Enhanced security analysis** with detailed security groups and IAM
- ✅ **Performance improvements** with better error handling
- ✅ **Summary analytics** and resource counting
- ✅ **US Gov Cloud support** with dedicated shortcuts

### v1.0.0
- ✅ Basic 14 resource types
- ✅ Multi-account and multi-region support
- ✅ Interactive and CLI modes
- ✅ JSON/CSV export capabilities



---

**⚡ Quick Start**: `python3 aws_resource_analyzer.py` and follow the interactive prompts!

**💡 Pro Tip**: Start with `--resources "nat_gateways,eip,load_balancers"` to quickly identify high-impact cost optimization opportunities.

---

Made with ❤️ by [pagoha]

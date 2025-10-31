# AWS Resource Analyzer

A comprehensive AWS resource inventory tool that discovers and catalogs AWS resources across multiple profiles and regions. Built for cloud infrastructure auditing, compliance reporting, and resource management at scale.

## Overview

The AWS Resource Analyzer provides a unified view of your AWS infrastructure by scanning multiple AWS accounts and regions simultaneously. It inventories 14 different AWS resource types and presents the results in multiple formats for analysis and reporting.

## Features

- **Multi-Account Support**: Scan across multiple AWS profiles simultaneously
- **Multi-Region Coverage**: Support for all AWS regions including US Gov regions
- **Parallel Execution**: Multi-threaded scanning for fast results
- **Multiple Output Formats**: Table, JSON, and CSV output options
- **Interactive & CLI Modes**: User-friendly interactive selection or command-line automation
- **Comprehensive Resource Coverage**: 14 AWS service types including EC2, RDS, S3, Lambda, and more
- **Government Cloud Support**: Full support for US Gov East and West regions
- **Export Capabilities**: Save results to files for reporting and analysis

## Supported AWS Resources

| Service | Resources Inventoried |
|---------|----------------------|
| **CloudFormation** | Stacks (Name, Status) |
| **EC2** | Instances (Name, ID, Type, State) |
| **VPC** | Virtual Private Clouds (ID, CIDR) |
| **Subnets** | Subnet details (ID, VPC, CIDR) |
| **RDS** | Database instances (Identifier, Class, Status) |
| **S3** | Buckets (Name, Creation Date) |
| **EBS** | Volumes (ID, Size, State) |
| **ECS** | Clusters (ARN) |
| **EKS** | Kubernetes Clusters (Name) |
| **Lambda** | Functions (Name, Runtime, State) |
| **Elastic IP** | Addresses (IP, Allocation ID, Instance) |
| **DynamoDB** | Tables (Name) |
| **EFS** | File Systems (ID, State) |
| **IAM** | Users and Policies (Names, IDs, Attachment Count) |

## Prerequisites

- Python 3.6+
- AWS CLI configured with appropriate profiles
- Required Python packages:
  ```bash
  pip install boto3 tabulate
  ```

## Installation

1. Clone or download the script:
   ```bash
   wget https://github.com/your-org/aws-resource-analyzer/raw/main/aws_resource_analyzer.py
   chmod +x aws_resource_analyzer.py
   ```

2. Install dependencies:
   ```bash
   pip install boto3 tabulate
   ```

3. Ensure AWS CLI is configured with your profiles:
   ```bash
   aws configure list-profiles
   ```

## Usage

### Interactive Mode

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

Starting inventory across 2 account(s) and 5 region(s)...
Resource types: cloudformation, ec2, vpc, subnets, rds, s3, ebs, ecs, eks, lambda, eip, dynamodb, efs, iam
Using 10 threads for parallel execution

✅ Completed 1/10: production (123456789012) - us-east-1
✅ Completed 2/10: staging (123456789013) - us-east-1
✅ Completed 3/10: production (123456789012) - us-west-2
...
```

### Command Line Mode

Use command-line arguments for automated execution:

```bash
# Scan specific profiles and regions
python3 aws_resource_analyzer.py --profiles prod,staging --regions us-east-1,us-west-2

# Scan only EC2 and RDS resources  
python3 aws_resource_analyzer.py --resources ec2,rds --regions common

# US Government regions only
python3 aws_resource_analyzer.py --profiles govcloud-profile --regions gov

# Export results to JSON
python3 aws_resource_analyzer.py --profiles prod --output-format json --output-file inventory.json

# Export results to CSV
python3 aws_resource_analyzer.py --profiles prod --output-format csv --output-file inventory.csv

# Scan all regions with custom thread count
python3 aws_resource_analyzer.py --profiles prod --regions all --threads 20
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--profiles` | Comma-separated list of AWS profiles | Interactive selection |
| `--regions` | Regions to scan (`all`, `common`, `gov`, or specific regions) | Interactive selection |
| `--resources` | Resource types to inventory (`all` or specific types) | `all` |
| `--output-format` | Output format: `table`, `json`, or `csv` | `table` |
| `--output-file` | File path to save results | stdout |
| `--threads` | Number of parallel threads | `10` |

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

RDS Instances:
┌─────────────────────┬─────────────────┬─────────────────┐
│ DBInstanceIdentifier│ DBInstanceClass │ DBInstanceStatus│
├─────────────────────┼─────────────────┼─────────────────┤
│ prod-mysql-db       │ db.r5.large     │ available       │
│ prod-postgres-db    │ db.t3.medium    │ available       │
└─────────────────────┴─────────────────┴─────────────────┘
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
        "cloudformation": [
          ["web-application-stack", "CREATE_COMPLETE"],
          ["database-stack", "UPDATE_COMPLETE"]
        ],
        "ec2": [
          ["web-server-1", "i-0123456789abcdef0", "t3.medium", "running"],
          ["web-server-2", "i-0987654321fedcba0", "t3.medium", "running"]
        ],
        "rds": [
          ["prod-mysql-db", "db.r5.large", "available"]
        ]
      }
    }
  ]
}
```

### CSV Format
```csv
Profile,Account ID,Region,Resource Type,Resource Details
production,123456789012,us-east-1,cloudformation,web-application-stack | CREATE_COMPLETE
production,123456789012,us-east-1,cloudformation,database-stack | UPDATE_COMPLETE  
production,123456789012,us-east-1,ec2,web-server-1 | i-0123456789abcdef0 | t3.medium | running
production,123456789012,us-east-1,ec2,web-server-2 | i-0987654321fedcba0 | t3.medium | running
```

## Region Shortcuts

The tool supports convenient region shortcuts:

- **`common`**: `us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`, `ap-northeast-1`
- **`gov`**: `us-gov-east-1`, `us-gov-west-1`  
- **`all`**: All available AWS regions including Gov regions

## US Government Cloud Support

The tool fully supports AWS GovCloud regions:

```bash
# Scan US Gov regions only
python3 aws_resource_analyzer.py --profiles govcloud-profile --regions gov

# Mix commercial and gov regions
python3 aws_resource_analyzer.py --profiles prod,govcloud --regions us-east-1,us-gov-west-1
```

**Note**: Ensure your AWS profiles are properly configured for GovCloud access with appropriate credentials and region settings.

## Performance Considerations

- **Threading**: Default 10 threads provide good performance for most scenarios
- **Large Inventories**: For accounts with thousands of resources, consider:
  - Using specific resource filters (`--resources ec2,rds`)
  - Limiting regions to reduce scope
  - Increasing thread count (`--threads 20`)
- **Rate Limiting**: AWS API rate limits are handled automatically with exponential backoff

## Error Handling

The tool gracefully handles common scenarios:
- Invalid or inaccessible AWS profiles
- Regions where services are not available
- Network connectivity issues
- Insufficient IAM permissions

Errors are reported clearly while continuing to process other accounts/regions.

## IAM Permissions Required

Ensure your AWS profiles have the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:ListStacks",
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs", 
                "ec2:DescribeSubnets",
                "ec2:DescribeVolumes",
                "ec2:DescribeAddresses",
                "rds:DescribeDBInstances",
                "s3:ListBuckets",
                "ecs:ListClusters",
                "eks:ListClusters", 
                "lambda:ListFunctions",
                "dynamodb:ListTables",
                "efs:DescribeFileSystems",
                "iam:ListUsers",
                "iam:ListPolicies",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Use Cases

- **Infrastructure Auditing**: Get comprehensive view of resources across all accounts
- **Compliance Reporting**: Generate inventory reports for audit requirements  
- **Cost Analysis**: Identify resources for cost optimization initiatives
- **Security Reviews**: Catalog resources for security assessments
- **Migration Planning**: Inventory existing resources before cloud migrations
- **Resource Cleanup**: Identify unused or orphaned resources

## License

This project is licensed under the MIT License - see the LICENSE file for details.

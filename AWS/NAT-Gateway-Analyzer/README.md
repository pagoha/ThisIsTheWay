# AWS NAT Gateway Analyzer

<div align="center">

![AWS](https://img.shields.io/badge/AWS-VPC-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Discover what's using your NAT Gateways**

A comprehensive Python tool that maps NAT Gateway usage across your AWS infrastructure

</div>

---

## 🎯 What It Does

This tool scans your AWS account and finds:

- 🌐 **All NAT Gateways** across selected regions
- 📍 **Location details** - VPC, subnet, and availability zone information
- 🛣️ **Route tables** that direct traffic through each NAT Gateway
- 🔗 **Associated subnets** using the NAT Gateway for outbound traffic
- 💻 **EC2 instances** relying on NAT Gateway connectivity
- ⚡ **Lambda functions** in VPC using NAT Gateways
- 🗄️ **RDS databases** with NAT Gateway dependencies

**Then it generates a beautiful Excel report** with all findings organized in 7 tabs, plus a detailed text report.

---

## ⚡ Quick Start

### Step 1: Install Python Packages

```bash
pip install boto3 openpyxl
```

**What these do:**
- `boto3` - Talks to AWS
- `openpyxl` - Creates Excel files

### Step 2: Download the Script

Download `nat_gateway_analyzer.py` from this repository and save it to your computer.

Make it executable (Mac/Linux only):
```bash
chmod +x nat_gateway_analyzer.py
```

### Step 3: Run It

```bash
python3 nat_gateway_analyzer.py
```

The script will guide you through the rest!

---

## 🎛️ Configuration Options

When you run the script, it will ask you several questions. Here's what they mean:

### 1. Select Your AWS Profile

```
Available AWS profiles:
1. default
2. production
3. development

Enter profile number or name (or press Enter for default): 2
```

**What this means:** Choose which AWS account to scan

**Tip:** Press Enter to use your default profile

### 2. Confirm Your Account

```
AWS Account Information:
Profile: production
Account ID: 123456789012
Account Alias: my-company-prod
IAM ARN: arn:aws:iam::123456789012:user/your-name

Is this the correct account? (yes/no):
```

**What this means:** Double-check you're scanning the right account

**Important:** Always verify before continuing!

### 3. Select Regions

```
REGION SELECTION
Options:
  1. All regions (comprehensive but slower)
  2. Specific regions (faster)
  3. Current region only

Select an option [1-3] (default: 2):
```

**What this means:** Which AWS regions to scan for NAT Gateways

**Examples:**

**Option 1: All regions**
- Scans all ~20 AWS regions
- Takes 2-5 minutes
- Use when: Complete inventory needed

**Option 2: Specific regions** (Recommended)
```
Common regions:
  1. us-east-1
  2. us-east-2
  3. us-west-1
  4. us-west-2
  5. eu-west-1
  6. eu-central-1
  7. ap-southeast-1
  8. ap-northeast-1

Enter region names: us-east-1,us-west-2
Or enter numbers: 1,4
```
- Scans only specified regions
- Takes 30-90 seconds
- Use when: You know where NAT Gateways are

**Option 3: Current region only**
- Scans one region
- Takes 10-30 seconds
- Use when: Quick check needed

### 4. Output Filename

```
Enter output filename prefix (default: nat_gateway_analysis): my_nat_audit
```

**What this means:** What to name your report files

**Result:**
```
my_nat_audit_20250110_143022.xlsx
my_nat_audit_20250110_143022.txt
```

**Tip:** Press Enter to use default with timestamp

### 5. Start Analysis

```
ANALYSIS CONFIGURATION SUMMARY
AWS Profile:     production
AWS Account:     123456789012 (my-company-prod)
Regions:         us-east-1, us-west-2
Output Prefix:   nat_gateway_analysis_20250110_143022

Start analysis? (yes/no) [default: yes]:
```

**What this means:** Final confirmation before scanning

**Tip:** Review the summary, then type "yes" or press Enter

---

## 📋 What You Get

### Excel Report with 7 Tabs

After the scan completes, you'll get an Excel file with these tabs:

#### Tab 1: Summary 📊
**Overview of the entire analysis**

Contains:
- Report metadata (account, regions, timestamp)
- Total counts summary
- **Workbook Tabs Guide** - Detailed description of each tab
- Helpful notes and usage tips

Perfect for executives and quick reviews!

#### Tab 2: NAT Gateways 🌐
**Main inventory of all NAT Gateways**

Columns:
- NAT Gateway ID, Name, Region, State
- Elastic IP address
- VPC details (ID, Name, CIDR)
- Subnet details (ID, Name, CIDR, AZ)
- Resource counts (Route Tables, Subnets, EC2, Lambda, RDS)
- Creation timestamp

Use this to: Get complete NAT Gateway overview

#### Tab 3: Route Tables 🛣️
**Route tables directing traffic through NAT Gateways**

Columns:
- NAT Gateway ID and Name
- Route Table ID and Name
- Destination CIDR blocks

Use this to: Understand routing configuration

#### Tab 4: Associated Subnets 🔗
**Subnets using NAT Gateways for outbound traffic**

Columns:
- NAT Gateway ID and Name
- Subnet ID, Name, CIDR
- Availability Zone

Use this to: Identify private subnets with internet access

#### Tab 5: EC2 Instances 💻
**EC2 instances using NAT Gateways**

Columns:
- NAT Gateway ID and Name
- Instance ID, Name, Type
- State, Private IP
- Subnet ID

Use this to: Find which workloads depend on each NAT Gateway

#### Tab 6: Lambda Functions ⚡
**Lambda functions with VPC connectivity via NAT Gateways**

Columns:
- NAT Gateway ID and Name
- Function Name, Runtime
- VPC Subnets

Use this to: Identify serverless workloads with external dependencies

#### Tab 7: RDS Instances 🗄️
**RDS databases potentially using NAT Gateways**

Columns:
- NAT Gateway ID and Name
- DB Instance ID, Engine
- Status, Subnets

Use this to: Understand database connectivity patterns

### Text Report

You also get a detailed text file with:
- Complete analysis information
- All NAT Gateways with full details
- Location information
- Tags
- Associated resources
- Easy-to-read formatting

Perfect for: Archiving, version control, or viewing without Excel

---

## 📊 Example Output

### What the Terminal Shows

```
================================================================================
AWS NAT GATEWAY ANALYZER
================================================================================

================================================================================
AWS PROFILE SELECTION
================================================================================

Available AWS profiles:
  1. default
  2. production

Enter profile number or name (or press Enter for default): 2

================================================================================
AWS ACCOUNT INFORMATION
================================================================================
Profile:        production
Account ID:     123456789012
Account Alias:  my-company-prod
IAM ARN:        arn:aws:iam::123456789012:user/paul
================================================================================

Is this the correct account? (yes/no): yes

================================================================================
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

Enter region names: 1,4
✓ Will analyze 2 region(s): us-east-1, us-west-2

================================================================================
OUTPUT OPTIONS
================================================================================

Output formats will be generated:
  ✓ Console output (always generated)
  ✓ Text file report
  ✓ Excel workbook (single file with multiple tabs)

Enter output filename prefix (default: nat_gateway_analysis): 
✓ Output files will be saved with prefix: nat_gateway_analysis_20250110_143022

================================================================================
ANALYSIS CONFIGURATION SUMMARY
================================================================================
AWS Profile:     production
AWS Account:     123456789012 (my-company-prod)
Regions:         us-east-1, us-west-2
Output Prefix:   nat_gateway_analysis_20250110_143022
================================================================================

Start analysis? (yes/no) [default: yes]: yes

================================================================================
STARTING ANALYSIS...
================================================================================

[14:30:22] Checking region: us-east-1
  ✓ Found 3 NAT Gateway(s)
    - Analyzed nat-0a1b2c3d4e5f67890
    - Analyzed nat-1b2c3d4e5f6789012
    - Analyzed nat-2c3d4e5f678901234

[14:30:45] Checking region: us-west-2
  ✓ Found 2 NAT Gateway(s)
    - Analyzed nat-3d4e5f67890123456
    - Analyzed nat-4e5f678901234567a

================================================================================
ANALYSIS COMPLETE
================================================================================
Total NAT Gateways Found: 5

Generating outputs...

[Console output displays here...]

✓ Text report saved: nat_gateway_analysis_20250110_143022.txt
✓ Excel workbook saved: nat_gateway_analysis_20250110_143022.xlsx
  Contains 7 tabs:
    - Summary (with detailed tab guide)
    - NAT Gateways
    - Route Tables
    - Associated Subnets
    - EC2 Instances
    - Lambda Functions
    - RDS Instances

================================================================================
ALL OUTPUTS GENERATED SUCCESSFULLY
================================================================================
```

### Summary Tab Example

```
┌─────────────────────────────────────────────────────────────┐
│  NAT Gateway Analysis Report                                │
├─────────────────────────────────────────────────────────────┤
│  ANALYSIS INFORMATION                                        │
│  Generated:         2025-01-10 14:30:22                     │
│  AWS Profile:       production                               │
│  AWS Account:       123456789012 (my-company-prod)          │
│  Regions Analyzed:  us-east-1, us-west-2                    │
│                                                              │
│  RESULTS SUMMARY                                             │
│  Total NAT Gateways Found:        5                         │
│  Total Route Tables:              12                        │
│  Total Associated Subnets:        18                        │
│  Total EC2 Instances:             47                        │
│  Total Lambda Functions:          8                         │
│  Total RDS Instances:             3                         │
│  Total Resources:                 58                        │
│                                                              │
│  WORKBOOK TABS GUIDE                                         │
│  ┌──────────────────┬──────────────────────────────────┐   │
│  │ Tab Name         │ Description                      │   │
│  ├──────────────────┼──────────────────────────────────┤   │
│  │ Summary          │ Overview of the analysis report  │   │
│  │ NAT Gateways     │ Complete list of all NAT GWs    │   │
│  │ Route Tables     │ Route tables using NAT GWs      │   │
│  │ Associated...    │ Subnets using NAT GWs           │   │
│  │ EC2 Instances    │ EC2 instances using NAT GWs     │   │
│  │ Lambda Functions │ Lambda functions using NAT GWs  │   │
│  │ RDS Instances    │ RDS databases using NAT GWs     │   │
│  └──────────────────┴──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### NAT Gateways Tab Example

| NAT Gateway ID | Name | Region | State | Elastic IP | VPC ID | VPC Name | Subnet ID | AZ | RT Count | Subnet Count | EC2 Count | Lambda Count | RDS Count | Total Resources |
|----------------|------|--------|-------|------------|--------|----------|-----------|----|----|-------|-------|-------|-------|-------|
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | available | 54.123.45.67 | vpc-abc123 | Production VPC | subnet-xyz789 | us-east-1a | 3 | 6 | 15 | 2 | 1 | 18 |
| nat-1b2c3d4e5f6789012 | prod-nat-gw-1b | us-east-1 | available | 54.234.56.78 | vpc-abc123 | Production VPC | subnet-xyz790 | us-east-1b | 3 | 6 | 18 | 3 | 1 | 22 |
| nat-2c3d4e5f678901234 | prod-nat-gw-1c | us-east-1 | available | 54.345.67.89 | vpc-abc123 | Production VPC | subnet-xyz791 | us-east-1c | 3 | 3 | 9 | 2 | 1 | 12 |

### Route Tables Tab Example

| NAT Gateway ID | NAT Gateway Name | Region | Route Table ID | Route Table Name | Destination |
|----------------|------------------|--------|----------------|------------------|-------------|
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | rtb-abc123 | private-rt-1a | 0.0.0.0/0 |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | rtb-abc124 | app-rt-1a | 0.0.0.0/0 |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | rtb-abc125 | db-rt-1a | 0.0.0.0/0 |

### Associated Subnets Tab Example

| NAT Gateway ID | NAT Gateway Name | Region | Subnet ID | Subnet Name | Subnet CIDR | Availability Zone |
|----------------|------------------|--------|-----------|-------------|-------------|-------------------|
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | subnet-abc123 | private-app-1a | 10.0.10.0/24 | us-east-1a |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | subnet-abc124 | private-web-1a | 10.0.20.0/24 | us-east-1a |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | subnet-abc125 | private-db-1a | 10.0.30.0/24 | us-east-1a |

### EC2 Instances Tab Example

| NAT Gateway ID | NAT Gateway Name | Region | Instance ID | Instance Name | Instance Type | State | Private IP | Subnet ID |
|----------------|------------------|--------|-------------|---------------|---------------|-------|------------|-----------|
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | i-0a1b2c3d4e5f | web-server-01 | t3.medium | running | 10.0.10.15 | subnet-abc123 |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | i-1b2c3d4e5f6 | app-server-01 | t3.large | running | 10.0.20.23 | subnet-abc124 |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | i-2c3d4e5f678 | api-server-01 | t3.xlarge | running | 10.0.20.45 | subnet-abc124 |

### Lambda Functions Tab Example

| NAT Gateway ID | NAT Gateway Name | Region | Function Name | Runtime | Subnets |
|----------------|------------------|--------|---------------|---------|---------|
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | data-processor | python3.9 | subnet-abc123, subnet-def456 |
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | api-handler | nodejs18.x | subnet-abc123 |

### RDS Instances Tab Example

| NAT Gateway ID | NAT Gateway Name | Region | DB Instance ID | Engine | Status | Subnets |
|----------------|------------------|--------|----------------|--------|--------|---------|
| nat-0a1b2c3d4e5f67890 | prod-nat-gw-1a | us-east-1 | prod-mysql-01 | mysql | available | subnet-abc125, subnet-def458 |
| nat-1b2c3d4e5f6789012 | prod-nat-gw-1b | us-east-1 | prod-postgres-01 | postgres | available | subnet-abc126, subnet-def459 |

---

## 🔧 Prerequisites

### What You Need

✅ **Python 3.7 or higher**
```bash
# Check your version
python3 --version
```

✅ **AWS CLI configured**
```bash
# Set up AWS credentials
aws configure
```

✅ **AWS EC2/VPC read permissions** (see below)

### Installing Python Packages

**Option 1: Direct install**
```bash
pip install boto3 openpyxl
```

**Option 2: Using requirements.txt**

Create a file called `requirements.txt`:
```txt
boto3>=1.26.0
botocore>=1.29.0
openpyxl>=3.0.0
```

Then install:
```bash
pip install -r requirements.txt
```

### Setting Up AWS Credentials

**Method 1: AWS Configure (Recommended)**
```bash
aws configure
# Enter your Access Key ID
# Enter your Secret Access Key
# Enter your default region (e.g., us-east-1)
# Enter output format (json)
```

**Method 2: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

**Method 3: Multiple Profiles**
```bash
# Create a specific profile
aws configure --profile production

# The script will let you select it
python3 nat_gateway_analyzer.py
```

---

## 🔐 AWS Permissions Required

The script needs **read-only** EC2/VPC permissions. It will **never** modify anything in your AWS account.

### Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeNatGateways",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInstances",
        "lambda:ListFunctions",
        "rds:DescribeDBInstances",
        "iam:ListAccountAliases",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Easy Option: Use AWS Managed Policy

AWS provides pre-made policies with the permissions you need:

**Policy Name:** `ReadOnlyAccess`

**Policy ARN:** `arn:aws:iam::aws:policy/ReadOnlyAccess`

**To attach it:**
```bash
# For a user
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# For a role
aws iam attach-role-policy \
  --role-name your-role-name \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

### What These Permissions Do

| Permission | What It Does |
|------------|--------------|
| `ec2:DescribeRegions` | Lists available AWS regions |
| `ec2:DescribeNatGateways` | Gets NAT Gateway information |
| `ec2:DescribeSubnets` | Gets subnet details and CIDR blocks |
| `ec2:DescribeVpcs` | Gets VPC information |
| `ec2:DescribeRouteTables` | Finds routing configuration |
| `ec2:DescribeInstances` | Lists EC2 instances in subnets |
| `lambda:ListFunctions` | Lists Lambda functions |
| `rds:DescribeDBInstances` | Lists RDS databases |
| `iam:ListAccountAliases` | Gets account alias (optional) |
| `sts:GetCallerIdentity` | Verifies account ID |

**Note:** All permissions are **read-only**. The script cannot delete, modify, or create anything.

---

## 🚀 Complete Usage Guide

### Basic Run (Recommended for First Time)

```bash
python3 nat_gateway_analyzer.py
```

Then follow the prompts:
1. Select your AWS profile
2. Confirm the account
3. Choose regions (try option 3 - current region only)
4. Press Enter for default filename
5. Confirm and start

This will give you a quick analysis in 10-30 seconds!

### Comprehensive Analysis

For a complete inventory across all your infrastructure:

```bash
python3 nat_gateway_analyzer.py
```

**Configuration:**
```
Profile: production
Account: Confirm yes
Regions: 1 (all regions)
Filename: [press Enter]
Start: yes
```

This scans everything but takes 2-5 minutes.

### Quick Regional Check

To quickly check specific regions where you know you have NAT Gateways:

```bash
python3 nat_gateway_analyzer.py
```

**Configuration:**
```
Profile: [your profile]
Account: Confirm yes
Regions: 2 (specific regions)
  Enter: us-east-1,us-west-2
Filename: quick_nat_check
Start: yes
```

Takes 30-90 seconds.

### What Happens During Analysis

**Phase 1: Setup**
```
AWS PROFILE SELECTION
AWS ACCOUNT INFORMATION
REGION SELECTION
OUTPUT OPTIONS
```
- Interactive configuration
- Account verification
- Region selection

**Phase 2: Scanning**
```
[14:30:22] Checking region: us-east-1
  ✓ Found 3 NAT Gateway(s)
    - Analyzed nat-0a1b2c3d4e5f67890
```
- Scans each region
- Finds NAT Gateways
- Analyzes configuration

**Phase 3: Resource Discovery**
```
    - Analyzed nat-0a1b2c3d4e5f67890
```
For each NAT Gateway:
- Finds route tables
- Identifies subnets
- Discovers EC2 instances
- Finds Lambda functions
- Locates RDS databases

**Phase 4: Report Generation**
```
Generating outputs...
✓ Text report saved
✓ Excel workbook saved
```
- Creates console output
- Generates text report
- Builds Excel workbook

**Phase 5: Complete**
```
ALL OUTPUTS GENERATED SUCCESSFULLY
```

---

## 📈 Understanding Your Results

### Common Scenarios

#### Scenario 1: High-Availability Setup

```
Region: us-east-1
NAT Gateways: 3 (one per AZ)
Associated Subnets: 9 (three per AZ)
EC2 Instances: 45
```

**What it means:**
- Proper HA configuration
- Fault-tolerant design
- Resources distributed across AZs

**Recommendation:** ✅ Well-architected

#### Scenario 2: Over-provisioned

```
Region: us-west-2
NAT Gateways: 3
Associated Subnets: 2
EC2 Instances: 1
Lambda Functions: 0
```

**What it means:**
- More NAT Gateways than needed
- Unnecessary cost ($0.045/hour × 3 = ~$100/month)
- Simple workload

**Recommendation:** Consider consolidating to 1 NAT Gateway

#### Scenario 3: Single Point of Failure

```
Region: eu-west-1
NAT Gateways: 1 (us-east-1a only)
Associated Subnets: 12 (across 3 AZs)
EC2 Instances: 50
```

**What it means:**
- If AZ 1a fails, all subnets lose internet
- Not fault-tolerant
- Cost-optimized but risky

**Recommendation:** Add NAT Gateways in other AZs for production

#### Scenario 4: Lambda Heavy

```
NAT Gateway: nat-abc123
EC2 Instances: 2
Lambda Functions: 45
RDS Instances: 0
```

**What it means:**
- Serverless workload
- Lambda functions need external API access
- NAT Gateway required for VPC Lambda functions

**Recommendation:** Consider VPC endpoints to reduce NAT Gateway cost

### Cost Analysis

Use the report to estimate NAT Gateway costs:

**NAT Gateway Pricing (example us-east-1):**
- Per hour: $0.045
- Per GB processed: $0.045

**Calculate your costs:**

```
Monthly NAT Gateway cost = 
  (Number of NAT GWs × $0.045 × 730 hours) + 
  (GB processed × $0.045)

Example:
3 NAT Gateways = 3 × $0.045 × 730 = $98.55/month
+ Data processing (varies)
```

**Cost optimization tips:**
1. Consolidate NAT Gateways if HA not required
2. Use VPC endpoints for AWS services
3. Review Lambda function necessity for VPC
4. Consider NAT instances for dev/test

---

## 🛠️ What to Do With Findings

### 1. Review NAT Gateway Distribution

**Check your Summary tab:**

```
Total NAT Gateways: 8
Regions: us-east-1 (3), us-west-2 (3), eu-west-1 (2)
```

**Questions to ask:**
- Do we need NAT Gateways in all these regions?
- Is the distribution appropriate for our workload?
- Are we following HA best practices?

**Actions:**
- Document rationale for each NAT Gateway
- Identify unused or under-utilized NAT Gateways
- Plan consolidation if appropriate

### 2. Identify Unused NAT Gateways

**Look for:**
```
NAT Gateway: nat-xyz789
Route Tables: 0
Associated Subnets: 0
Total Resources: 0
```

**This means:**
- NAT Gateway not being used
- Costing ~$33/month for nothing
- Safe to delete

**How to verify:**
```bash
# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/NATGateway \
  --metric-name BytesOutToSource \
  --dimensions Name=NatGatewayId,Value=nat-xyz789 \
  --start-time 2024-12-01T00:00:00Z \
  --end-time 2025-01-10T00:00:00Z \
  --period 86400 \
  --statistics Sum
```

**How to delete:**
```bash
# Release Elastic IP first
aws ec2 describe-nat-gateways --nat-gateway-ids nat-xyz789
# Note the AllocationId

# Delete NAT Gateway
aws ec2 delete-nat-gateway --nat-gateway-id nat-xyz789

# Wait for deletion (5-10 minutes)
# Then release EIP
aws ec2 release-address --allocation-id eipalloc-abc123
```

### 3. Optimize Lambda Function VPC Configuration

**Look for:**
```
Lambda Functions: 20
VPC Subnets: subnet-abc, subnet-def, subnet-ghi
```

**Questions:**
- Do these functions really need VPC access?
- Could we use VPC endpoints instead?
- Are we paying unnecessary NAT Gateway data costs?

**Lambda VPC decision tree:**

```
Does Lambda need private resource access?
├─ No → Remove from VPC (no NAT Gateway needed)
│
├─ Yes → What does it access?
    ├─ AWS Services (S3, DynamoDB, etc.)
    │   └─ Use VPC Endpoints (no NAT Gateway needed)
    │
    ├─ Private RDS/Redis/etc.
    │   └─ Keep in VPC (NAT Gateway needed for internet)
    │
    └─ External APIs
        └─ Keep in VPC (NAT Gateway needed)
```

**How to remove Lambda from VPC:**
```bash
aws lambda update-function-configuration \
  --function-name my-function \
  --vpc-config SubnetIds=[],SecurityGroupIds=[]
```

### 4. Implement VPC Endpoints

**If you see many resources accessing AWS services:**

```
EC2 Instances: 30 (accessing S3, DynamoDB)
Lambda Functions: 15 (accessing S3, DynamoDB)
NAT Gateway data processing: High
```

**Solution: Create VPC Endpoints**

```bash
# S3 Gateway Endpoint (free)
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-abc123 \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids rtb-abc123

# DynamoDB Gateway Endpoint (free)
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-abc123 \
  --service-name com.amazonaws.us-east-1.dynamodb \
  --route-table-ids rtb-abc123
```

**Savings:**
- Reduce NAT Gateway data processing costs
- Faster access to AWS services
- More secure (traffic stays in AWS network)

### 5. Document Your Architecture

**Use the report to create documentation:**

```markdown
# Production VPC NAT Gateway Architecture

## us-east-1

### NAT Gateway: prod-nat-gw-1a
- **Purpose:** Provides internet access for private subnets in AZ 1a
- **Elastic IP:** 54.123.45.67
- **Subnet:** subnet-public-1a (10.0.1.0/24)
- **Resources:** 18 EC2 instances, 3 Lambda functions, 1 RDS
- **Monthly Cost:** ~$33 + data transfer

### NAT Gateway: prod-nat-gw-1b
- **Purpose:** Provides internet access for private subnets in AZ 1b
- **Elastic IP:** 54.234.56.78
- **Subnet:** subnet-public-1b (10.0.2.0/24)
- **Resources:** 22 EC2 instances, 3 Lambda functions, 1 RDS
- **Monthly Cost:** ~$33 + data transfer

### NAT Gateway: prod-nat-gw-1c
- **Purpose:** Provides internet access for private subnets in AZ 1c
- **Elastic IP:** 54.345.67.89
- **Subnet:** subnet-public-1c (10.0.3.0/24)
- **Resources:** 12 EC2 instances, 2 Lambda functions, 1 RDS
- **Monthly Cost:** ~$33 + data transfer

**Total Monthly Cost:** ~$99 + data transfer
**HA Configuration:** Yes (one NAT GW per AZ)
**Justification:** Production workload requires fault tolerance
```

---

## ❓ Common Questions

### How long does analysis take?

| Scenario | Time |
|----------|------|
| Single region, few NAT GWs | 10-30 seconds |
| Multiple regions, moderate | 30-90 seconds |
| All regions scan | 2-5 minutes |
| Large account (many resources) | 3-10 minutes |

### Does it change anything in AWS?

**No!** The script is 100% read-only:
- ✅ Only reads information
- ❌ Never deletes anything
- ❌ Never modifies anything
- ❌ Never creates anything

All actions are **manual** based on the report.

### Can I run this in production?

**Yes!** It's safe because:
- Read-only operations
- No changes to AWS resources
- API calls are logged in CloudTrail
- Minimal API usage
- Used by many organizations

**Best practice:** Test on a dev account first

### How often should I run this?

**Recommended schedule:**
- **After infrastructure changes:** Immediately
- **Regular audits:** Monthly or Quarterly
- **Cost reviews:** Monthly
- **Architecture documentation:** As needed

### What about IPv6?

The script analyzes IPv4 NAT Gateways. For IPv6:
- IPv6 traffic uses egress-only internet gateways
- Different resource type
- Not covered by this analyzer (yet!)

**Future feature:** Egress-only IGW analysis

### Can I scan multiple accounts?

**Yes!** Two approaches:

**Method 1: Multiple profiles**
```bash
# Configure profiles
aws configure --profile account1
aws configure --profile account2
aws configure --profile account3

# Run separately
python3 nat_gateway_analyzer.py  # Select account1
python3 nat_gateway_analyzer.py  # Select account2
python3 nat_gateway_analyzer.py  # Select account3
```

**Method 2: AWS Organizations (future feature)**
- Coming soon: Scan all accounts at once
- Cross-account role assumption
- Consolidated reporting

### Is my data secure?

**Yes!** Security features:
- ✅ Runs locally on your computer
- ✅ Reports saved to your disk only
- ✅ No data sent to external servers
- ✅ No credentials stored
- ✅ All AWS calls logged in CloudTrail

**Store reports securely:**
- Encrypt reports at rest
- Limit access with file permissions
- Don't commit to git repositories

### Why do I see "N/A" values?

**Common reasons:**

1. **Resources without Name tags:**
   ```
   VPC Name: N/A
   ```
   Solution: Tag your resources!

2. **Resources deleted after creation:**
   ```
   Subnet Name: N/A
   ```
   The NAT Gateway references a deleted subnet

3. **Permissions issue:**
   ```
   VPC CIDR: N/A
   ```
   Missing describe permissions

4. **Never used resources:**
   ```
   Last Used: N/A
   ```
   Normal for newly created resources

---

## 🐛 Troubleshooting

### Error: "No AWS profiles found"

**Problem:** AWS CLI not configured

**Solution:**
```bash
aws configure
```
Then enter your credentials

### Error: "AccessDenied"

**Problem:** Missing EC2/VPC permissions

**Solutions:**

1. **Check your permissions:**
```bash
aws ec2 describe-nat-gateways --max-results 1
```

2. **Attach ReadOnlyAccess policy:**
```bash
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

### Error: "Could not connect to AWS"

**Problem:** Network or credential issues

**Solutions:**

1. **Check internet connection**

2. **Verify credentials:**
```bash
aws sts get-caller-identity
```

3. **Check AWS credentials file:**
```bash
cat ~/.aws/credentials
```

4. **Try different profile:**
```bash
export AWS_PROFILE=default
```

### Error: "Region not found"

**Problem:** Invalid region name

**Solution:**
```bash
# List valid regions
aws ec2 describe-regions --query 'Regions[].RegionName' --output table

# Use exact region name
# Correct: us-east-1
# Wrong: US-EAST-1, us_east_1, virginia
```

### Script runs slowly

**Causes and solutions:**

| Cause | Solution |
|-------|----------|
| Many regions selected | Select only needed regions |
| Large number of resources | Normal, wait for completion |
| API throttling | Script auto-retries, be patient |
| Slow network | Check connection speed |

**Check progress:**
```
[14:30:22] Checking region: us-east-1    ← Currently processing
  ✓ Found 3 NAT Gateway(s)               ← Progress indicator
    - Analyzed nat-abc123                 ← Individual completion
```

### Excel file won't open

**Causes and solutions:**

1. **File still being written:**
   - Wait for "✅ Analysis completed"
   - Look for completion message

2. **Corrupt file:**
   - Re-run the script
   - Try text output instead

3. **Excel not installed:**
   - Use Google Sheets
   - Use LibreOffice Calc
   - Use text report instead

4. **File too large:**
   - Reduce regions scanned
   - Split into multiple runs

### "openpyxl not installed" error

**Problem:** Missing Excel library

**Solution:**
```bash
pip install openpyxl

# Or use pip3
pip3 install openpyxl

# On some systems
python3 -m pip install openpyxl
```

### No NAT Gateways found (but you have them)

**Possible causes:**

1. **Wrong region:**
   ```
   Solution: Select the correct region(s)
   ```

2. **Wrong account:**
   ```
   Solution: Check account ID in output
   ```

3. **All NAT Gateways deleted:**
   ```
   Solution: Check AWS Console to verify
   ```

4. **Filtered out:**
   ```
   Note: Script excludes "deleted" state NAT Gateways
   ```

### Getting more help

**Check the log file:**
```bash
# Script creates log file automatically
cat nat_gateway_analyzer.log
```

**Enable verbose output:**
Add `print()` statements or check console output

**Report issues:**
Include in your report:
- Error message
- Python version: `python3 --version`
- Boto3 version: `pip show boto3`
- AWS region
- Account size (approx. resource count)

---

## 📚 Best Practices

### Running Regular Audits

**Set up a schedule:**

```bash
# Monthly audit (runs 1st of month at 2 AM)
0 2 1 * * /usr/bin/python3 /path/to/nat_gateway_analyzer.py \
  --profile production \
  --regions us-east-1,us-west-2 \
  --output /reports/nat-$(date +\%Y\%m\%d)

# Quarterly audit
0 2 1 1,4,7,10 * /usr/bin/python3 /path/to/nat_gateway_analyzer.py
```

**Create audit checklist:**

- [ ] Run NAT Gateway analyzer
- [ ] Review Summary tab
- [ ] Check for unused NAT Gateways
- [ ] Verify HA configuration
- [ ] Document any changes
- [ ] Calculate cost estimates
- [ ] Compare with previous report
- [ ] Update architecture diagrams
- [ ] Archive report securely

### Cost Optimization Workflow

**Step 1: Baseline (Week 1)**
```bash
python3 nat_gateway_analyzer.py
# Save as: baseline_nat_audit.xlsx
```

**Step 2: Analysis (Week 1)**
- Review all NAT Gateways
- Identify optimization opportunities
- Document findings

**Step 3: Planning (Week 2)**
- Create implementation plan
- Get approvals
- Schedule maintenance windows

**Step 4: Implementation (Week 3)**
- Remove unused NAT Gateways
- Add VPC endpoints
- Optimize Lambda configurations
- Test thoroughly

**Step 5: Verification (Week 4)**
```bash
python3 nat_gateway_analyzer.py
# Save as: optimized_nat_audit.xlsx
# Compare with baseline
```

**Step 6: Monitoring (Ongoing)**
- Track cost savings
- Monitor for issues
- Document lessons learned

### Architecture Documentation

**Use reports to maintain current documentation:**

```bash
# Run monthly
python3 nat_gateway_analyzer.py

# Archive with version control
git add nat_gateway_analysis_$(date +%Y%m).xlsx
git commit -m "Monthly NAT Gateway audit - $(date +%B_%Y)"
git push
```

**Generate diagrams:**
```
┌─────────────────────────────────────────────────┐
│                  VPC (10.0.0.0/16)              │
│                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────┐ │
│  │ AZ-1a        │  │ AZ-1b        │  │ AZ-1c  │ │
│  │              │  │              │  │        │ │
│  │ Public:      │  │ Public:      │  │ Public:│ │
│  │  NAT GW 1    │  │  NAT GW 2    │  │  NAT 3 │ │
│  │              │  │              │  │        │ │
│  │ Private:     │  │ Private:     │  │ Private│ │
│  │  18 resources│  │  22 resources│  │  12 res│ │
│  └──────────────┘  └──────────────┘  └────────┘ │
└─────────────────────────────────────────────────┘

From: nat_gateway_analysis.xlsx
```

### Storing Reports Securely

**Reports may contain sensitive infrastructure details!**

**Option 1: Encrypt locally**
```bash
# Encrypt with password
gpg --symmetric nat_gateway_analysis_*.xlsx

# Decrypt when needed
gpg nat_gateway_analysis_*.xlsx.gpg
```

**Option 2: Upload to secure S3**
```bash
# Upload with encryption
aws s3 cp nat_gateway_analysis_*.xlsx \
  s3://your-secure-bucket/network-audits/ \
  --sse AES256 \
  --acl private

# Set lifecycle policy
aws s3api put-bucket-lifecycle-configuration \
  --bucket your-secure-bucket \
  --lifecycle-configuration file://retention.json
```

**Option 3: Store in document management system**
- Confluence with restricted access
- SharePoint with permissions
- Internal wiki with authentication

**Never:**
- ❌ Commit to public git repos
- ❌ Email unencrypted
- ❌ Store in public S3 buckets
- ❌ Share on public channels

### Tracking Changes Over Time

**Compare reports month-over-month:**

```bash
# Create comparison script
#!/bin/bash

echo "NAT Gateway Analysis Comparison"
echo "================================"
echo ""
echo "Previous Month: Nov 2024"
echo "Current Month:  Dec 2024"
echo ""
echo "Metric                 | Nov    | Dec    | Change"
echo "-------------------------------------------------"
echo "Total NAT Gateways     | 8      | 6      | -2 ✅"
echo "Total Resources        | 120    | 118    | -2"
echo "Estimated Monthly Cost | $265   | $199   | -$66 ✅"
```

**Track improvements:**
| Quarter | NAT GWs | Monthly Cost | Resources |
|---------|---------|--------------|-----------|
| Q4 2024 | 8       | $265         | 120       |
| Q1 2025 | 6       | $199         | 118       |
| Q2 2025 | 5       | $166         | 115       |

**Document your wins!** 📈

---

## 🎓 Understanding NAT Gateways

### What is a NAT Gateway?

**NAT = Network Address Translation**

A NAT Gateway allows resources in private subnets (no public IP) to access the internet while remaining private.

**Example:**
```
Private EC2 Instance (10.0.1.50) 
    ↓
NAT Gateway (10.0.0.10 / 54.123.45.67)
    ↓
Internet (api.example.com)
```

The EC2 instance can make outbound connections but cannot receive inbound connections from the internet.

### When Do You Need a NAT Gateway?

**You NEED a NAT Gateway when:**
- ✅ Private subnet resources need to access the internet
- ✅ Downloading software updates
- ✅ Calling external APIs
- ✅ Accessing public services

**You DON'T NEED a NAT Gateway when:**
- ❌ Resources are in public subnets (they have public IPs)
- ❌ Only accessing AWS services (use VPC endpoints instead)
- ❌ No outbound internet access needed

### NAT Gateway vs NAT Instance

| Feature | NAT Gateway | NAT Instance |
|---------|-------------|--------------|
| **Management** | AWS managed | You manage |
| **Availability** | Highly available in AZ | Single EC2 instance |
| **Bandwidth** | Up to 100 Gbps | Depends on instance type |
| **Cost** | $0.045/hour + data | EC2 cost |
| **Maintenance** | None | You handle patches |
| **Use Case** | Production | Dev/test, cost savings |

**Recommendation:** Use NAT Gateways for production workloads

### NAT Gateway Best Practices

**1. Deploy One NAT Gateway Per AZ (High Availability)**

❌ **Bad: Single NAT Gateway**
```
AZ-1a: NAT Gateway ← All traffic
AZ-1b: No NAT Gateway
AZ-1c: No NAT Gateway

Risk: If AZ-1a fails, everything loses internet
```

✅ **Good: NAT Gateway Per AZ**
```
AZ-1a: NAT Gateway ← Traffic from 1a
AZ-1b: NAT Gateway ← Traffic from 1b
AZ-1c: NAT Gateway ← Traffic from 1c

Benefit: Each AZ independent, fault-tolerant
```

**2. Use VPC Endpoints to Reduce Costs**

❌ **Expensive: Everything through NAT Gateway**
```
EC2 → NAT Gateway → Internet → S3
Cost: $0.045/GB through NAT Gateway
```

✅ **Cheaper: S3 VPC Endpoint**
```
EC2 → VPC Endpoint → S3
Cost: Free! (Gateway endpoint)
```

**Services with Gateway Endpoints (FREE):**
- S3
- DynamoDB

**Services with Interface Endpoints ($0.01/hour):**
- Lambda
- SNS
- SQS
- And many more...

**3. Monitor NAT Gateway Metrics**

**Key CloudWatch metrics:**
```
- BytesOutToDestination: Data sent to internet
- BytesInFromDestination: Data received from internet
- PacketsOutToDestination: Packets sent
- PacketsInFromDestination: Packets received
- ErrorPortAllocation: Connection errors
```

**Set up alarms:**
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name high-nat-gateway-traffic \
  --metric-name BytesOutToDestination \
  --namespace AWS/NATGateway \
  --statistic Sum \
  --period 3600 \
  --threshold 10000000000 \
  --comparison-operator GreaterThanThreshold
```

**4. Tag Your NAT Gateways**

```bash
aws ec2 create-tags \
  --resources nat-abc123 \
  --tags \
    Key=Name,Value=prod-nat-gw-1a \
    Key=Environment,Value=production \
    Key=CostCenter,Value=engineering \
    Key=Owner,Value=platform-team
```

**Benefits:**
- Easy identification
- Cost allocation
- Better organization
- Compliance tracking

---

## 📝 License

MIT License - Free to use, modify, and distribute.

```
Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software, to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## 💬 Support & Community

**Questions or issues?**
- 📖 Read the [Troubleshooting](#-troubleshooting) section
- 💡 Check [Common Questions](#-common-questions)
- 🐛 Report bugs with detailed error messages

**Share your experience:**
- ⭐ Star the repo if useful
- 🐦 Tweet about your findings
- 📝 Write a blog post
- 💼 Use in your organization

---

## 🙏 Acknowledgments

Built with:
- **Boto3** - AWS SDK for Python
- **OpenPyXL** - Excel file creation
- **AWS VPC** - Virtual Private Cloud networking

Inspired by AWS Well-Architected Framework and real-world infrastructure audit needs.

---

<div align="center">

**Made with ❤️ by [pagoha]**

⭐ Star this repo if you find it useful!

**[Back to Top](#aws-nat-gateway-analyzer)**

</div>

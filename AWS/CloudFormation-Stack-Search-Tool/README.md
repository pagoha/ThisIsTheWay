# CloudFormation Stack Search Tool

A powerful Python tool to search for CloudFormation stacks and StackSets across multiple AWS profiles and regions using customizable pattern matching.

## Features

- 🔍 **Flexible Search**: Search by stack name with case-insensitive matching by default
- 🎯 **Regex Support**: Use regular expressions for advanced pattern matching
- 🌐 **Multi-Account**: Search across multiple AWS profiles simultaneously
- 🗺️ **Multi-Region**: Search across all AWS regions or select specific ones
- ⚡ **Concurrent Processing**: Fast parallel execution using threading
- 📊 **Detailed Results**: Comprehensive stack information including resources, tags, and status
- 📈 **StackSets Support**: Discover and analyze CloudFormation StackSets
- 💾 **Export Options**: Export results to JSON and CSV formats
- 🎛️ **Interactive Mode**: User-friendly interactive prompts for easy configuration
- 📋 **Command Line**: Full CLI support for automation and scripting

## Installation

### Prerequisites

- Python 3.6 or higher
- AWS CLI configured with profiles
- Appropriate AWS permissions for CloudFormation access

### Setup

1. Clone or download the script:
```bash
wget https://raw.githubusercontent.com/your-repo/cloudformation_stack_search.py
# or
curl -O https://raw.githubusercontent.com/your-repo/cloudformation_stack_search.py
```

2. Install required dependencies:
```bash
pip install boto3 botocore
```

3. Make the script executable:
```bash
chmod +x cloudformation_stack_search.py
```

## Usage

### Interactive Mode (Recommended)

Run the script without arguments for an interactive experience:

```bash
python cloudformation_stack_search.py
```

The interactive mode will guide you through:
- Entering your search pattern
- Selecting case sensitivity and regex options
- Choosing AWS profiles
- Selecting regions to search
- Export options

======================================================================

## Interactive Mode Example

Here's a complete example of running the script in interactive mode:

```bash
$ python cloudformation_stack_search.py

======================================================================
CloudFormation Stack Search Tool
======================================================================

Enter search pattern (stack name contains): nops
Case sensitive search? (y/N): n
Use regex pattern matching? (y/N): n

Searching for stacks containing: 'nops' (case insensitive)

Available AWS profiles:
1. default
2. production
3. staging
4. development
5. security

Profile selection options:
- Enter profile numbers separated by commas (e.g., 1,3,5)
- Enter ranges with dashes (e.g., 1-5)
- Enter profile names separated by commas (e.g., prod,staging,dev)
- Enter 'all' to select all profiles
- Press Enter to select default profile only

Enter your selection: 2,3,4

Validating 3 profile(s)...
[OK] production: Account 123456789012
[OK] staging: Account 234567890123
[OK] development: Account 345678901234

Found 3 valid account(s):
  - Profile: production | Account: 123456789012
  - Profile: staging | Account: 234567890123
  - Profile: development | Account: 345678901234

Proceed with analysis of these 3 account(s)? (yes/no): yes

Available AWS Regions (24 total):
------------------------------------------------------------
 1. af-south-1          2. ap-east-1          3. ap-northeast-1    
 4. ap-northeast-2      5. ap-northeast-3     6. ap-south-1        
 7. ap-southeast-1      8. ap-southeast-2     9. ap-southeast-3    
10. ca-central-1       11. eu-central-1      12. eu-north-1       
13. eu-south-1         14. eu-west-1         15. eu-west-2        
16. eu-west-3         17. me-south-1        18. sa-east-1        
19. us-east-1         20. us-east-2         21. us-gov-east-1    
22. us-gov-west-1     23. us-west-1         24. us-west-2        

Region selection options:
- Enter region numbers separated by commas (e.g., 1,5,10)
- Enter ranges with dashes (e.g., 1-5)
- Enter region names separated by commas (e.g., us-east-1,eu-west-1)
- Enter 'all' to select all regions
- Enter 'common' for common regions (us-east-1, us-west-2, eu-west-1)
- Press Enter to select us-east-1 only

Enter your selection: common

Selected 5 region(s):
  - us-east-1
  - us-west-2
  - eu-west-1
  - ap-southeast-1
  - ap-northeast-1

Starting search for resources...
Search pattern: 'nops' (case insensitive)
Profiles: 3 accounts
Regions: 5 regions
Total combinations: 15
----------------------------------------------------------------------
Checking profile production (Account: 123456789012) in region us-east-1...
Checking profile production (Account: 123456789012) in region us-west-2...
Checking profile staging (Account: 234567890123) in region us-east-1...
Checking profile development (Account: 345678901234) in region us-east-1...
Checking profile production (Account: 123456789012) in region eu-west-1...
Completed 5/15 checks...
Checking profile staging (Account: 234567890123) in region us-west-2...
Checking profile development (Account: 345678901234) in region us-west-2...
Checking profile staging (Account: 234567890123) in region eu-west-1...
Checking profile development (Account: 345678901234) in region eu-west-1...
Checking profile production (Account: 123456789012) in region ap-southeast-1...
Completed 10/15 checks...
Checking profile staging (Account: 234567890123) in region ap-southeast-1...
Checking profile development (Account: 345678901234) in region ap-southeast-1...
Checking profile production (Account: 123456789012) in region ap-northeast-1...
Checking profile staging (Account: 234567890123) in region ap-northeast-1...
Checking profile development (Account: 345678901234) in region ap-northeast-1...

Search completed! Processed 15 profile/region combinations.

================================================================================
SEARCH RESULTS
================================================================================

Found 4 CloudFormation stacks containing 'nops':
--------------------------------------------------------------------------------

1. Stack Name: nops-monitoring-prod
   Profile: production
   Account: 123456789012
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-10-15T14:30:22.000000
   Resources: 12
   Description: nOps monitoring and cost optimization stack for production

2. Stack Name: prod-nops-alerting
   Profile: production
   Account: 123456789012
   Region: us-west-2
   Status: UPDATE_COMPLETE
   Created: 2023-09-28T09:15:45.000000
   Resources: 8
   Description: Production alerting infrastructure managed by nOps

3. Stack Name: nops-cost-optimizer-staging
   Profile: staging
   Account: 234567890123
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-10-01T11:22:17.000000
   Resources: 6
   Description: nOps cost optimization tools for staging environment

4. Stack Name: dev-nops-playground
   Profile: development
   Account: 345678901234
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-10-20T16:45:33.000000
   Resources: 4
   Description: Development environment for testing nOps integrations

Found 1 StackSets containing 'nops':
--------------------------------------------------------------------------------

1. StackSet Name: nops-cross-account-role
   Profile: production
   Account: 123456789012
   Status: ACTIVE
   Permission Model: SERVICE_MANAGED
   Description: Cross-account IAM roles for nOps access across organization
   Instance Count: 15
   Deployed Regions: us-east-1, us-west-2, eu-west-1
   Deployed Accounts: 15 accounts
   Last Operation: CREATE (SUCCEEDED)

================================================================================
SUMMARY: Found 5 total resources matching 'nops'
- CloudFormation Stacks: 4
- StackSets: 1
- Errors: 0
================================================================================

Export results? (json/csv/both/n): both
Stacks exported to: cloudformation_search_nops_stacks_20241004_153942.csv
StackSets exported to: cloudformation_search_nops_stacksets_20241004_153942.csv
Full results exported to: cloudformation_search_nops_20241004_153942.json
```

======================================================================

### Command Line Mode

For automation and scripting, use command line arguments:

```bash
# Basic search
python cloudformation_stack_search.py --pattern "nops" --profiles prod staging --regions us-east-1 us-west-2

# Case-sensitive search
python cloudformation_stack_search.py --pattern "MyStack" --case-sensitive --profiles default

# Regex pattern matching
python cloudformation_stack_search.py --pattern "^(prod|stage)-.*" --regex --profiles main

# Search all regions in a profile
python cloudformation_stack_search.py --pattern "monitoring" --profiles prod --regions all

# Export results
python cloudformation_stack_search.py --pattern "datadog" --profiles prod --export-json results --export-csv results
```

----------------------------------------------------------------------

## Command Line Example

Here's an example of using the command line mode:

```bash
$ python cloudformation_stack_search.py --pattern "datadog" --profiles production staging --regions us-east-1 us-west-2 --export-json datadog_search

Searching for 'datadog' in profiles: ['production', 'staging'], regions: ['us-east-1', 'us-west-2']

================================================================================
SEARCH RESULTS
================================================================================

Found 3 CloudFormation stacks containing 'datadog':
--------------------------------------------------------------------------------

1. Stack Name: datadog-integration-prod
   Profile: production
   Account: 123456789012
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-08-15T10:30:15.000000
   Resources: 7
   Description: DataDog monitoring integration for production environment

2. Stack Name: prod-datadog-logs
   Profile: production
   Account: 123456789012
   Region: us-west-2
   Status: UPDATE_COMPLETE
   Created: 2023-09-01T14:22:33.000000
   Resources: 5
   Description: DataDog log forwarding configuration

3. Stack Name: staging-datadog-monitoring
   Profile: staging
   Account: 234567890123
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-09-10T09:15:42.000000
   Resources: 4
   Description: DataDog monitoring setup for staging environment

No StackSets containing 'datadog' found.

================================================================================
SUMMARY: Found 3 total resources matching 'datadog'
- CloudFormation Stacks: 3
- StackSets: 0
- Errors: 0
================================================================================

Full results exported to: datadog_search_20241004_154125.json
```

----------------------------------------------------------------------

### Advanced Examples with Regex

```bash
$ python cloudformation_stack_search.py --pattern "^(prod|stage)-.*-(monitoring|logging)$" --regex --profiles production staging --regions us-east-1

Searching for '^(prod|stage)-.*-(monitoring|logging)$' in profiles: ['production', 'staging'], regions: ['us-east-1']

================================================================================
SEARCH RESULTS
================================================================================

Found 2 CloudFormation stacks matching regex '^(prod|stage)-.*-(monitoring|logging)$':
--------------------------------------------------------------------------------

1. Stack Name: prod-app1-monitoring
   Profile: production
   Account: 123456789012
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-10-05T08:45:12.000000
   Resources: 15
   Description: Production monitoring stack for application 1

2. Stack Name: stage-webapp-logging
   Profile: staging
   Account: 234567890123
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-10-12T13:20:08.000000
   Resources: 8
   Description: Staging logging infrastructure for web application

No StackSets matching regex '^(prod|stage)-.*-(monitoring|logging)$' found.

================================================================================
SUMMARY: Found 2 total resources matching '^(prod|stage)-.*-(monitoring|logging)$' (regex)
- CloudFormation Stacks: 2
- StackSets: 0
- Errors: 0
================================================================================
```

----------------------------------------------------------------------

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--pattern` | `-p` | Search pattern for stack names |
| `--case-sensitive` | `-c` | Enable case-sensitive search (default: case insensitive) |
| `--regex` | | Use regex pattern matching |
| `--profiles` | | Space-separated list of AWS profile names |
| `--regions` | `-r` | Space-separated list of AWS regions |
| `--export-json` | | Export results to JSON file (specify base filename) |
| `--export-csv` | | Export results to CSV files (specify base filename) |

======================================================================

## Examples with Error Handling

Sometimes you might encounter errors. Here's how the tool handles them:

```bash
$ python cloudformation_stack_search.py --pattern "test" --profiles invalid-profile --regions us-east-1

Error: Invalid profiles: ['invalid-profile']
Available profiles: ['default', 'production', 'staging', 'development', 'security']
```

----------------------------------------------------------------------

### Example with Permission Issues

```bash
$ python cloudformation_stack_search.py

======================================================================
CloudFormation Stack Search Tool
======================================================================

Enter search pattern (stack name contains): vpc
Case sensitive search? (y/N): n
Use regex pattern matching? (y/N): n

# ... profile and region selection ...

Starting search for resources...
Search pattern: 'vpc' (case insensitive)
Profiles: 2 accounts
Regions: 3 regions
Total combinations: 6
----------------------------------------------------------------------
Checking profile production (Account: 123456789012) in region us-east-1...
Error accessing CloudFormation in production(123456789012), region eu-central-1: An error occurred (AccessDenied) when calling the ListStacks operation: User: arn:aws:iam::123456789012:user/test-user is not authorized to perform: cloudformation:ListStacks
Checking profile staging (Account: 234567890123) in region us-east-1...
# ... continues with other regions ...

Search completed! Processed 6 profile/region combinations.

================================================================================
SEARCH RESULTS
================================================================================

Found 2 CloudFormation stacks containing 'vpc':
--------------------------------------------------------------------------------

1. Stack Name: vpc-prod-main
   Profile: production
   Account: 123456789012
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-07-20T12:00:00.000000
   Resources: 25
   Description: Main VPC infrastructure for production

2. Stack Name: staging-vpc-setup
   Profile: staging
   Account: 234567890123
   Region: us-east-1
   Status: CREATE_COMPLETE
   Created: 2023-08-15T09:30:15.000000
   Resources: 18
   Description: VPC configuration for staging environment

No StackSets containing 'vpc' found.

Encountered 1 error(s):
--------------------------------------------------------------------------------

1. Profile: production
   Account: 123456789012
   Error Type: cloudformation_access_failed
   Message: An error occurred (AccessDenied) when calling the ListStacks operation: User is not authorized to perform: cloudformation:ListStacks

================================================================================
SUMMARY: Found 2 total resources matching 'vpc'
- CloudFormation Stacks: 2
- StackSets: 0
- Errors: 1
================================================================================
```

======================================================================

## Sample Export Files

### JSON Export Example

```json
{
  "search_pattern": "nops",
  "case_sensitive": false,
  "use_regex": false,
  "timestamp": "2024-10-04T15:39:42.123456",
  "summary": {
    "total_stacks": 4,
    "total_stacksets": 1,
    "total_errors": 0
  },
  "results": {
    "stacks": [
      {
        "profile_name": "production",
        "account_id": "123456789012",
        "region": "us-east-1",
        "stack_name": "nops-monitoring-prod",
        "stack_id": "arn:aws:cloudformation:us-east-1:123456789012:stack/nops-monitoring-prod/12345678-1234-1234-1234-123456789012",
        "stack_status": "CREATE_COMPLETE",
        "creation_time": "2023-10-15T14:30:22.000000",
        "last_updated_time": "2023-10-15T14:30:22.000000",
        "description": "nOps monitoring and cost optimization stack for production",
        "resource_count": 12,
        "drift_status": "NOT_CHECKED",
        "tags": [
          {
            "Key": "Environment",
            "Value": "production"
          },
          {
            "Key": "Owner",
            "Value": "devops-team"
          }
        ],
        "capabilities": ["CAPABILITY_IAM"],
        "stack_policy": "No",
        "is_stackset_instance": false,
        "nested_stack_count": 0
      }
    ],
    "stacksets": [
      {
        "profile_name": "production",
        "account_id": "123456789012",
        "stackset_name": "nops-cross-account-role",
        "stackset_id": "nops-cross-account-role:87654321-4321-4321-4321-210987654321",
        "status": "ACTIVE",
        "description": "Cross-account IAM roles for nOps access across organization",
        "permission_model": "SERVICE_MANAGED",
        "instance_count": 15,
        "regions": ["us-east-1", "us-west-2", "eu-west-1"],
        "accounts": ["123456789012", "234567890123", "345678901234"],
        "last_operation": {
          "operation_id": "12345678-1234-1234-1234-123456789012",
          "action": "CREATE",
          "status": "SUCCEEDED",
          "creation_timestamp": "2023-10-01T10:00:00.000000"
        }
      }
    ],
    "errors": []
  }
}
```

----------------------------------------------------------------------

### CSV Export Example

**cloudformation_search_nops_stacks_20241004_153942.csv**
```csv
profile_name,account_id,region,stack_name,stack_status,creation_time,last_updated_time,description,resource_count,is_stackset_instance,stackset_name,nested_stack_count,drift_status,stack_policy
production,123456789012,us-east-1,nops-monitoring-prod,CREATE_COMPLETE,2023-10-15T14:30:22.000000,2023-10-15T14:30:22.000000,nOps monitoring and cost optimization stack for production,12,False,,0,NOT_CHECKED,No
production,123456789012,us-west-2,prod-nops-alerting,UPDATE_COMPLETE,2023-09-28T09:15:45.000000,2023-10-20T11:30:15.000000,Production alerting infrastructure managed by nOps,8,False,,0,NOT_CHECKED,No
staging,234567890123,us-east-1,nops-cost-optimizer-staging,CREATE_COMPLETE,2023-10-01T11:22:17.000000,2023-10-01T11:22:17.000000,nOps cost optimization tools for staging environment,6,False,,0,NOT_CHECKED,No
development,345678901234,us-east-1,dev-nops-playground,CREATE_COMPLETE,2023-10-20T16:45:33.000000,2023-10-20T16:45:33.000000,Development environment for testing nOps integrations,4,False,,0,NOT_CHECKED,No
```

**cloudformation_search_nops_stacksets_20241004_153942.csv**
```csv
profile_name,account_id,stackset_name,status,description,permission_model,instance_count
production,123456789012,nops-cross-account-role,ACTIVE,Cross-account IAM roles for nOps access across organization,SERVICE_MANAGED,15
```

======================================================================

## Output Information

The tool provides comprehensive information for each found stack:

### Stack Information
- Stack name and ID
- AWS profile and account ID
- Region
- Current status
- Creation and last update times
- Description
- Resource count
- Drift detection status
- Tags and capabilities
- Stack policy presence
- StackSet association (if applicable)
- Nested stack count

### StackSet Information
- StackSet name and ID
- Status and permission model
- Description
- Instance count and distribution
- Deployed regions and accounts
- Last operation details

## Export Formats

### JSON Export
Complete results with metadata, search parameters, and full stack details.

### CSV Export
Separate CSV files for stacks and StackSets with key information in tabular format.

## Error Handling

The tool gracefully handles various scenarios:
- Invalid AWS profiles or regions
- Missing permissions
- Network connectivity issues
- API rate limiting
- Stack access errors

All errors are logged and reported in the final results.

## Performance

- **Concurrent Processing**: Uses ThreadPoolExecutor for parallel region/profile scanning
- **Pagination**: Properly handles AWS API pagination for large result sets
- **Rate Limiting**: Respects AWS API limits with appropriate error handling
- **Progress Indicators**: Shows progress for long-running operations

## AWS Permissions Required

The tool requires the following AWS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:ListStacks",
                "cloudformation:DescribeStacks",
                "cloudformation:ListStackResources",
                "cloudformation:ListStackSets",
                "cloudformation:DescribeStackSet",
                "cloudformation:ListStackInstances",
                "cloudformation:ListStackSetOperations",
                "sts:GetCallerIdentity",
                "ec2:DescribeRegions"
            ],
            "Resource": "*"
        }
    ]
}
```

## Troubleshooting

### Common Issues

1. **"No AWS profiles found"**
   - Configure AWS CLI: `aws configure`
   - Verify profiles: `aws configure list-profiles`

2. **"AccessDenied" errors**
   - Check IAM permissions
   - Verify profile has CloudFormation access

3. **"StackSets not accessible"**
   - StackSets are only accessible from organization management accounts
   - This is expected behavior for member accounts

4. **Regex pattern errors**
   - Validate regex syntax before running
   - Use online regex testers for complex patterns

### Debug Mode

For additional debugging information, you can modify the script to enable verbose logging by adding debug statements or using the `--verbose` flag (if implemented).


---

Made with ❤️ by [pagoha]

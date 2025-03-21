# AWS Unused Resources Checker
This Python script helps identify potentially unused or orphaned resources in your AWS account. It's designed to assist in maintaining a clean AWS environment and potentially reduce costs by identifying resources that may no longer be needed.

## Features
- Confirms and displays AWS profile details before execution
- Checks for unused AWS resources across multiple categories
- Supports AWS SSO profiles
- Generates both console output and a detailed text file report
- Easy to run with command-line arguments or interactive prompt

## Profile Confirmation
Before checking for unused resources, the script confirms the AWS profile being used. It displays:
- The profile name
- The AWS account number
- The ARN (Amazon Resource Name) of the user or role

This confirmation step helps ensure that you're operating in the intended AWS environment before any checks are performed.

## Resources Checked
The script currently checks for the following unused resources:

1. **Unassociated Elastic IPs**: Identifies Elastic IP addresses that are not associated with any running EC2 instances.
2. **Orphaned EBS Volumes**: Finds EBS volumes that are not attached to any EC2 instances.
3. **Old Snapshots**: Detects EBS snapshots that are older than 30 days.
4. **Stopped EC2 Instances**: Lists EC2 instances that are in a stopped state.

## Prerequisites
- Python 3.6 or higher
- Boto3 library (`pip install boto3`)
- Valid AWS credentials configured (either through AWS CLI or environment variables)
- Appropriate AWS permissions to describe EC2 resources

## Installation
1. Clone this repository or download the script file.
2. Install the required Python library:
pip install boto3
3. Ensure you have valid AWS credentials configured.

## Usage
You can run the script in two ways:

1. With a specified AWS profile:
python AWSUnusedResources.py --profile your-profile-name

2. Without specifying a profile (you will be prompted to enter the profile name):
python AWSUnusedResources.py

3. Upon execution, the script will confirm the AWS profile being used and display the associated account number and user ARN before proceeding with the resource check.


## Output
The script provides output in two forms:

1. **Console Output**: 
   - Displays the AWS profile being used, including account number and user ARN.
   - Shows a summary of found unused resources.

2. **Text File**: Generates a detailed report in the same directory as the script. 
   - The filename includes the date and time of the report generation, in the format: `aws_unused_resources_YYYYMMDD_HHMMSS.txt`.
   - This naming convention allows for multiple reports to be saved and easily identified by their creation time.


## AWS Permissions
The AWS user or role used to run this script should have permissions to describe the following EC2 resources:
- EC2 instances
- Elastic IP addresses
- EBS volumes
- EBS snapshots

## Limitations
- The script currently only checks resources in the default region of the specified profile.
- It does not automatically take action on the identified resources; it only reports them.

## Security Note
Always review the findings carefully before taking any action. Some resources may appear unused but could be serving important functions in your AWS environment.

## Contributing
Contributions to improve the script or extend its functionality are welcome.

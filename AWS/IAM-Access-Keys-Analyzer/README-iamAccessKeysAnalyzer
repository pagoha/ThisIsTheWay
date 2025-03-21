AWS IAM Access Keys Analyzer 🔑
PythonAWSLicense

A Python tool that identifies unused and old AWS IAM access keys to help maintain AWS account security and compliance.

📋 Overview
The AWS IAM Access Keys Analyzer scans your AWS accounts for:

🕒 Access keys older than the threshold (default: 200 days) that have never been used
⚠️ Access keys that haven't been used in the last X days (configurable threshold)
The script produces a detailed report that can help identify security risks and maintain compliance with security best practices.

✨ Features
🔄 Interactive AWS profile selection from your configured AWS profiles
⚙️ Configurable age threshold (default: 200 days)
📊 Detailed, well-formatted text report
✅ Account verification before running analysis
🛡️ Comprehensive error handling
💾 Automatic saving of report to a text file
🚀 Prerequisites
Python Requirements
Python 3.6 or higher
AWS SDK for Python (boto3) library
To install the required Python packages:


pip install boto3
AWS Credentials Setup
The script uses the AWS CLI credentials and configuration. Before running the script, ensure you have:

AWS CLI installed
Configured AWS Credentials
Set up your AWS credentials using one of these methods:

a. Using the AWS CLI:

aws configure
b. Manually creating/editing the credentials file:
Linux/MacOS location: ~/.aws/credentials
Windows location: C:\Users\USERNAME\.aws\credentials
Example credentials file:

[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

[prod]
aws_access_key_id = ANOTHER_ACCESS_KEY
aws_secret_access_key = ANOTHER_SECRET_KEY
Required IAM Permissions
The user or role must have these IAM permissions:

iam:ListUsers
iam:ListAccessKeys
iam:GetAccessKeyLastUsed
sts:GetCallerIdentity
Example minimal policy:


{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
📝 Usage
On Linux/MacOS:
Download the script
Make the script executable:

chmod +x iamAccessKeysAnalyzer.py
Run the script:

./iamAccessKeysAnalyzer.py
On Windows (PowerShell):
Download the script
Run the script:

python iamAccessKeysAnalyzer.py
Using the Script
Follow the interactive prompts:

Select an AWS profile
Confirm the account details
Enter a custom age threshold (or press Enter for the default 200 days)
The generated report will look like this:

==========================================================================================================
                                   AWS ACCESS KEY ANALYSIS REPORT                                   
                                     Account ID: 123456789012                                      
                                     Age Threshold: 200 days                                       
                           Generated at: 2023-04-15 14:32:19                                      
==========================================================================================================

===================================== OLD UNUSED KEYS =====================================
Found 2 access keys older than 200 days that have never been used

Username               | Access Key ID              | Creation Date        | Age (days)  | Status    
------------------------------------------------------------------------------------------------------------
test-user              | AKIAIOSFODNN7EXAMPLE      | 2022-03-15 12:45:21  | 396         | Active    
admin-service          | AKIAI44QH8DHBEXAMPLE      | 2021-11-01 09:30:12  | 530         | Active    

===================================== OLD USED KEYS ======================================
Found 1 access keys not used in the last 200 days

Username               | Access Key ID              | Last Used Date       | Service/Region           | Age (days)  | Days Since | Status  
------------------------------------------------------------------------------------------------------------
database-user          | AKIAXHRT5CT3EXAMPLE        | 2022-08-12 15:22:01  | S3/us-east-1             | 365         | 246        | Active  

==========================================================================================================
                                   SUMMARY AND RECOMMENDATIONS                                   
==========================================================================================================

Found a total of 3 access keys that require attention:
  - 2 keys older than 200 days that have never been used
  - 1 keys not used in the last 200 days

Recommended actions:
  1. Delete unused keys that are no longer needed
  2. Rotate active keys that are older than 90 days
  3. Set up AWS Config rule 'iam-user-unused-credentials-check'
  4. Implement automated key rotation

==========================================================================================================
🔒 Security Considerations
This script requires IAM permissions to read user and access key information
The report includes sensitive information about access keys (but not the secret keys)
Consider who has access to the generated reports
🌟 Best Practices
Run this script regularly (e.g., weekly or monthly)
Immediately rotate or delete old and unused access keys
Use IAM roles instead of long-lived access keys when possible
Configure expiration dates for access keys when they are created
Implement automated key rotation
🔧 Troubleshooting Common Issues
Permission Denied:
Error: An error occurred (AccessDenied) when calling the ListUsers operation: User is not authorized to perform: iam:ListUsers
Solution: Ensure your user has the required IAM permissions listed in the prerequisites.

No AWS Profiles Found:
No AWS profiles found. Please configure AWS CLI first using 'aws configure'.
Solution: Set up your AWS credentials using aws configure command.

Profile Not Found:
Error connecting to AWS with profile 'dev': The config profile (dev) could not be found
Solution: Verify the profile name exists in your AWS configuration.

Empty Reports:
Found 0 IAM users. Retrieving access keys...
Successfully processed all 0 users.
Solution: If you're using a role with restricted permissions, ensure it has access to list all IAM users. Alternatively, check if you're in the correct AWS account and confirm if there are actually any IAM users configured.

💼 Use Cases
Security Audits: Identify potential security risks from unused access keys
Compliance: Meet compliance requirements for regular credential rotation
Cost Optimization: Remove unused access keys to reduce management overhead
Security Best Practices: Follow AWS best practices for IAM access key management
📄 License
MIT License

👥 Contributing
Contributions are welcome!

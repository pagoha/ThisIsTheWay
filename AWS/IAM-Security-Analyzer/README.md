# AWS IAM Security Analyzer

<div align="center">

![AWS](https://img.shields.io/badge/AWS-IAM-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Find security risks in your AWS IAM configuration**

A simple Python tool that audits your AWS users, roles, and access keys

</div>

---

## 🎯 What It Does

This tool scans your AWS account and finds:

- 🔑 **Old access keys** that haven't been used in months
- 👤 **Inactive users** who haven't logged in recently  
- 🔓 **Users without MFA** (multi-factor authentication)
- ⚠️ **Risky permissions** like Administrator access
- 🎭 **Unused roles** that should be deleted

**Then it generates an easy-to-read Excel report** with all the findings organized in tabs.

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

Download `iam_security_analyzer.py` from this repository and save it to your computer.

Make it executable (Mac/Linux only):
```bash
chmod +x iam_security_analyzer.py
```

### Step 3: Run It

```bash
python3 iam_security_analyzer.py
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
IAM ARN: arn:aws:iam::123456789012:user/your-name

Is this the correct account? (yes/no):
```

**What this means:** Double-check you're scanning the right account

**Important:** Always verify before continuing!

### 3. Set Inactivity Threshold

```
Enter inactivity threshold in days (default 200): 90
```

**What this means:** How long before something is considered "inactive"

**Examples:**
- `90` = Flag items not used in 90+ days
- `200` = Flag items not used in 200+ days (default)
- `365` = Flag items not used in 1+ year

**Recommendation:** Start with 200, adjust based on your needs

### 4. Set Worker Threads

```
Enter max worker threads for parallel processing (default 5): 5
```

**What this means:** How many things to check at once

**Guidelines:**
- `3` = Slower, safer (use if you get rate limit errors)
- `5` = Balanced (default, works for most accounts)
- `10` = Faster (use for large accounts)

**Tip:** Press Enter to use default

### 5. Analyze Policies?

```
Analyze attached policies? (y/n, default y): y
```

**What this means:** Check for risky permissions like "Administrator Access"

**Recommendation:** Always choose `y` (yes)

### 6. Detailed Access Key Analysis?

```
Perform detailed access key analysis? (y/n, default y): y
```

**What this means:** Get full details on every access key (age, last used, etc.)

**Recommendation:** Always choose `y` (yes)

### 7. Output Format

```
Output format options:
1. Text report only
2. Excel workbook only (multiple tabs)
3. Both text and Excel (default)

Choose output format (1-3, default 3): 3
```

**What this means:** What kind of report files to create

**Recommendations:**
- Choose `3` for complete documentation
- Choose `2` if you only want Excel (easier to read)

### 8. Exclude Patterns (Optional)

```
Enter exclude patterns for usernames/roles (comma-separated, optional): service-,automation-
```

**What this means:** Skip users/roles that match these patterns

**Examples:**
- `service-,automation-` = Skip anything starting with "service-" or "automation-"
- `test,demo` = Skip anything with "test" or "demo" in the name
- Leave blank to scan everything

**Tip:** Press Enter to skip (scan everything)

### 9. Dry Run Mode

```
Dry run mode (skip confirmations)? (y/n, default n): n
```

**What this means:** Skip the account confirmation step

**Recommendation:** Choose `n` (no) for safety

---

## 📋 What You Get

### Excel Report with 7 Tabs

After the scan completes, you'll get an Excel file with these tabs:

#### Tab 1: Summary
Quick overview with total counts and risk level

#### Tab 2: All Users
Every IAM user with:
- Status (Active/Inactive)
- Last activity date
- MFA status
- Access keys count
- Attached policies

#### Tab 3: All Roles
Every IAM role with:
- When it was last used
- What service used it
- Attached policies

#### Tab 4: Old Unused Keys 🔴
Access keys that were **never used** - highest security risk

#### Tab 5: Old Used Keys 🟡
Access keys **not used recently** - should be rotated or deleted

#### Tab 6: Users Without MFA 🔴
Users missing two-factor authentication

#### Tab 7: Risky Policies ⚠️
Users/roles with Administrator or PowerUser access

### Text Report

You also get a detailed text file with:
- Executive summary
- Risk assessment
- Prioritized recommendations
- Security best practices

---

## 📊 Example Output

### What the Terminal Shows

```
🔍 Starting comprehensive IAM security analysis...
   Threshold: 200 days
   Workers: 5 parallel threads

Retrieving all IAM users and roles...
Found 245 IAM users
Found 187 IAM roles

Processing users with comprehensive analysis...
Processed 10/245 users...
Processed 20/245 users...
Processed 50/245 users...
Processed 100/245 users...
Successfully processed all 245 users

Processing roles...
Processed 10/187 roles...
Processed 50/187 roles...
Successfully processed all 187 roles

✅ Analysis completed in 47.32 seconds

📄 Files created:
   • iam_security_report_123456789012_20250104_143022.xlsx (245,678 bytes)
   • iam_security_report_123456789012_20250104_143022.txt (89,234 bytes)

📊 Analysis Summary:
   • Total users analyzed: 245
   • Total roles analyzed: 187
   • Inactive entities: 42
   • Access key issues: 38

⚠️  Security Alert: Found 42 inactive IAM entities requiring review!
⚠️  Access Key Alert: Found 38 old or unused access keys!
🔒 MFA Alert: 18 users without MFA enabled
🚨 Policy Alert: 12 entities with potentially risky policies

📋 Review the generated reports for detailed findings and recommendations.
```

### Summary Tab Example

```
┌─────────────────────────────────────────────────────────────┐
│  AWS IAM Security Analysis Summary                          │
├─────────────────────────────────────────────────────────────┤
│  Account ID:         123456789012                           │
│  Generated:          2025-01-04 14:30:22                    │
│  Threshold (days):   200                                    │
│                                                              │
│  USERS                                                       │
│  ───────────────────────────────────────                    │
│  Total Users:        245                                    │
│  Active Users:       203  ✅                                │
│  Inactive Users:      42  ⚠️                                │
│                                                              │
│  ROLES                                                       │
│  ───────────────────────────────────────                    │
│  Total Roles:        187                                    │
│  Active Roles:       165  ✅                                │
│  Inactive Roles:      22  ⚠️                                │
│                                                              │
│  ACCESS KEYS                                                 │
│  ───────────────────────────────────────                    │
│  Old Unused Keys:     28  🔴 HIGH RISK                      │
│  Old Used Keys:       10  🟡 MEDIUM RISK                    │
│                                                              │
│  SECURITY GAPS                                               │
│  ───────────────────────────────────────                    │
│  Users Without MFA:   18  🔴 HIGH RISK                      │
│                                                              │
│  ⚠️  Overall Risk Level: HIGH                               │
└─────────────────────────────────────────────────────────────┘
```

### All Users Tab Example

| Username | Status | Last Activity | Days Inactive | MFA | Keys | Risky Policies |
|----------|--------|---------------|---------------|-----|------|----------------|
| john.doe | 🔴 Inactive | 2023-02-10 | 328 | ❌ No | 2 | AdministratorAccess |
| jane.smith | ✅ Active | 2025-01-03 | 1 | ✅ Yes | 1 | None |
| service-old | 🔴 Inactive | Never | Never | ❌ No | 1 | S3FullAccess |
| alice.dev | ✅ Active | 2025-01-04 | 0 | ✅ Yes | 0 | None |

**Colors in Excel:**
- 🔴 Red background = Security issues that need attention
- ✅ White background = Everything is good

### Old Unused Keys Tab Example

These keys were created but **NEVER used** - delete immediately!

| Username | Access Key ID | Status | Created | Age |
|----------|---------------|--------|---------|-----|
| service-old | AKIAIOSFODNN7EXAMPLE | Active | 2020-11-08 | 1518 days |
| john.doe | AKIAI44QH8DHBEXAMPLE | Active | 2022-01-15 | 1085 days |
| test-user | AKIAIOSFODNN8EXAMPLE | Active | 2022-06-20 | 929 days |

**⚠️ All rows highlighted RED in Excel**

### Old Used Keys Tab Example

These keys haven't been used recently - should be rotated or deleted:

| Username | Access Key ID | Last Used | Days Since | Service | Region |
|----------|---------------|-----------|------------|---------|--------|
| bob.contractor | AKIA...EXAMPLE | 2024-02-15 | 324 | s3 | us-east-1 |
| api-account | AKIA...EXAMPLE | 2024-01-20 | 350 | ec2 | eu-west-1 |

### Users Without MFA Tab Example

| Username | Status | Last Activity | Active Keys |
|----------|--------|---------------|-------------|
| john.doe | Inactive | 328 days ago | 1 |
| temp-dev | Active | Yesterday | 2 |
| contractor | Active | 2 days ago | 0 |

### Risky Policies Tab Example

| Type | Name | Status | Risky Policy |
|------|------|--------|--------------|
| User | john.doe | Inactive | AdministratorAccess |
| Role | EC2-Prod-Role | Active | AdministratorAccess |
| User | contractor | Inactive | PowerUserAccess |

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

✅ **AWS IAM read permissions** (see below)

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

# Use it with the script
export AWS_PROFILE=production
python3 iam_security_analyzer.py
```

---

## 🔐 AWS Permissions Required

The script needs **read-only** IAM permissions. It will **never** modify anything in your AWS account.

### Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetRole",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListUserTags",
        "iam:ListRoleTags",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Easy Option: Use AWS Managed Policy

AWS provides a pre-made policy with all the permissions you need:

**Policy Name:** `SecurityAudit`

**Policy ARN:** `arn:aws:iam::aws:policy/SecurityAudit`

**To attach it:**
```bash
# For a user
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# For a role
aws iam attach-role-policy \
  --role-name your-role-name \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

### What These Permissions Do

| Permission | What It Does |
|------------|--------------|
| `iam:ListUsers` | Gets list of all IAM users |
| `iam:ListRoles` | Gets list of all IAM roles |
| `iam:ListAccessKeys` | Finds access keys for each user |
| `iam:GetAccessKeyLastUsed` | Checks when keys were last used |
| `iam:GetRole` | Gets role details and usage info |
| `iam:ListMFADevices` | Checks if users have MFA enabled |
| `iam:List*Policies` | Gets attached policies |
| `iam:List*Tags` | Reads resource tags |
| `sts:GetCallerIdentity` | Verifies your account ID |

**Note:** All permissions are **read-only**. The script cannot delete, modify, or create anything.

---

## 🚀 Complete Usage Guide

### Basic Run (Recommended for First Time)

```bash
python3 iam_security_analyzer.py
```

Then just press Enter for all defaults. This will:
- Use your default AWS profile
- Set 200-day inactivity threshold
- Use 5 worker threads
- Analyze everything
- Create both Excel and text reports

### Custom Configuration Example

```bash
python3 iam_security_analyzer.py
```

**Then configure:**
```
Enter profile: production              # Scan production account
Enter threshold: 90                    # Flag 90+ day inactivity
Enter workers: 10                      # Faster processing
Analyze policies: y                    # Check permissions
Analyze keys: y                        # Full key analysis
Output format: 2                       # Excel only
Exclude patterns: service-,test-       # Skip service accounts
Dry run: n                             # Confirm account
```

### What Happens During Analysis

**Phase 1: Connection**
```
🔍 Starting comprehensive IAM security analysis...
Retrieving all IAM users and roles...
```
- Connects to AWS
- Verifies permissions
- Gets list of users and roles

**Phase 2: User Analysis**
```
Found 245 IAM users
Processing users with comprehensive analysis...
Processed 50/245 users...
```
- Checks each user's activity
- Analyzes access keys
- Checks MFA status
- Reviews policies

**Phase 3: Role Analysis**
```
Found 187 IAM roles
Processing roles...
Processed 50/187 roles...
```
- Checks when roles were last used
- Reviews role policies
- Identifies service-linked roles

**Phase 4: Report Generation**
```
Successfully processed all users and roles
Generating reports...
```
- Creates Excel workbook
- Generates text report
- Calculates risk scores

**Phase 5: Complete**
```
✅ Analysis completed in 47.32 seconds
📄 Files created: [list of files]
📊 Analysis Summary: [key findings]
```

---

## 📈 Understanding Your Results

### Risk Levels Explained

The tool assigns an overall risk level based on findings:

| Risk Level | Total Issues | What It Means | Action Timeline |
|------------|--------------|---------------|-----------------|
| 🟢 **LOW** | 1-10 issues | Minor concerns | Review this month |
| 🟡 **MEDIUM** | 11-20 issues | Needs attention | Review this week |
| 🟠 **HIGH** | 21-50 issues | Significant risks | Review today |
| 🔴 **CRITICAL** | 50+ issues | Serious security gaps | **Immediate action** |

### Issue Priority Guide

**🔴 Priority 1: CRITICAL (Fix Today)**

1. **Old Unused Keys**
   - Keys created but never used
   - Pure security risk, no benefit
   - **Action:** Delete immediately

2. **Users Without MFA**
   - Accounts vulnerable to credential theft
   - Easy target for attackers
   - **Action:** Enable MFA now

**🟡 Priority 2: HIGH (Fix This Week)**

3. **Old Used Keys**
   - Keys not used in months
   - Could be compromised
   - **Action:** Contact owner, rotate or delete

4. **Inactive Users**
   - Abandoned accounts
   - Could be exploited
   - **Action:** Disable or delete

**⚠️ Priority 3: MEDIUM (Fix This Month)**

5. **Inactive Roles**
   - Unused permissions
   - Unnecessary attack surface
   - **Action:** Delete if truly unused

6. **Risky Policies**
   - Overly broad permissions
   - Violates least privilege
   - **Action:** Review and tighten

---

## 🛠️ What to Do With Findings

### 1. Delete Old Unused Keys 🔴

**Why:** These keys pose pure security risk with no benefit

**How to verify:**
```bash
# Check CloudTrail for any recent usage
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=USERNAME \
  --max-results 10
```

**How to delete:**
```bash
aws iam delete-access-key \
  --user-name USERNAME \
  --access-key-id AKIAIOSFODNN7EXAMPLE
```

**In AWS Console:**
1. Go to IAM → Users
2. Click on the username
3. Security Credentials tab
4. Find the access key
5. Click "Delete"

### 2. Enable MFA for Users 🔴

**Why:** MFA prevents 99% of credential theft attacks

**How to enable (AWS Console):**
1. Go to IAM → Users
2. Click on username
3. Security Credentials tab
4. Click "Assign MFA device"
5. Follow setup wizard

**How to enforce with policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### 3. Rotate or Delete Old Used Keys 🟡

**Contact key owner first:**
```bash
# Get user's email from tags
aws iam list-user-tags --user-name USERNAME
```

**Create new key:**
```bash
aws iam create-access-key --user-name USERNAME
```

**Delete old key (after confirming new one works):**
```bash
aws iam delete-access-key \
  --user-name USERNAME \
  --access-key-id OLD_KEY_ID
```

### 4. Disable or Delete Inactive Users ⚠️

**Check CloudTrail first:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=USERNAME \
  --start-time 2024-01-01
```

**Disable login (safer first step):**
```bash
# Remove console access
aws iam delete-login-profile --user-name USERNAME

# Deactivate keys
aws iam update-access-key \
  --user-name USERNAME \
  --access-key-id KEY_ID \
  --status Inactive
```

**Delete user (after verification):**
```bash
# Remove policies first
aws iam list-attached-user-policies --user-name USERNAME
aws iam detach-user-policy --user-name USERNAME --policy-arn ARN

# Delete access keys
aws iam list-access-keys --user-name USERNAME
aws iam delete-access-key --user-name USERNAME --access-key-id KEY_ID

# Delete user
aws iam delete-user --user-name USERNAME
```

### 5. Delete Inactive Roles ⚠️

**Verify not used:**
```bash
# Check role details
aws iam get-role --role-name ROLE_NAME

# Look for RoleLastUsed field
```

**Delete role:**
```bash
# Remove policies first
aws iam list-attached-role-policies --role-name ROLE_NAME
aws iam detach-role-policy --role-name ROLE_NAME --policy-arn ARN

# Delete role
aws iam delete-role --role-name ROLE_NAME
```

### 6. Review Risky Policies ⚠️

**Check what permissions user actually needs:**
```bash
# Use Access Analyzer
aws accessanalyzer list-analyzed-resources
```

**Replace broad policy with specific one:**
```bash
# Detach admin policy
aws iam detach-user-policy \
  --user-name USERNAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Attach specific policy
aws iam attach-user-policy \
  --user-name USERNAME \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess
```

---

## ❓ Common Questions

### How long does analysis take?

| Account Size | Time |
|--------------|------|
| Small (< 50 users) | 10-30 seconds |
| Medium (50-200 users) | 30-90 seconds |
| Large (200-500 users) | 1-3 minutes |
| Very Large (500+ users) | 3-10 minutes |

**Tip:** Use more worker threads for faster analysis

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
- Used by many organizations

**Best practice:** Test on a dev account first

### How often should I run this?

**Recommended schedule:**
- **Production accounts:** Monthly
- **Development accounts:** Quarterly
- **After major changes:** Immediately

**Automate it:**
```bash
# Add to crontab for monthly runs
0 2 1 * * python3 /path/to/iam_security_analyzer.py
```

### What about service accounts?

**Service accounts** (automated systems) should:
- Use roles, not access keys
- Have `service-` or `automation-` prefix
- Be excluded using the exclude patterns feature

**Example:**
```
Exclude patterns: service-,automation-,system-
```

### Can I scan multiple accounts?

**Yes!** Two approaches:

**Method 1: Multiple profiles**
```bash
# Configure profiles
aws configure --profile account1
aws configure --profile account2

# Run separately
python3 iam_security_analyzer.py  # Select account1
python3 iam_security_analyzer.py  # Select account2
```

**Method 2: AWS Organizations (future feature)**
- Coming soon: Scan all accounts at once
- Currently in development

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

### What if I get rate limit errors?

**Symptoms:**
```
Rate limited, waiting 2.5 seconds...
Throttling error, retrying...
```

**Solutions:**

1. **Reduce worker threads:**
   ```
   Enter max workers: 3
   ```

2. **The script auto-retries** with exponential backoff

3. **Wait and re-run** if it continues

**Why it happens:**
- Large accounts
- Other tools using AWS API
- AWS API limits

### Can I customize the report?

**Current customization options:**
- Inactivity threshold (days)
- Output format (text/Excel/both)
- Exclude patterns
- Analysis depth

**Future features** (planned):
- Custom risk scoring
- CSV output
- JSON output
- HTML dashboard
- Email notifications

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

**Problem:** Missing IAM permissions

**Solutions:**

1. **Check your permissions:**
```bash
aws iam get-user
```

2. **Attach SecurityAudit policy:**
```bash
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

3. **Use an admin user** (temporarily)

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

### Error: "openpyxl not installed"

**Problem:** Missing Excel library

**Solution:**
```bash
pip install openpyxl
```

**Alternative:** Choose text-only output (option 1)

### Script runs slowly

**Causes and solutions:**

| Cause | Solution |
|-------|----------|
| Large account (500+ users) | Increase workers to 10 |
| API throttling | Decrease workers to 3 |
| Slow network | Check connection |
| Many policies to analyze | This is normal, wait |

**Check progress:**
```
Processed 50/245 users...    ← Shows it's working
```

### Excel file won't open

**Causes and solutions:**

1. **File still being written:**
   - Wait for script to complete
   - Look for "✅ Analysis completed"

2. **Corrupt file:**
   - Re-run the script
   - Try text output instead

3. **Excel not installed:**
   - Use Google Sheets
   - Use LibreOffice Calc
   - Use text report instead

### "InvalidClientTokenId" error

**Problem:** AWS credentials expired

**Solution:**

1. **For long-term credentials:**
```bash
aws configure
# Re-enter your keys
```

2. **For temporary credentials (SSO):**
```bash
aws sso login --profile your-profile
```

3. **For assumed roles:**
```bash
# Get new session
aws sts assume-role --role-arn YOUR_ROLE_ARN --role-session-name audit
```

### Script freezes or hangs

**Problem:** Network issue or API timeout

**Solutions:**

1. **Press Ctrl+C** to stop

2. **Check log file:**
```bash
tail -f iam_security_analyzer.log
```

3. **Re-run with fewer workers:**
```
Enter max workers: 3
```

4. **Check AWS status:**
Visit: https://status.aws.amazon.com

### Getting more help

**Check the log file:**
```bash
cat iam_security_analyzer.log
```

**Enable debug mode:**
Edit the script and change:
```python
logging.basicConfig(level=logging.DEBUG)
```

**Report issues:**
Include in your report:
- Error message
- Python version: `python3 --version`
- Boto3 version: `pip show boto3`
- Log file excerpt

---

## 📚 Best Practices

### Running Regular Audits

**Set up a schedule:**

```bash
# Monthly audit (runs 1st of month at 2 AM)
0 2 1 * * /usr/bin/python3 /path/to/iam_security_analyzer.py

# Quarterly audit (runs 1st day of Jan/Apr/Jul/Oct)
0 2 1 1,4,7,10 * /usr/bin/python3 /path/to/iam_security_analyzer.py
```

**Create audit checklist:**

- [ ] Run IAM security analyzer
- [ ] Review Summary tab for risk level
- [ ] Delete old unused keys
- [ ] Enable MFA for users without it
- [ ] Contact owners of old used keys
- [ ] Review inactive users/roles
- [ ] Document exceptions
- [ ] Track remediation in tickets
- [ ] Re-run after fixes
- [ ] Archive report securely

### Storing Reports Securely

**Reports contain sensitive data! Protect them:**

**Option 1: Encrypt locally**
```bash
# Encrypt with password
gpg --symmetric iam_security_report_*.xlsx

# Decrypt when needed
gpg iam_security_report_*.xlsx.gpg
```

**Option 2: Upload to secure S3**
```bash
# Upload with encryption
aws s3 cp iam_security_report_*.xlsx \
  s3://your-secure-bucket/audits/ \
  --sse AES256

# Set retention policy
aws s3api put-bucket-lifecycle-configuration \
  --bucket your-secure-bucket \
  --lifecycle-configuration file://retention.json
```

**Option 3: Store in password manager**
- Use 1Password, LastPass, etc.
- Keep with other sensitive documents

**Never:**
- ❌ Commit to git
- ❌ Email unencrypted
- ❌ Store in public locations
- ❌ Share on Slack/Teams

### Tracking Improvements

**Keep historical reports:**

```bash
# Organize by date
reports/
  ├── 2024-11/
  │   └── iam_security_report_*.xlsx
  ├── 2024-12/
  │   └── iam_security_report_*.xlsx
  └── 2025-01/
      └── iam_security_report_*.xlsx
```

**Compare month-over-month:**

| Month | Inactive Users | Old Keys | Users Without MFA | Risk Level |
|-------|----------------|----------|-------------------|------------|
| Nov 2024 | 65 | 52 | 34 | CRITICAL |
| Dec 2024 | 42 | 38 | 18 | HIGH |
| Jan 2025 | 28 | 15 | 8 | MEDIUM |

**Track your progress!** 📈

### Building a Remediation Workflow

**Step 1: Triage (Day 1)**
- Run the analyzer
- Review Summary tab
- Identify critical issues
- Create tickets for each

**Step 2: Critical Fixes (Day 1-2)**
- Delete old unused keys
- Enable MFA for active users
- Disable clearly abandoned accounts

**Step 3: Verification (Day 3-5)**
- Contact owners of old used keys
- Verify inactive users are truly unused
- Document business justification for exceptions

**Step 4: Remediation (Week 1-2)**
- Rotate or delete verified old keys
- Delete confirmed inactive users/roles
- Review and reduce risky permissions

**Step 5: Verification (Week 2)**
- Re-run analyzer
- Confirm improvements
- Document remaining exceptions

**Step 6: Prevention (Ongoing)**
- Set up AWS Config rules
- Implement SCPs for MFA
- Automate key rotation
- Schedule next audit

### Integrating with Other Tools

**AWS Config Rules:**
```bash
# Enable unused credentials check
aws configservice put-config-rule \
  --config-rule file://iam-user-unused-credentials-check.json
```

**AWS CloudWatch Alarms:**
```bash
# Alert on new access key creation
aws cloudwatch put-metric-alarm \
  --alarm-name "New-Access-Key-Created" \
  --alarm-actions arn:aws:sns:region:account:topic
```

**Automation Scripts:**
```bash
# Auto-disable keys older than 365 days
# (After manual review)
```

**Ticketing Integration:**
```python
# Create Jira tickets for findings
# Send Slack notifications
# Email security team
```

---

## 🎓 Understanding IAM Security

### Why IAM Security Matters

**Real-world scenarios:**

**Scenario 1: Compromised Access Key**
- Unused access key leaked on GitHub
- Attacker mines cryptocurrency in your account
- Bill: $50,000 in 3 days
- **Prevention:** Delete unused keys

**Scenario 2: Credential Stuffing**
- User without MFA
- Password breached on another site
- Attacker uses same password
- Data exfiltrated before detection
- **Prevention:** Enforce MFA

**Scenario 3: Over-Privileged Role**
- Lambda function with AdministratorAccess
- Code injection vulnerability
- Full account compromise
- **Prevention:** Least privilege principle

### IAM Security Best Practices

**1. Use Roles, Not Keys**

❌ **Bad:**
```
EC2 instance → Access keys hardcoded
```

✅ **Good:**
```
EC2 instance → IAM role attached
```

**2. Enable MFA Everywhere**

**Especially for:**
- All human users
- Root account (always!)
- Break-glass/emergency accounts
- Any account with sensitive access

**3. Rotate Credentials Regularly**

| Credential Type | Rotation Schedule |
|----------------|-------------------|
| Access keys | Every 90 days |
| Passwords | Every 90 days |
| Root credentials | Every 180 days |
| Service keys | Per policy |

**4. Apply Least Privilege**

Start with minimal permissions, add as needed:

```
1. Start: No permissions
2. User requests: "I need S3 access"
3. Grant: S3 read-only for specific bucket
4. User requests more: "I need to upload"
5. Grant: S3 write for specific prefix
```

Never start with admin and remove!

**5. Monitor and Alert**

Set up alerts for:
- Root account usage
- Failed login attempts
- IAM policy changes
- Access key creation
- MFA device changes

### Common Mistakes to Avoid

❌ **Mistake 1: "Just give admin access"**
- Violates least privilege
- Increases attack surface
- Makes auditing harder

✅ **Better:** Grant specific permissions needed

❌ **Mistake 2: "We'll clean up later"**
- Later never comes
- Accumulates over time
- Becomes overwhelming

✅ **Better:** Clean as you go, audit regularly

❌ **Mistake 3: "Service accounts don't need MFA"**
- True for programmatic access
- But they should use roles, not keys!

✅ **Better:** Use instance profiles and roles

❌ **Mistake 4: "Shared accounts are fine"**
- Can't audit who did what
- Can't revoke individual access
- Passwords get shared insecurely

✅ **Better:** Individual accounts, assume roles

❌ **Mistake 5: "This key is temporary"**
- Keys marked "temp" last years
- Never get cleaned up
- Often have excessive permissions

✅ **Better:** Use STS temporary credentials

---

## 🚀 Advanced Usage

### Running in Different Environments

**AWS CloudShell:**
```bash
# Install dependencies (session-specific)
pip3 install --user openpyxl

# Download script
curl -O [script-url]

# Run
python3 iam_security_analyzer.py

# Download report
# Click Actions → Download file
```

**AWS Lambda:**
```python
# Deploy as Lambda function
# Schedule with EventBridge
# Store reports in S3
# Send alerts via SNS
```

**Docker Container:**
```dockerfile
FROM python:3.9-slim
RUN pip install boto3 openpyxl
COPY iam_security_analyzer.py /app/
WORKDIR /app
CMD ["python", "iam_security_analyzer.py"]
```

**CI/CD Pipeline:**
```yaml
# GitLab CI example
iam-security-audit:
  stage: security
  script:
    - pip install boto3 openpyxl
    - python3 iam_security_analyzer.py
    - aws s3 cp *.xlsx s3://audit-reports/
  only:
    - schedules
```

### Filtering and Exclusions

**Exclude patterns examples:**

```
# Exclude service accounts
service-,svc-,automation-

# Exclude test environments
test-,dev-,temp-,demo-

# Exclude specific prefixes
backup-,readonly-,monitoring-

# Combine multiple patterns
service-,test-,automation-,backup-
```

**Tag-based exclusions:**

The script automatically excludes resources tagged:
```
Type: system
Type: service
Type: automation
```

**Example AWS CLI tag:**
```bash
aws iam tag-user \
  --user-name service-backup \
  --tags Key=Type,Value=service
```

### Customizing Thresholds

**Different use cases:**

**Strict compliance (PCI-DSS, SOC2):**
```
Threshold: 90 days
```

**Standard security:**
```
Threshold: 200 days (default)
```

**Legacy system cleanup:**
```
Threshold: 365 days
```

**Finding ancient credentials:**
```
Threshold: 730 days (2 years)
```

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

## 🤝 Contributing

Want to improve this tool? Contributions welcome!

**Ways to contribute:**
- 🐛 Report bugs
- 💡 Suggest features
- 📖 Improve documentation
- 🔧 Submit code improvements

**How to contribute:**

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Test thoroughly
5. Commit: `git commit -m "Add my feature"`
6. Push: `git push origin my-feature`
7. Open a Pull Request

**Code guidelines:**
- Follow PEP 8 style
- Add docstrings
- Comment complex logic
- Test before submitting

---

## 💬 Support & Community

**Share your experience:**
- ⭐ Star the repo if useful
- 🐦 Tweet about it
- 📝 Write a blog post
- 💼 Use in your organization

---

## 🙏 Acknowledgments

Built with:
- **Boto3** - AWS SDK for Python
- **OpenPyXL** - Excel file creation
- **AWS IAM** - Identity and Access Management

Inspired by AWS security best practices and real-world audit needs.

---

<div align="center">

**Made with ❤️ by [pagoha]**

⭐ Star this repo if you find it useful!

**[Back to Top](#aws-iam-security-analyzer)**

</div>







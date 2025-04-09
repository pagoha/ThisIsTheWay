# AWS Access Key Analyzer for CloudShell [bash]
This script identifies old and unused AWS access keys


1. Log into an AWS account, launch CloudShell, and create the file using GNU nano:

```bash
nano iamAccessKeysAnalyzer.sh
```

2. Copy and paste the entire script below into the GNU nano editor:

```bash
#!/bin/bash

# AWS Access Key Analyzer for CloudShell
# This script identifies old and unused AWS access keys

# Default threshold - 200 days
DAYS_THRESHOLD=200

# Terminal formatting
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)

# Function to create a separator line
create_separator() {
  local char=${1:-"-"}
  local width=${2:-100}
  printf "%${width}s\n" | tr " " "$char"
}

# Function to center text
center_text() {
  local text="$1"
  local width=${2:-100}
  local padding=$(( (width - ${#text}) / 2 ))
  printf "%${padding}s%s%${padding}s\n" "" "$text" ""
}

# Print header
echo
create_separator "=" 80
center_text "AWS ACCESS KEY ANALYZER" 80
create_separator "=" 80
echo
echo "This script identifies:"
echo "  1. AWS access keys that are older than the threshold and never used"
echo "  2. AWS access keys that were last used more than the threshold days ago"
echo

# Get AWS account information (no confirmation needed for CloudShell)
echo "Fetching AWS account information..."
ACCOUNT_INFO=$(aws sts get-caller-identity)
ACCOUNT_ID=$(echo $ACCOUNT_INFO | jq -r '.Account')
IAM_ARN=$(echo $ACCOUNT_INFO | jq -r '.Arn')

echo "AWS Account ID: $ACCOUNT_ID"
echo

# Get threshold
read -p "Enter age threshold in days (or press Enter for default $DAYS_THRESHOLD): " THRESHOLD_INPUT
if [[ -n "$THRESHOLD_INPUT" && "$THRESHOLD_INPUT" =~ ^[0-9]+$ ]]; then
  DAYS_THRESHOLD=$THRESHOLD_INPUT
fi

echo
echo "Fetching and analyzing access keys older than $DAYS_THRESHOLD days..."
echo "This may take several minutes depending on the number of users..."

# Create timestamp for filenames
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TMP_DIR="/tmp/aws_key_analysis_${TIMESTAMP}"
mkdir -p $TMP_DIR

# Create output files
REPORT_FILE="access_keys_report_${ACCOUNT_ID}_${TIMESTAMP}.txt"
UNUSED_KEYS_FILE="${TMP_DIR}/unused_keys.txt"
USED_KEYS_FILE="${TMP_DIR}/used_keys.txt"
USERS_LIST_FILE="${TMP_DIR}/users.txt"

# Write report header
{
  create_separator "=" 140
  center_text "AWS ACCESS KEY ANALYSIS REPORT" 140
  center_text "Account ID: $ACCOUNT_ID" 140
  center_text "Age Threshold: $DAYS_THRESHOLD days" 140
  center_text "Generated at: $(date '+%Y-%m-%d %H:%M:%S')" 140
  create_separator "=" 140
} > "$REPORT_FILE"

# Get all IAM users
echo "Retrieving list of IAM users..."
aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' > "$USERS_LIST_FILE"
USER_COUNT=$(wc -l < "$USERS_LIST_FILE")
echo "Found $USER_COUNT IAM users"

# Initialize counters
UNUSED_COUNT=0
USED_COUNT=0
PROCESSED_COUNT=0

# Process each user
while IFS= read -r USERNAME; do
  PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
  
  # Show progress every 10 users
  if (( PROCESSED_COUNT % 10 == 0 )); then
    echo "Processed $PROCESSED_COUNT/$USER_COUNT users..."
  fi

  # Get user's access keys
  aws iam list-access-keys --user-name "$USERNAME" --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output text | while IFS=$'\t' read -r ACCESS_KEY_ID STATUS CREATE_DATE; do
    # Skip if no keys
    [ -z "$ACCESS_KEY_ID" ] && continue
    
    # Convert CreateDate to epoch for age calculation
    CREATE_EPOCH=$(date -d "$CREATE_DATE" +%s)
    CURRENT_EPOCH=$(date +%s)
    AGE_SECONDS=$((CURRENT_EPOCH - CREATE_EPOCH))
    AGE_DAYS=$((AGE_SECONDS / 86400))
    
    # Only process keys older than threshold
    if [ "$AGE_DAYS" -gt "$DAYS_THRESHOLD" ]; then
      # Get key last used info
      LAST_USED_INFO=$(aws iam get-access-key-last-used --access-key-id "$ACCESS_KEY_ID")
      LAST_USED_DATE=$(echo "$LAST_USED_INFO" | jq -r '.AccessKeyLastUsed.LastUsedDate // ""')
      
      if [ -z "$LAST_USED_DATE" ]; then
        # Key never used
        echo -e "$USERNAME\t$ACCESS_KEY_ID\t$CREATE_DATE\t$AGE_DAYS\t$STATUS" >> "$UNUSED_KEYS_FILE"
      else
        # Key used, check if used recently
        LAST_USED_EPOCH=$(date -d "$LAST_USED_DATE" +%s)
        DAYS_SINCE_LAST_USE=$(( (CURRENT_EPOCH - LAST_USED_EPOCH) / 86400 ))
        
        if [ "$DAYS_SINCE_LAST_USE" -gt "$DAYS_THRESHOLD" ]; then
          SERVICE=$(echo "$LAST_USED_INFO" | jq -r '.AccessKeyLastUsed.ServiceName // "N/A"')
          REGION=$(echo "$LAST_USED_INFO" | jq -r '.AccessKeyLastUsed.Region // "N/A"')
          echo -e "$USERNAME\t$ACCESS_KEY_ID\t$LAST_USED_DATE\t$SERVICE/$REGION\t$AGE_DAYS\t$DAYS_SINCE_LAST_USE\t$STATUS" >> "$USED_KEYS_FILE"
        fi
      fi
    fi
  done
done < "$USERS_LIST_FILE"

echo "Successfully processed all $USER_COUNT users"

# Get counts
if [ -f "$UNUSED_KEYS_FILE" ]; then
  UNUSED_COUNT=$(wc -l < "$UNUSED_KEYS_FILE" || echo 0)
else
  UNUSED_COUNT=0
fi

if [ -f "$USED_KEYS_FILE" ]; then
  USED_COUNT=$(wc -l < "$USED_KEYS_FILE" || echo 0)
else
  USED_COUNT=0
fi

# Append OLD UNUSED KEYS section to report
{
  echo
  create_separator "=" 70
  echo " OLD UNUSED KEYS "
  create_separator "=" 70
  echo "Found $UNUSED_COUNT access keys older than $DAYS_THRESHOLD days that have never been used"
  echo
} >> "$REPORT_FILE"

# If there are unused keys, format and add them to the report
if [ -f "$UNUSED_KEYS_FILE" ] && [ -s "$UNUSED_KEYS_FILE" ]; then
  {
    echo "Username | Access Key ID | Creation Date | Age (days) | Status"
    create_separator "-" 80
  } >> "$REPORT_FILE"
  
  # Sort by age (oldest first) and format the output
  sort -t$'\t' -k4,4nr "$UNUSED_KEYS_FILE" | while IFS=$'\t' read -r USERNAME KEY_ID CREATE_DATE AGE STATUS; do
    printf "%-20s | %-26s | %-20s | %-10s | %-10s\n" "$USERNAME" "$KEY_ID" "$CREATE_DATE" "$AGE" "$STATUS" >> "$REPORT_FILE"
  done
else
  echo "No old unused keys found." >> "$REPORT_FILE"
fi

# Append OLD USED KEYS section to report
{
  echo
  create_separator "=" 70
  echo " OLD USED KEYS "
  create_separator "=" 70
  echo "Found $USED_COUNT access keys not used in the last $DAYS_THRESHOLD days"
  echo
} >> "$REPORT_FILE"

# If there are used keys, format and add them to the report
if [ -f "$USED_KEYS_FILE" ] && [ -s "$USED_KEYS_FILE" ]; then
  {
    echo "Username | Access Key ID | Last Used Date | Service/Region | Age (days) | Days Since | Status"
    create_separator "-" 120
  } >> "$REPORT_FILE"
  
  # Sort by days since last use (longest first) and format the output
  sort -t$'\t' -k6,6nr "$USED_KEYS_FILE" | while IFS=$'\t' read -r USERNAME KEY_ID LAST_USED SERVICE_REGION AGE DAYS_SINCE STATUS; do
    printf "%-20s | %-26s | %-20s | %-20s | %-10s | %-10s | %-8s\n" "$USERNAME" "$KEY_ID" "$LAST_USED" "$SERVICE_REGION" "$AGE" "$DAYS_SINCE" "$STATUS" >> "$REPORT_FILE"
  done
else
  echo "No old used keys found." >> "$REPORT_FILE"
fi

# Add summary and recommendations
TOTAL_ISSUES=$((UNUSED_COUNT + USED_COUNT))
{
  echo
  create_separator "=" 140
  center_text "SUMMARY AND RECOMMENDATIONS" 140
  create_separator "=" 140
} >> "$REPORT_FILE"

if [ "$TOTAL_ISSUES" -gt 0 ]; then
  {
    echo
    echo "Found a total of $TOTAL_ISSUES access keys that require attention:"
    echo "  - $UNUSED_COUNT keys older than $DAYS_THRESHOLD days that have never been used"
    echo "  - $USED_COUNT keys not used in the last $DAYS_THRESHOLD days"
    echo
    echo "Recommended actions:"
    echo "  1. Delete unused keys that are no longer needed"
    echo "  2. Rotate active keys that are older than 90 days"
    echo "  3. Set up AWS Config rule 'iam-user-unused-credentials-check'"
    echo "  4. Implement automated key rotation"
  } >> "$REPORT_FILE"
else
  {
    echo
    echo "No access keys older than $DAYS_THRESHOLD days requiring attention were found."
    echo
    echo "Best practices:"
    echo "  1. Continue to rotate keys regularly (at least every 90 days)"
    echo "  2. Use IAM roles instead of access keys where possible"
    echo "  3. Monitor access key usage with CloudTrail and CloudWatch"
  } >> "$REPORT_FILE"
fi

echo >> "$REPORT_FILE"
create_separator "=" 140 >> "$REPORT_FILE"

# Clean up temporary files
rm -rf "$TMP_DIR"

# Display report location and cat the file
echo
echo "${BOLD}${GREEN}Analysis complete!${NORMAL}"
echo "Detailed report saved to: ${BOLD}$REPORT_FILE${NORMAL}"
echo
echo "Summary:"
echo "  - Found $USER_COUNT IAM users"
echo "  - Found $UNUSED_COUNT unused keys older than $DAYS_THRESHOLD days"
echo "  - Found $USED_COUNT keys not used in the last $DAYS_THRESHOLD days"
echo
echo "${YELLOW}Use 'cat $REPORT_FILE' to view the full report${NORMAL}"
```

3. Save the file by pressing Ctrl+O, then Enter, then Ctrl+X to exit the editor.

4. Make the script executable:

```bash
chmod +x iamAccessKeysAnalyzer.sh
```

5. Now run the script:

```bash
./iamAccessKeysAnalyzer.sh
```

If you get an error, there might be an issue with line endings. Try running:

```bash
dos2unix iamAccessKeysAnalyzer.sh
```

If the `dos2unix` command is not available, you can use:

```bash
sed -i 's/\r$//' iamAccessKeysAnalyzer.sh
```

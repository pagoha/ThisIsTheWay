# AWS S3 Comprehensive Analyzer for CloudShell [bash]
This script analyzes AWS S3 buckets in the current account for security, cost optimization, and governance insights


1. Log into an AWS account, launch CloudShell, and create the file using GNU nano:

```bash
nano S3-Comprehensive-Analyzer.sh
```

2. Copy and paste the entire script below into the GNU nano editor:

```bash
#!/bin/bash

# AWS S3 Comprehensive Analyzer for CloudShell
# This script analyzes S3 buckets in the current AWS account

# Terminal formatting
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)

# Function to create a separator line
create_separator() {
  local char=${1:-"-"}
  local width=${2:-120}
  printf "%${width}s\n" | tr " " "$char"
}

# Function to center text
center_text() {
  local text="$1"
  local width=${2:-120}
  local padding=$(( (width - ${#text}) / 2 ))
  printf "%${padding}s%s%${padding}s\n" "" "$text" ""
}

# Function to format bytes to human readable
format_size() {
  local bytes=$1
  if [[ $bytes -eq 0 ]]; then
    echo "0 B"
    return
  fi
  
  local units=("B" "KB" "MB" "GB" "TB")
  local unit=0
  local size=$bytes
  
  while [[ $size -ge 1024 && $unit -lt 4 ]]; do
    size=$((size / 1024))
    unit=$((unit + 1))
  done
  
  printf "%.2f %s" "$size" "${units[$unit]}"
}

# Print header
echo
create_separator "=" 100
center_text "AWS S3 COMPREHENSIVE ANALYZER" 100
create_separator "=" 100
echo
echo "This script analyzes S3 buckets in the current AWS account for:"
echo "  1. Bucket inventory with sizes and object counts"
echo "  2. Security configurations (encryption, public access)"
echo "  3. Cost optimization opportunities"
echo "  4. Lifecycle policies and governance recommendations"
echo

# Get AWS account information
echo "Fetching AWS account information..."
ACCOUNT_INFO=$(aws sts get-caller-identity)
ACCOUNT_ID=$(echo $ACCOUNT_INFO | jq -r '.Account')
IAM_ARN=$(echo $ACCOUNT_INFO | jq -r '.Arn')

echo "AWS Account ID: $ACCOUNT_ID"
echo

# Get output preferences
echo "Output format options:"
echo "1. Text report only"
echo "2. CSV export only"
echo "3. Both text report and CSV export"
echo

read -p "Select output format (1-3, or press Enter for both): " OUTPUT_CHOICE
case $OUTPUT_CHOICE in
  1) GENERATE_TEXT=true; GENERATE_CSV=false ;;
  2) GENERATE_TEXT=false; GENERATE_CSV=true ;;
  *) GENERATE_TEXT=true; GENERATE_CSV=true ;;
esac

echo
echo "Analyzing S3 buckets in account $ACCOUNT_ID..."
echo "This may take several minutes depending on the number of buckets..."

# Create timestamp for filenames
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TMP_DIR="/tmp/s3_analysis_${TIMESTAMP}"
mkdir -p $TMP_DIR

# Create output files
REPORT_FILE="s3_comprehensive_report_${ACCOUNT_ID}_${TIMESTAMP}.txt"
CSV_FILE="s3_comprehensive_report_${ACCOUNT_ID}_${TIMESTAMP}.csv"
BUCKETS_FILE="${TMP_DIR}/buckets.json"
BUCKET_DETAILS_FILE="${TMP_DIR}/bucket_details.txt"

# Get all S3 buckets
echo "Retrieving list of S3 buckets..."
aws s3api list-buckets > "$BUCKETS_FILE"
BUCKET_COUNT=$(jq -r '.Buckets | length' "$BUCKETS_FILE")

if [[ $BUCKET_COUNT -eq 0 ]]; then
  echo "No S3 buckets found in this account."
  exit 0
fi

echo "Found $BUCKET_COUNT S3 buckets"

# Initialize counters
PROCESSED_COUNT=0
ERROR_COUNT=0
EMPTY_BUCKETS=0
UNENCRYPTED_BUCKETS=0
PUBLIC_BUCKETS=0
NO_LIFECYCLE_BUCKETS=0
LARGE_BUCKETS=0

# Process each bucket
echo "Processing bucket details..."

# CSV header if generating CSV
if [[ $GENERATE_CSV == true ]]; then
  echo "BucketName,Region,CreationDate,AgeInDays,SizeBytes,SizeFormatted,ObjectCount,IsEmpty,VersioningStatus,EncryptionEnabled,PublicAccessBlocked,HasLifecycle,LifecycleRules,SecurityIssues,CostOptimization" > "$CSV_FILE"
fi

# Clear the details file
> "$BUCKET_DETAILS_FILE"

jq -r '.Buckets[] | @base64' "$BUCKETS_FILE" | while IFS= read -r bucket_data; do
  BUCKET_JSON=$(echo "$bucket_data" | base64 -d)
  BUCKET_NAME=$(echo "$BUCKET_JSON" | jq -r '.Name')
  CREATION_DATE=$(echo "$BUCKET_JSON" | jq -r '.CreationDate')
  
  PROCESSED_COUNT=$((PROCESSED_COUNT + 1))
  
  # Show progress every 5 buckets
  if (( PROCESSED_COUNT % 5 == 0 )); then
    echo "  Processed $PROCESSED_COUNT/$BUCKET_COUNT buckets..."
  fi
  
  # Calculate bucket age
  CREATE_EPOCH=$(date -d "$CREATION_DATE" +%s)
  CURRENT_EPOCH=$(date +%s)
  AGE_DAYS=$(( (CURRENT_EPOCH - CREATE_EPOCH) / 86400 ))
  
  # Get bucket region
  REGION_OUTPUT=$(aws s3api get-bucket-location --bucket "$BUCKET_NAME" 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    REGION=$(echo "$REGION_OUTPUT" | jq -r '.LocationConstraint // "us-east-1"')
  else
    REGION="unknown"
    ((ERROR_COUNT++))
    continue
  fi
  
  # Get bucket size and object count (using CloudWatch metrics or list-objects)
  SIZE_BYTES=0
  OBJECT_COUNT=0
  
  # Try CloudWatch metrics first
  CW_SIZE=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/S3 \
    --metric-name BucketSizeBytes \
    --dimensions Name=BucketName,Value="$BUCKET_NAME" Name=StorageType,Value=StandardStorage \
    --statistics Average \
    --start-time $(date -u -d '2 days ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 86400 \
    --region "$REGION" 2>/dev/null)
  
  if [[ $? -eq 0 ]] && [[ $(echo "$CW_SIZE" | jq '.Datapoints | length') -gt 0 ]]; then
    SIZE_BYTES=$(echo "$CW_SIZE" | jq -r '.Datapoints[-1].Average // 0' | cut -d. -f1)
  fi
  
  CW_COUNT=$(aws cloudwatch get-metric-statistics \
    --namespace AWS/S3 \
    --metric-name NumberOfObjects \
    --dimensions Name=BucketName,Value="$BUCKET_NAME" Name=StorageType,Value=AllStorageTypes \
    --statistics Average \
    --start-time $(date -u -d '2 days ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 86400 \
    --region "$REGION" 2>/dev/null)
  
  if [[ $? -eq 0 ]] && [[ $(echo "$CW_COUNT" | jq '.Datapoints | length') -gt 0 ]]; then
    OBJECT_COUNT=$(echo "$CW_COUNT" | jq -r '.Datapoints[-1].Average // 0' | cut -d. -f1)
  fi
  
  # If CloudWatch metrics not available, try to estimate
  if [[ $OBJECT_COUNT -eq 0 ]]; then
    LIST_OUTPUT=$(aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --max-keys 1 2>/dev/null)
    if [[ $? -eq 0 ]] && [[ $(echo "$LIST_OUTPUT" | jq '.Contents | length') -gt 0 ]]; then
      OBJECT_COUNT=1  # Estimated
    fi
  fi
  
  # Determine if bucket is empty
  IS_EMPTY=false
  if [[ $OBJECT_COUNT -eq 0 ]]; then
    IS_EMPTY=true
    ((EMPTY_BUCKETS++))
  fi
  
  # Check if large bucket (>1GB)
  if [[ $SIZE_BYTES -gt 1073741824 ]]; then
    ((LARGE_BUCKETS++))
  fi
  
  # Get versioning status
  VERSIONING_OUTPUT=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    VERSIONING_STATUS=$(echo "$VERSIONING_OUTPUT" | jq -r '.Status // "Disabled"')
  else
    VERSIONING_STATUS="Unknown"
  fi
  
  # Check encryption
  ENCRYPTION_ENABLED=false
  aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" >/dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    ENCRYPTION_ENABLED=true
  else
    ((UNENCRYPTED_BUCKETS++))
  fi
  
  # Check public access block
  PUBLIC_ACCESS_BLOCKED=false
  PAB_OUTPUT=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    BLOCK_PUBLIC_ACLS=$(echo "$PAB_OUTPUT" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls // false')
    IGNORE_PUBLIC_ACLS=$(echo "$PAB_OUTPUT" | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls // false')
    BLOCK_PUBLIC_POLICY=$(echo "$PAB_OUTPUT" | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy // false')
    RESTRICT_PUBLIC_BUCKETS=$(echo "$PAB_OUTPUT" | jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets // false')
    
    if [[ "$BLOCK_PUBLIC_ACLS" == "true" && "$IGNORE_PUBLIC_ACLS" == "true" && 
          "$BLOCK_PUBLIC_POLICY" == "true" && "$RESTRICT_PUBLIC_BUCKETS" == "true" ]]; then
      PUBLIC_ACCESS_BLOCKED=true
    else
      ((PUBLIC_BUCKETS++))
    fi
  else
    ((PUBLIC_BUCKETS++))
  fi
  
  # Check lifecycle configuration
  HAS_LIFECYCLE=false
  LIFECYCLE_RULES=0
  aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET_NAME" >/dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    HAS_LIFECYCLE=true
    LIFECYCLE_OUTPUT=$(aws s3api get-bucket-lifecycle-configuration --bucket "$BUCKET_NAME" 2>/dev/null)
    LIFECYCLE_RULES=$(echo "$LIFECYCLE_OUTPUT" | jq '.Rules | length' 2>/dev/null || echo 0)
  else
    if [[ $IS_EMPTY == false ]]; then
      ((NO_LIFECYCLE_BUCKETS++))
    fi
  fi
  
  # Format size
  SIZE_FORMATTED=$(format_size $SIZE_BYTES)
  
  # Identify security issues
  SECURITY_ISSUES=""
  if [[ $ENCRYPTION_ENABLED == false ]]; then
    SECURITY_ISSUES="No Encryption"
  fi
  if [[ $PUBLIC_ACCESS_BLOCKED == false ]]; then
    if [[ -n "$SECURITY_ISSUES" ]]; then
      SECURITY_ISSUES="$SECURITY_ISSUES; Public Access Not Blocked"
    else
      SECURITY_ISSUES="Public Access Not Blocked"
    fi
  fi
  if [[ -z "$SECURITY_ISSUES" ]]; then
    SECURITY_ISSUES="None"
  fi
  
  # Identify cost optimization opportunities
  COST_OPTIMIZATION=""
  if [[ $IS_EMPTY == true ]]; then
    COST_OPTIMIZATION="Empty Bucket"
  fi
  if [[ $HAS_LIFECYCLE == false && $IS_EMPTY == false ]]; then
    if [[ -n "$COST_OPTIMIZATION" ]]; then
      COST_OPTIMIZATION="$COST_OPTIMIZATION; No Lifecycle Policy"
    else
      COST_OPTIMIZATION="No Lifecycle Policy"
    fi
  fi
  if [[ -z "$COST_OPTIMIZATION" ]]; then
    COST_OPTIMIZATION="None"
  fi
  
  # Store bucket details for reporting
  echo "${BUCKET_NAME}|${REGION}|${CREATION_DATE}|${AGE_DAYS}|${SIZE_BYTES}|${SIZE_FORMATTED}|${OBJECT_COUNT}|${IS_EMPTY}|${VERSIONING_STATUS}|${ENCRYPTION_ENABLED}|${PUBLIC_ACCESS_BLOCKED}|${HAS_LIFECYCLE}|${LIFECYCLE_RULES}|${SECURITY_ISSUES}|${COST_OPTIMIZATION}" >> "$BUCKET_DETAILS_FILE"
  
  # Add to CSV if generating CSV
  if [[ $GENERATE_CSV == true ]]; then
    echo "\"$BUCKET_NAME\",\"$REGION\",\"$CREATION_DATE\",$AGE_DAYS,$SIZE_BYTES,\"$SIZE_FORMATTED\",$OBJECT_COUNT,$IS_EMPTY,\"$VERSIONING_STATUS\",$ENCRYPTION_ENABLED,$PUBLIC_ACCESS_BLOCKED,$HAS_LIFECYCLE,$LIFECYCLE_RULES,\"$SECURITY_ISSUES\",\"$COST_OPTIMIZATION\"" >> "$CSV_FILE"
  fi
done

echo "Successfully processed $BUCKET_COUNT buckets"

# Generate text report if requested
if [[ $GENERATE_TEXT == true ]]; then
  # Calculate totals
  TOTAL_SIZE=0
  TOTAL_OBJECTS=0
  
  while IFS='|' read -r name region created age size_bytes size_formatted objects empty versioning encrypted public_blocked lifecycle lifecycle_rules security cost; do
    TOTAL_SIZE=$((TOTAL_SIZE + size_bytes))
    TOTAL_OBJECTS=$((TOTAL_OBJECTS + objects))
  done < "$BUCKET_DETAILS_FILE"
  
  TOTAL_SIZE_FORMATTED=$(format_size $TOTAL_SIZE)
  
  # Write report header
  {
    create_separator "=" 140
    center_text "AWS S3 COMPREHENSIVE ANALYSIS REPORT" 140
    center_text "Account ID: $ACCOUNT_ID" 140
    center_text "Generated at: $(date '+%Y-%m-%d %H:%M:%S')" 140
    create_separator "=" 140
  } > "$REPORT_FILE"
  
  # Overall summary
  {
    echo
    create_separator "=" 50
    echo " OVERALL SUMMARY "
    create_separator "=" 50
    echo "Total S3 Buckets: $BUCKET_COUNT"
    echo "Total Storage Used: $TOTAL_SIZE_FORMATTED"
    echo "Total Objects: $(printf "%'d" $TOTAL_OBJECTS)"
    echo
    echo "Bucket Categories:"
    echo "  - Empty Buckets: $EMPTY_BUCKETS"
    echo "  - Large Buckets (>1GB): $LARGE_BUCKETS"
    echo "  - Unencrypted Buckets: $UNENCRYPTED_BUCKETS"
    echo "  - Buckets without Public Access Block: $PUBLIC_BUCKETS"
    echo "  - Buckets without Lifecycle Policies: $NO_LIFECYCLE_BUCKETS"
  } >> "$REPORT_FILE"
  
  # Security issues section
  if [[ $UNENCRYPTED_BUCKETS -gt 0 || $PUBLIC_BUCKETS -gt 0 ]]; then
    {
      echo
      create_separator "=" 50
      echo " SECURITY ISSUES "
      create_separator "=" 50
    } >> "$REPORT_FILE"
    
    if [[ $UNENCRYPTED_BUCKETS -gt 0 ]]; then
      {
        echo "Unencrypted buckets ($UNENCRYPTED_BUCKETS):"
        while IFS='|' read -r name region created age size_bytes size_formatted objects empty versioning encrypted public_blocked lifecycle lifecycle_rules security cost; do
          if [[ "$encrypted" == "false" ]]; then
            echo "  - $name ($size_formatted)"
          fi
        done < "$BUCKET_DETAILS_FILE"
      } >> "$REPORT_FILE"
    fi
    
    if [[ $PUBLIC_BUCKETS -gt 0 ]]; then
      {
        echo
        echo "Buckets without public access block ($PUBLIC_BUCKETS):"
        while IFS='|' read -r name region created age size_bytes size_formatted objects empty versioning encrypted public_blocked lifecycle lifecycle_rules security cost; do
          if [[ "$public_blocked" == "false" ]]; then
            echo "  - $name ($size_formatted)"
          fi
        done < "$BUCKET_DETAILS_FILE"
      } >> "$REPORT_FILE"
    fi
  fi
  
  # Top 10 largest buckets
  {
    echo
    create_separator "=" 50
    echo " TOP 10 LARGEST BUCKETS "
    create_separator "=" 50
    echo
    printf "%-30s | %-15s | %-12s | %-15s | %-15s\n" "Bucket Name" "Size" "Objects" "Region" "Encrypted"
    create_separator "-" 100
  } >> "$REPORT_FILE"
  
  # Sort by size and show top 10
  sort -t'|' -k5,5nr "$BUCKET_DETAILS_FILE" | head -10 | while IFS='|' read -r name region created age size_bytes size_formatted objects empty versioning encrypted public_blocked lifecycle lifecycle_rules security cost; do
    printf "%-30s | %-15s | %-12s | %-15s | %-15s\n" "${name:0:29}" "$size_formatted" "$(printf "%'d" $objects)" "$region" "$encrypted" >> "$REPORT_FILE"
  done
  
  # Recommendations
  {
    echo
    create_separator "=" 140
    center_text "RECOMMENDATIONS" 140
    create_separator "=" 140
  } >> "$REPORT_FILE"
  
  if [[ $EMPTY_BUCKETS -gt 0 || $UNENCRYPTED_BUCKETS -gt 0 || $PUBLIC_BUCKETS -gt 0 || $NO_LIFECYCLE_BUCKETS -gt 0 ]]; then
    {
      echo
      echo "Priority Actions:"
      if [[ $EMPTY_BUCKETS -gt 0 ]]; then
        echo "  1. Empty Buckets Cleanup: Review and delete $EMPTY_BUCKETS empty buckets"
      fi
      if [[ $UNENCRYPTED_BUCKETS -gt 0 ]]; then
        echo "  2. Security: Enable encryption on $UNENCRYPTED_BUCKETS unencrypted buckets"
      fi
      if [[ $PUBLIC_BUCKETS -gt 0 ]]; then
        echo "  3. Security: Configure public access block on $PUBLIC_BUCKETS buckets"
      fi
      if [[ $NO_LIFECYCLE_BUCKETS -gt 0 ]]; then
        echo "  4. Cost Optimization: Implement lifecycle policies on $NO_LIFECYCLE_BUCKETS buckets"
      fi
      echo
      echo "Best Practices:"
      echo "  - Enable S3 bucket notifications for security monitoring"
      echo "  - Implement consistent tagging strategy for cost allocation"
      echo "  - Use S3 Storage Lens for ongoing cost optimization"
      echo "  - Set up AWS Config rules for S3 compliance monitoring"
      echo "  - Consider AWS Control Tower for centralized governance"
    } >> "$REPORT_FILE"
  else
    {
      echo
      echo "Excellent! No critical issues found."
      echo
      echo "Maintenance Recommendations:"
      echo "  - Continue regular review of bucket usage and costs"
      echo "  - Monitor S3 access patterns with CloudTrail"
      echo "  - Consider S3 Intelligent Tiering for cost optimization"
      echo "  - Implement automated backup and disaster recovery"
    } >> "$REPORT_FILE"
  fi
  
  echo >> "$REPORT_FILE"
  create_separator "=" 140 >> "$REPORT_FILE"
fi

# Clean up temporary files
rm -rf "$TMP_DIR"

# Display completion message
echo
echo "${BOLD}${GREEN}Analysis complete!${NORMAL}"
echo
echo "Summary:"
echo "  - Total buckets analyzed: $BUCKET_COUNT"
echo "  - Empty buckets: $EMPTY_BUCKETS"
echo "  - Unencrypted buckets: $UNENCRYPTED_BUCKETS"
echo "  - Buckets without public access block: $PUBLIC_BUCKETS"
echo "  - Buckets without lifecycle policies: $NO_LIFECYCLE_BUCKETS"

if [[ $GENERATE_TEXT == true ]]; then
  echo "  - Text report saved: ${BOLD}$REPORT_FILE${NORMAL}"
fi

if [[ $GENERATE_CSV == true ]]; then
  echo "  - CSV export saved: ${BOLD}$CSV_FILE${NORMAL}"
fi

echo
if [[ $GENERATE_TEXT == true ]]; then
  echo "${YELLOW}Use 'cat $REPORT_FILE' to view the full report${NORMAL}"
fi
if [[ $GENERATE_CSV == true ]]; then
  echo "${YELLOW}Use 'head $CSV_FILE' to preview the CSV export${NORMAL}"
fi
```

3. Save the file by pressing Ctrl+O, then Enter, then Ctrl+X to exit the GNU nano editor.

4. Make the script executable:

```bash
chmod +x S3-Comprehensive-Analyzer.sh
```

5. Now run the script:

```bash
./S3-Comprehensive-Analyzer.sh
```

If you get an error, there might be an issue with line endings. Try running:

```bash
dos2unix S3-Comprehensive-Analyzer.sh
```

If the `dos2unix` command is not available, you can use:

```bash
sed -i 's/\r$//' S3-Comprehensive-Analyzer.sh
```

## CloudShell Usage Notes

- **Single Account**: Analyzes buckets in the current CloudShell account only
- **No Profile Selection**: Uses current CloudShell credentials automatically  
- **CloudWatch Integration**: Attempts to get accurate size/object counts from CloudWatch metrics
- **Output Options**: Choose between text reports, CSV exports, or both formats
- **Progress Tracking**: Shows progress during bucket analysis
- **Error Handling**: Continues analysis even if some buckets have permission issues

## View Generated Reports

After the analysis completes, you can view the reports using:

```bash
# View the text report
cat s3_comprehensive_report_ACCOUNTID_TIMESTAMP.txt

# Or use less for easier navigation
less s3_comprehensive_report_ACCOUNTID_TIMESTAMP.txt

# Preview CSV data
head s3_comprehensive_report_ACCOUNTID_TIMESTAMP.csv
```


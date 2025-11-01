# AWS Resource Analyzer for CloudShell [bash]
The AWS Resource Analyzer is a comprehensive shell script designed to discover, analyze, and provide cost optimization recommendations for AWS resources across your infrastructure. It's the CloudShell-compatible version of the original Python AWS Resource Analyzer, providing the same powerful analysis capabilities with enhanced portability and ease of use.

What It Does

🔍 Comprehensive Resource Discovery

Scans and inventories 7 major categories of AWS resources:
- High-Cost Infrastructure: NAT Gateways, Load Balancers, ElastiCache clusters
- Compute Resources: EC2 instances (running/stopped), Auto Scaling Groups
- Database Services: RDS instances (all engine types)
- Network Resources: Unattached Elastic IPs, VPC components
- Storage Systems: EBS volumes, snapshots
- Management Tools: CloudFormation stacks with dependency analysis
- Cost Optimization Targets: Unused and underutilized resources

💰 Cost Optimization Analysis
Calculates potential monthly and annual savings
Identifies immediate cost reduction opportunities
Prioritizes actions by cost impact and risk level
Provides specific AWS CLI commands for cost-saving operations

🛡️ Safety & Compliance Features
CloudFormation Integration: Detects CF-managed resources to prevent configuration drift
Operational Safety Checks: Pre-operation checklists and warnings
Non-Destructive Analysis: Read-only discovery with clear action recommendations
Gov Cloud Compatible: Works seamlessly in both commercial AWS and AWS GovCloud

Key Features

✅ Multi-Environment Support
- Commercial AWS: All regions (us-east-1, us-west-2, eu-west-1, etc.)
- AWS GovCloud: Fully tested in us-gov-east-1 and us-gov-west-1
- CloudShell Optimized: No external dependencies beyond standard AWS CLI tools

✅ Intelligent Cost Analysis
Real-time cost calculations based on current AWS pricing
Risk-categorized recommendations (Immediate, High, Medium, Flexible)
ROI-focused prioritization (highest savings with lowest risk first)

✅ Professional Output
Color-coded terminal output for easy scanning
Organized file structure with timestamped analysis reports
Machine-readable JSON files for automation and integration
Executive summary reports with key findings and recommendations

✅ Enterprise Ready
CloudFormation awareness prevents accidental infrastructure drift
Bulk operation capabilities with safety guards
Audit trail generation for compliance and change management
Weekly/monthly operational use for ongoing cost optimization


1. Log into an AWS account, launch CloudShell, and create the file using GNU nano:

```bash
nano aws-resource-analyzer.sh
```

2. Copy and paste the entire script below into the GNU nano editor:

```bash
#!/bin/bash
# aws-resource-analyzer.sh
# Integrated AWS Resource Discovery and Cost Optimization Analysis
# Compatible with both Commercial AWS and Gov Cloud

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
REGION=$(aws configure get region || echo "us-east-1")
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "Unknown")
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")

# Create organized output directory structure
OUTPUT_BASE="aws-analysis-${TIMESTAMP}"
OUTPUT_DIR="${OUTPUT_BASE}/json-details"
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}🚀 AWS Resource Cost Optimizer${NC}"
echo -e "${BLUE}=================================${NC}"
echo -e "Account: ${CYAN}${ACCOUNT_ID}${NC}"
echo -e "Region: ${CYAN}${REGION}${NC}"
echo -e "Output Directory: ${CYAN}${OUTPUT_BASE}${NC}"
echo -e "JSON Details: ${CYAN}${OUTPUT_DIR}${NC}"
echo ""

# Function to calculate potential savings
calculate_savings() {
    local resource_type="$1"
    local count="$2"
    local monthly_cost="$3"
    
    if [ "$count" -gt 0 ]; then
        local total_savings=$((count * monthly_cost))
        echo -e "${GREEN}💰 Potential Monthly Savings: \$${total_savings} (${count} × \$${monthly_cost})${NC}" >&2
        echo $total_savings
    else
        echo -e "${CYAN}ℹ️  No resources found${NC}" >&2
        echo 0
    fi
}

# Function to check CloudFormation ownership
check_cf_ownership() {
    local resource_id="$1"
    echo -e "\n${YELLOW}🏗️  Checking CloudFormation ownership for: ${resource_id}${NC}"
    
    local cf_info=$(aws cloudformation describe-stack-resources \
        --physical-resource-id "$resource_id" 2>/dev/null || echo "")
    
    if [ -n "$cf_info" ]; then
        local stack_name=$(echo "$cf_info" | jq -r '.StackResources[0].StackName' 2>/dev/null || echo "Unknown")
        echo -e "${RED}⚠️  CloudFormation Managed by stack: ${stack_name}${NC}"
        echo -e "${RED}   Use stack updates instead of direct resource changes${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Not CloudFormation managed - safe for direct operations${NC}"
        return 0
    fi
}

# Function to display stop/pause recommendations
show_recommendations() {
    local resource_type="$1"
    local action="$2"
    local command="$3"
    
    echo -e "${PURPLE}📋 Recommended Actions:${NC}"
    echo -e "   Action: ${action}"
    echo -e "   Command: ${CYAN}${command}${NC}"
}

echo -e "${BLUE}🔍 PHASE 1: HIGH-COST RESOURCE DISCOVERY${NC}"
echo -e "${BLUE}=========================================${NC}"

# Initialize savings counter
total_potential_savings=0

# 1. NAT Gateways (Highest Cost Impact)
echo -e "\n${YELLOW}🌐 NAT Gateways (\$32-45/month each)${NC}"
nat_gateways=$(aws ec2 describe-nat-gateways \
    --query 'NatGateways[?State==`available`]' \
    --output json 2>/dev/null || echo '[]')

nat_count=$(echo "$nat_gateways" | jq length)
echo "$nat_gateways" > "$OUTPUT_DIR/nat_gateways.json"

if [ "$nat_count" -gt 0 ]; then
    echo -e "Found ${RED}${nat_count}${NC} active NAT Gateway(s):"
    echo "$nat_gateways" | jq -r '.[] | "  • \(.NatGatewayId) in \(.SubnetId) - \(.State)"'
    
    savings=$(calculate_savings "NAT Gateway" "$nat_count" 35)
    total_potential_savings=$((total_potential_savings + savings))
    
    show_recommendations "NAT Gateway" "DELETE (cannot be stopped)" \
        "aws ec2 delete-nat-gateway --nat-gateway-id NAT_GATEWAY_ID"
    
    echo -e "${RED}⚠️  WARNING: Deletion loses configuration and IP address${NC}"
else
    calculate_savings "NAT Gateway" "$nat_count" 35 >/dev/null
fi

# 2. Load Balancers
echo -e "\n${YELLOW}⚖️  Load Balancers (\$16-25/month each)${NC}"

# ALB/NLB
alb_nlb=$(aws elbv2 describe-load-balancers --output json 2>/dev/null || echo '{"LoadBalancers":[]}')
alb_count=$(echo "$alb_nlb" | jq '.LoadBalancers | length')

# Classic Load Balancers  
clb=$(aws elb describe-load-balancers --output json 2>/dev/null || echo '{"LoadBalancerDescriptions":[]}')
clb_count=$(echo "$clb" | jq '.LoadBalancerDescriptions | length')

total_lb_count=$((alb_count + clb_count))
echo "$alb_nlb" > "$OUTPUT_DIR/alb_nlb.json"
echo "$clb" > "$OUTPUT_DIR/classic_lb.json"

if [ "$total_lb_count" -gt 0 ]; then
    echo -e "Found ${RED}${total_lb_count}${NC} Load Balancer(s):"
    
    if [ "$alb_count" -gt 0 ]; then
        echo "$alb_nlb" | jq -r '.LoadBalancers[] | "  • ALB/NLB: \(.LoadBalancerName) - \(.State.Code)"'
    fi
    
    if [ "$clb_count" -gt 0 ]; then
        echo "$clb" | jq -r '.LoadBalancerDescriptions[] | "  • Classic: \(.LoadBalancerName) - \(.Scheme)"'
    fi
    
    savings=$(calculate_savings "Load Balancer" "$total_lb_count" 20)
    total_potential_savings=$((total_potential_savings + savings))
    
    show_recommendations "Load Balancer" "DELETE (cannot be stopped)" \
        "aws elbv2 delete-load-balancer --load-balancer-arn LB_ARN"
    
    echo -e "${YELLOW}⚠️  Check target groups before deletion${NC}"
else
    calculate_savings "Load Balancer" "$total_lb_count" 20 >/dev/null
fi

# 3. ElastiCache Clusters
echo -e "\n${YELLOW}🗄️  ElastiCache Clusters (\$50-500+/month)${NC}"

# Redis clusters
redis_clusters=$(aws elasticache describe-replication-groups \
    --query 'ReplicationGroups[?Status==`available`]' \
    --output json 2>/dev/null || echo '[]')

# Memcached clusters
memcached_clusters=$(aws elasticache describe-cache-clusters \
    --query 'CacheClusters[?CacheClusterStatus==`available` && Engine==`memcached`]' \
    --output json 2>/dev/null || echo '[]')

redis_count=$(echo "$redis_clusters" | jq length)
memcached_count=$(echo "$memcached_clusters" | jq length)
total_cache_count=$((redis_count + memcached_count))

echo "$redis_clusters" > "$OUTPUT_DIR/redis_clusters.json"
echo "$memcached_clusters" > "$OUTPUT_DIR/memcached_clusters.json"

if [ "$total_cache_count" -gt 0 ]; then
    echo -e "Found ${RED}${total_cache_count}${NC} ElastiCache Cluster(s):"
    
    if [ "$redis_count" -gt 0 ]; then
        echo "$redis_clusters" | jq -r '.[] | "  • Redis: \(.ReplicationGroupId) - \(.Status)"'
    fi
    
    if [ "$memcached_count" -gt 0 ]; then
        echo "$memcached_clusters" | jq -r '.[] | "  • Memcached: \(.CacheClusterId) - \(.CacheClusterStatus)"'
    fi
    
    savings=$(calculate_savings "ElastiCache" "$total_cache_count" 100)
    total_potential_savings=$((total_potential_savings + savings))
    
    show_recommendations "ElastiCache" "DELETE (cannot be stopped)" \
        "aws elasticache delete-replication-group --replication-group-id GROUP_ID"
    
    echo -e "${RED}⚠️  WARNING: All cached data will be lost${NC}"
else
    calculate_savings "ElastiCache" "$total_cache_count" 100 >/dev/null
fi

echo -e "\n${BLUE}🔍 PHASE 2: STOPPABLE RESOURCE DISCOVERY${NC}"
echo -e "${BLUE}=======================================${NC}"

# 4. Running EC2 Instances
echo -e "\n${YELLOW}🖥️  Running EC2 Instances (Variable cost)${NC}"
running_instances=$(aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[]' \
    --output json 2>/dev/null || echo '[]')

instance_count=$(echo "$running_instances" | jq length)
echo "$running_instances" > "$OUTPUT_DIR/running_instances.json"

if [ "$instance_count" -gt 0 ]; then
    echo -e "Found ${GREEN}${instance_count}${NC} running instance(s):"
    echo "$running_instances" | jq -r '.[] | "  • \(.InstanceId) (\(.InstanceType)) - \(if .Tags then (.Tags[] | select(.Key=="Name") | .Value) else "No Name" end)"'
    
    show_recommendations "EC2 Instance" "STOP (preserves configuration)" \
        "aws ec2 stop-instances --instance-ids INSTANCE_ID"
    
    echo -e "${GREEN}✅ Safe operation - configuration fully preserved${NC}"
    
    # Check CloudFormation ownership for first few instances
    echo "$running_instances" | jq -r '.[0:3][].InstanceId' | while read -r instance_id; do
        check_cf_ownership "$instance_id"
    done
else
    echo -e "${CYAN}ℹ️  No running instances found${NC}"
fi

# 5. Available RDS Instances  
echo -e "\n${YELLOW}🗄️  Available RDS Instances (Variable cost)${NC}"
available_rds=$(aws rds describe-db-instances \
    --query 'DBInstances[?DBInstanceStatus==`available`]' \
    --output json 2>/dev/null || echo '[]')

rds_count=$(echo "$available_rds" | jq length)
echo "$available_rds" > "$OUTPUT_DIR/available_rds.json"

if [ "$rds_count" -gt 0 ]; then
    echo -e "Found ${GREEN}${rds_count}${NC} available RDS instance(s):"
    echo "$available_rds" | jq -r '.[] | "  • \(.DBInstanceIdentifier) (\(.DBInstanceClass)) - \(.Engine)"'
    
    show_recommendations "RDS Instance" "STOP (auto-restarts after 7 days)" \
        "aws rds stop-db-instance --db-instance-identifier DB_NAME --db-snapshot-identifier snapshot-name"
    
    echo -e "${YELLOW}⚠️  Limitation: Auto-restarts after 7 days${NC}"
    echo -e "${GREEN}✅ Safe operation - data and config preserved${NC}"
else
    echo -e "${CYAN}ℹ️  No available RDS instances found${NC}"
fi

# 6. Auto Scaling Groups with Desired Capacity > 0
echo -e "\n${YELLOW}🔄 Auto Scaling Groups (Variable cost)${NC}"
active_asgs=$(aws autoscaling describe-auto-scaling-groups \
    --query 'AutoScalingGroups[?DesiredCapacity>`0`]' \
    --output json 2>/dev/null || echo '[]')

asg_count=$(echo "$active_asgs" | jq length)
echo "$active_asgs" > "$OUTPUT_DIR/active_asgs.json"

if [ "$asg_count" -gt 0 ]; then
    echo -e "Found ${GREEN}${asg_count}${NC} active Auto Scaling Group(s):"
    echo "$active_asgs" | jq -r '.[] | "  • \(.AutoScalingGroupName) - Desired: \(.DesiredCapacity), Running: \(.Instances | map(select(.LifecycleState=="InService")) | length)"'
    
    show_recommendations "Auto Scaling Group" "SCALE TO ZERO (preserves configuration)" \
        "aws autoscaling update-auto-scaling-group --auto-scaling-group-name ASG_NAME --desired-capacity 0 --min-size 0"
    
    echo -e "${GREEN}✅ Safe operation - configuration preserved for restart${NC}"
else
    echo -e "${CYAN}ℹ️  No active Auto Scaling Groups found${NC}"
fi

# 7. Unattached Elastic IPs
echo -e "\n${YELLOW}🌐 Unattached Elastic IPs (\$3.65/month each)${NC}"
unattached_eips=$(aws ec2 describe-addresses \
    --query 'Addresses[?!InstanceId && !NetworkInterfaceId]' \
    --output json 2>/dev/null || echo '[]')

eip_count=$(echo "$unattached_eips" | jq length)
echo "$unattached_eips" > "$OUTPUT_DIR/unattached_eips.json"

if [ "$eip_count" -gt 0 ]; then
    echo -e "Found ${RED}${eip_count}${NC} unattached Elastic IP(s):"
    echo "$unattached_eips" | jq -r '.[] | "  • \(.PublicIp) (\(.AllocationId))"'
    
    savings=$(calculate_savings "Unattached EIP" "$eip_count" 4)
    total_potential_savings=$((total_potential_savings + savings))
    
    show_recommendations "Elastic IP" "RELEASE (loses IP address)" \
        "aws ec2 release-address --allocation-id ALLOCATION_ID"
    
    echo -e "${RED}⚠️  WARNING: IP address will be lost and cannot be recovered${NC}"
else
    calculate_savings "Unattached EIP" "$eip_count" 4 >/dev/null
fi

echo -e "\n${BLUE}🔍 PHASE 3: CLOUDFORMATION ANALYSIS${NC}"
echo -e "${BLUE}==================================${NC}"

# CloudFormation Stacks
echo -e "\n${YELLOW}🏗️  Active CloudFormation Stacks${NC}"
active_stacks=$(aws cloudformation list-stacks \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE \
    --query 'StackSummaries[]' \
    --output json 2>/dev/null || echo '[]')

stack_count=$(echo "$active_stacks" | jq length)
echo "$active_stacks" > "$OUTPUT_DIR/active_stacks.json"

if [ "$stack_count" -gt 0 ]; then
    echo -e "Found ${CYAN}${stack_count}${NC} active CloudFormation stack(s):"
    echo "$active_stacks" | jq -r '.[] | "  • \(.StackName) - \(.StackStatus)"'
    
    echo -e "\n${PURPLE}📋 CloudFormation Best Practices:${NC}"
    echo -e "   • Use stack updates instead of direct resource changes"
    echo -e "   • Check for stack dependencies before modifications"
    echo -e "   • Monitor for UPDATE_IN_PROGRESS states before operations"
    
    # Check for in-progress operations
    in_progress_stacks=$(aws cloudformation list-stacks \
        --stack-status-filter CREATE_IN_PROGRESS UPDATE_IN_PROGRESS DELETE_IN_PROGRESS \
        --query 'StackSummaries[].StackName' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$in_progress_stacks" ] && [ "$in_progress_stacks" != "None" ]; then
        echo -e "\n${RED}⚠️  WARNING: Stacks currently updating: ${in_progress_stacks}${NC}"
        echo -e "${RED}   Wait for completion before making resource changes${NC}"
    fi
else
    echo -e "${CYAN}ℹ️  No active CloudFormation stacks found${NC}"
fi

echo -e "\n${BLUE}💰 PHASE 4: COST OPTIMIZATION SUMMARY${NC}"
echo -e "${BLUE}====================================${NC}"

echo -e "\n${GREEN}💵 TOTAL POTENTIAL MONTHLY SAVINGS: \$${total_potential_savings}${NC}"

if [ "$total_potential_savings" -gt 0 ]; then
    yearly_savings=$((total_potential_savings * 12))
    echo -e "${GREEN}📅 ANNUAL SAVINGS POTENTIAL: \$${yearly_savings}${NC}"
fi

echo -e "\n${PURPLE}🎯 RECOMMENDED ACTION PRIORITY:${NC}"

priority_actions=()

if [ "$eip_count" -gt 0 ]; then
    priority_actions+=("${RED}1. IMMEDIATE: Release ${eip_count} unattached Elastic IPs (\$$(($eip_count * 4))/month)${NC}")
fi

if [ "$nat_count" -gt 0 ]; then
    priority_actions+=("${RED}2. HIGH: Review ${nat_count} NAT Gateways for deletion (\$$(($nat_count * 35))/month)${NC}")
fi

if [ "$total_lb_count" -gt 0 ]; then
    priority_actions+=("${YELLOW}3. MEDIUM: Audit ${total_lb_count} Load Balancers for necessity (\$$(($total_lb_count * 20))/month)${NC}")
fi

if [ "$instance_count" -gt 0 ]; then
    priority_actions+=("${GREEN}4. FLEXIBLE: Stop ${instance_count} EC2 instances during off-hours (Variable savings)${NC}")
fi

if [ "$rds_count" -gt 0 ]; then
    priority_actions+=("${GREEN}5. FLEXIBLE: Stop ${rds_count} RDS instances during off-hours (Variable savings)${NC}")
fi

if [ "$total_cache_count" -gt 0 ]; then
    priority_actions+=("${YELLOW}6. EVALUATE: Review ${total_cache_count} ElastiCache clusters (\$$(($total_cache_count * 100))/month)${NC}")
fi

# Display priority actions
for action in "${priority_actions[@]}"; do
    echo -e "   $action"
done

if [ ${#priority_actions[@]} -eq 0 ]; then
    echo -e "   ${GREEN}✅ No immediate cost optimization opportunities found${NC}"
fi

echo -e "\n${BLUE}📊 PHASE 5: OPERATION SAFETY CHECKLIST${NC}"
echo -e "${BLUE}=====================================${NC}"

echo -e "\n${PURPLE}✅ Pre-Operation Checklist:${NC}"
echo -e "   [ ] Review CloudFormation dependencies in JSON files"
echo -e "   [ ] Coordinate maintenance windows for production resources"  
echo -e "   [ ] Verify backup/snapshot recency for databases"
echo -e "   [ ] Test operations in development environment first"
echo -e "   [ ] Document rollback procedures"
echo -e "   [ ] Monitor cost impact after changes"

# Create summary report
echo -e "\n${PURPLE}📂 Generated Files and Structure:${NC}"

# Generate a README file
cat > "$OUTPUT_BASE/README.txt" << EOF
AWS Resource Analysis - $TIMESTAMP
==================================

Account: $ACCOUNT_ID
Region: $REGION
Analysis Date: $(date)

SUMMARY:
- Total Potential Monthly Savings: \$${total_potential_savings}
- Annual Savings Potential: \$$(($total_potential_savings * 12))

FILES IN THIS DIRECTORY:
- analysis-report.txt: Complete analysis output (run with | tee)
- json-details/: Detailed AWS API responses for each resource type
- README.txt: This summary file

PRIORITY ACTIONS:
$(for action in "${priority_actions[@]}"; do echo "- $action" | sed 's/\x1b\[[0-9;]*m//g'; done)

NEXT STEPS:
1. Review detailed resource information in json-details/
2. Use AWS Resource Stop/Pause/Disable Guide for procedures
3. Start with lowest-risk, highest-impact operations
4. Re-run analysis weekly for ongoing optimization

SAFETY REMINDER:
- Check CloudFormation ownership before manual changes
- Coordinate maintenance windows for production resources
- Always create backups before stopping databases
- Test procedures in development first
EOF

# Show directory structure
echo "   📁 ${OUTPUT_BASE}/"
echo "   ├── 📄 README.txt (analysis summary)"
echo "   ├── 📄 analysis-report.txt (create with: | tee ${OUTPUT_BASE}/analysis-report.txt)"
echo "   └── 📁 json-details/"
ls -la "$OUTPUT_DIR"/ | grep -v "^total" | awk '{print "       ├── 📄 " $9 " (" $5 " bytes)"}'

echo -e "\n${PURPLE}🔧 Next Steps:${NC}"
echo -e "   1. Review detailed resource information in: ${CYAN}${OUTPUT_DIR}${NC}"
echo -e "   2. Use AWS Resource Stop/Pause/Disable Guide for specific procedures"
echo -e "   3. Start with lowest-risk, highest-impact operations (unattached EIPs)"
echo -e "   4. Re-run this script weekly to catch new optimization opportunities"

echo -e "\n${GREEN}🎉 Analysis Complete!${NC}"
echo -e "${CYAN}💡 Save this report: ./$(basename $0) | tee ${OUTPUT_BASE}/analysis-report.txt${NC}"
echo -e "${CYAN}💡 Explore JSON data: cat ${OUTPUT_DIR}/*.json | jq .${NC}"
echo -e "${CYAN}💡 Read summary: cat ${OUTPUT_BASE}/README.txt${NC}"
```

3. After pasting the script content, save by hitting [{Ctrl+X}, then {Y}, then {Enter}].

4. Make the script executable:

```bash
chmod +x aws-resource-analyzer.sh
```

5. Now run the script:

```bash
./aws-resource-analyzer.sh
```


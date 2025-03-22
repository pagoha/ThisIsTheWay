# AWS CLI - Powershell Command To List Instances and Tags
# Run this script in your PowerShell terminal by copying and pasting the whole script.
# This script will output a text file showing a list of your EC2 instances, their names (if available), and their tags, with proper separation between instances. It will also show total instances and region at bottom of file.
# 
# Pre-requisite:
# - Make sure your AWS Config File is configured
# - Run [aws sso login] to authenticate and start sso session
# - Run [aws s3 ls --profile <INSERTT Profile Name>] to confirm access
# - Update the command/code with the AWS Profile name you want to use before running
# - Copy and paste [Ctrl V] the whole code into your terminal window then hit enter to run

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$fileName = "EC2_Instances_Tags_Report_$timestamp.txt"

$instanceCount = 0
$output = aws ec2 describe-instances --profile <INSERT PROFILE FROM AWS CONFIG FILE> --query 'Reservations[*].Instances[*].[InstanceId, Tags]' --output json | ConvertFrom-Json | ForEach-Object { 
    $_ | ForEach-Object { 
        $instanceCount++
        $instanceId = $_[0]
        $tags = $_[1]
        $instanceName = ($tags | Where-Object { $_.Key -eq "Name" }).Value
        
        "Instance ID: $instanceId"
        if ($instanceName) {
            "Instance Name: $instanceName"
        } else {
            "Instance Name: N/A"
        }
        "Tags:"
        if ($tags) {
            $tags | Where-Object { $_.Key -ne "Name" } | ForEach-Object { "  $($_.Key): $($_.Value)" }
        } else {
            "  No tags"
        }
        "`n"
    }
}

# Get the current region
$region = aws ec2 describe-availability-zones --profile <INSERT PROFILE FROM AWS CONFIG FILE> --query 'AvailabilityZones[0].RegionName' --output text

$output + "Total number of instances: $instanceCount`nRegion: $region" | Out-File -FilePath $fileName

Write-Host "Report saved as $fileName"

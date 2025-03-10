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

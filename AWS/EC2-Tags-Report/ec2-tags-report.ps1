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
$fileName = "EC2_Instances_Tags_Report_$timestamp.csv"

# Define the profiles and regions you want to scan
$profilesToScan = @("PROFLE1", "PROFILE2", "PROFILE3")  # Add your AWS profiles here
$regionsToScan = @("us-east-1", "us-west-2")  # Add your desired regions here

$instanceData = @()
$instanceCount = 0

foreach ($profile in $profilesToScan) {
    Write-Host "Processing profile: $profile"
    
    foreach ($region in $regionsToScan) {
        Write-Host "  Processing region: $region"
        
        try {
            aws ec2 describe-instances --profile $profile --region $region --query 'Reservations[*].Instances[*].[InstanceId, Tags, State.Name, InstanceType, LaunchTime]' --output json | ConvertFrom-Json | ForEach-Object { 
                $_ | ForEach-Object { 
                    $instanceCount++
                    $instanceId = $_[0]
                    $tags = $_[1]
                    $state = $_[2]
                    $instanceType = $_[3]
                    $launchTime = $_[4]
                    
                    $instanceName = ($tags | Where-Object { $_.Key -eq "Name" }).Value
                    $environment = ($tags | Where-Object { $_.Key -eq "Environment" }).Value
                    $owner = ($tags | Where-Object { $_.Key -eq "Owner" }).Value
                    $costCenter = ($tags | Where-Object { $_.Key -eq "CostCenter" }).Value
                    
                    # Create custom object for CSV (now includes profile and region)
                    $instanceObj = [PSCustomObject]@{
                        'AWS Profile' = $profile  # Add profile to the output
                        'Region' = $region        # Add region to the output
                        'Instance ID' = $instanceId
                        'Instance Name' = if ($instanceName) { $instanceName } else { "N/A" }
                        'State' = $state
                        'Instance Type' = $instanceType
                        'Launch Time' = $launchTime
                        'Environment' = if ($environment) { $environment } else { "N/A" }
                        'Owner' = if ($owner) { $owner } else { "N/A" }
                        'Cost Center' = if ($costCenter) { $costCenter } else { "N/A" }
                    }
                    
                    # Add other tags
                    if ($tags) {
                        $tags | Where-Object { $_.Key -notin @("Name", "Environment", "Owner", "CostCenter") } | ForEach-Object {
                            $instanceObj | Add-Member -MemberType NoteProperty -Name "Tag: $($_.Key)" -Value $_.Value
                        }
                    }
                    
                    $instanceData += $instanceObj
                }
            }
        }
        catch {
            Write-Warning "Failed to process profile '$profile' in region '$region': $($_.Exception.Message)"
        }
    }
}

# Export to CSV
$instanceData | Export-Csv -Path $fileName -NoTypeInformation

# Create summary
$summaryFile = "EC2_Summary_$timestamp.txt"
"EC2 Instances Report Summary" | Out-File -FilePath $summaryFile
"Generated: $(Get-Date)" | Out-File -FilePath $summaryFile -Append
"Profiles Scanned: $($profilesToScan -join ', ')" | Out-File -FilePath $summaryFile -Append
"Regions Scanned: $($regionsToScan -join ', ')" | Out-File -FilePath $summaryFile -Append
"Total Instances: $instanceCount" | Out-File -FilePath $summaryFile -Append
"Report File: $fileName" | Out-File -FilePath $summaryFile -Append

Write-Host "CSV report saved as $fileName"
Write-Host "Summary saved as $summaryFile"
Write-Host "Total instances processed: $instanceCount across $($profilesToScan.Count) profiles and $($regionsToScan.Count) regions"

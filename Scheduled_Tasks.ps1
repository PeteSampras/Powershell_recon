# this script assumes you have a list of IPs with a column header of ip.

#date and time stamps
$Date = Get-Date -Format "yyyyMMdd"
$Time = Get-Date -Format "hhMMss"

#comment $creds out if you are using in multiple scripts or it will be super annoying
#$creds = Get-Credential

#change csv files to match what you need
$inputfile = ".\AllHosts.csv"
$outputfile = ".\"+$Date+"_"+$Time+"_Scheduled_Tasks.csv"

$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique


Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
$HostName =(Get-CimInstance -ClassName Win32_ComputerSystem).Name 
schtasks /query /V /FO CSV | ConvertFrom-Csv |
    Where-Object {$_."Scheduled Task State" -eq "Enabled"} |
        Select-Object -Property @{n="Domain";e={$Domain}},
                                @{n="HostName";e={$HostName}}, 
                                TaskName,
                                Status,
                                "Run As User",
                                "Schedule Time",
                                "Next Run Time",
                                "Last Run Time",
                                "Start Time",
                                "End Time",
                                "End Date",
                                "Task to Run",
                                @{n="Hash";e={(Get-FileHash -Path (($_."Task to Run") -replace "\.exe.*",".exe" -replace '"', '') -ErrorAction SilentlyContinue).hash}},
                                @{n="Date";e={$Date}},
                                @{n="Time";e={$Time}}
} | Export-Csv -Path $outputfile

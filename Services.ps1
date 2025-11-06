# this script assumes you have a list of IPs with a column header of ip.

#date and time stamps
$Date = Get-Date -Format "yyyyMMdd"
$Time = Get-Date -Format "hhMMss"

#comment $creds out if you are using in multiple scripts or it will be super annoying
#$creds = Get-Credential

#change csv files to match what you need
$inputfile = ".\AllHosts.csv"
$outputfile = ".\"+$Date+"_"+$Time+"_Services.csv"

$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique

#invoke command
Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
Get-CimInstance -ClassName Win32_Service |
        Select-Object -Property @{n="Domain";e={(Get-WmiObject Win32_ComputerSystem).Domain}},
                                @{n="HostName";e={(Get-CimInstance -ClassName Win32_ComputerSystem).Name}},
                                @{n="ServiceName";e={$_.name}},
                                @{n="Status";e={$_.state}},
                                @{n="StartType";e={$_.startmode}},
                                @{n="Hash";e={(Get-FileHash -Path ($_.PathName -replace "\.exe.*",".exe" -replace '"', '')).hash}},
                                @{n="ProcessName";e={(Get-Process -Id $_.ProcessID).ProcessName}},
                                PathName,
                                ProcessId,
                                @{n="Date";e={$Date}},
                                @{n="Time";e={$Time}}
} | Export-Csv -Path $outputfile

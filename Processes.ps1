# this script assumes you have a list of IPs with a column header of ip.

#date and time stamps
$Date = Get-Date -Format "yyyyMMdd"
$Time = Get-Date -Format "hhMMss"

#comment $creds out if you are using in multiple scripts or it will be super annoying
#$creds = Get-Credential

#change csv files to match what you need
$inputfile = ".\AllHosts.csv"
$outputfile = ".\"+$Date+"_"+$Time+"_Processes.csv"

$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique


Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
$processes = Get-CimInstance -ClassName win32_Process
foreach ($process in $processes) {
$owner = $process | Invoke-CimMethod -methodname GetOwner | select User -ExpandProperty User
$process | Select-Object -property @{n="Domain";e={(Get-WmiObject Win32_ComputerSystem).Domain}},
                                @{n="HostName";e={(Get-CimInstance -ClassName Win32_ComputerSystem).Name}}, 
                                ProcessName,
                                ProcessID,
                                Path,
                                CommandLine,
                                @{n="Owner";e={$owner}},
                                @{n="Hash";e={(Get-FileHash -Path $_.Path).hash}},
                                ParentProcessID,
                                @{n="ParentProcessName";e={(Get-Process -ErrorAction Ignore -Id $_.ParentProcessID).name}},
                                @{n="ParentProcessPath";e={(Get-Process -ErrorAction Ignore -Id $_.ParentProcessID).path}},
                                @{n="Date";e={$Date}},
                                @{n="Time";e={$Time}}
}
} | Export-Csv -Path $outputfile

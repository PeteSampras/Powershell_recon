# this script assumes you have a list of IPs with a column header of ip.

#date and time stamps
$Date = Get-Date -Format "yyyyMMdd"
$Time = Get-Date -Format "hhMMss"

#comment $creds out if you are using in multiple scripts or it will be super annoying
#$creds = Get-Credential

#change csv files to match what you need
$inputfile = ".\AllHosts.csv"
$outputfile = ".\"+$Date+"_"+$Time+"_TCP_Connections.csv"

$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique


Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
# modify these variables to filter out data
$connection_type = @("Established","Listen")
$port_cutoff = 65535
Get-NetTCPConnection | where {$_.state -in $connection_type -and ($_.RemotePort -lt $port_cutoff -or $_.LocalPort -lt $port_cutoff)} |
        Select-Object -Property @{n="Domain";e={(Get-WmiObject Win32_ComputerSystem).Domain}},
                                @{n="HostName";e={(Get-CimInstance -ClassName Win32_ComputerSystem).Name}},
                                LocalAddress,
                                LocalPort,
                                RemoteAddress,
                                RemotePort,
                                State,
                                @{n="ProcessID";e={$_.OwningProcess}},
                                @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}},
                                @{n="Date";e={$Date}},
                                @{n="Time";e={$Time}}
} | Export-Csv -Path $outputfile

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
#modify autoruns variable paths as needed
$autoruns = @'
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Window
HKLM:\System\CurrentControlSet\Control\Session Manager
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
'@ -split "`r`n"
ForEach ($Key in Get-Item -Path $autoruns -ErrorAction SilentlyContinue) {
    $Key.GetValueNames() | where {$Key.GetValue($_) -like '*.*'} |
        Select-Object -Property @{n="Domain";e={(Get-WmiObject Win32_ComputerSystem).Domain}},
                                @{n="HostName";e={(Get-CimInstance -ClassName Win32_ComputerSystem).Name}},
                                @{n="Key_Location";e={$Key}},
                                @{n="Key_ValueName";e={$_}},
                                @{n="Key_Value";e={$Key.GetValue($_)}},
                                @{n="Date";e={$Date}},
                                @{n="Time";e={$Time}}
} 
} | Export-Csv -Path $outputfile

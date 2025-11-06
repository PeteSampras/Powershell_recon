Get-ScheduledTask | Where-Object TaskPath -NotLike "\Microsoft\*" | Select-Object TaskName, TaskPath, State, Description, Triggers
#remote data
$winversion=(Get-CimInstance Win32_OperatingSystem).Version
$computername=(Get-CimInstance -ClassName Win32_ComputerSystem).Name
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq "Ethernet" -and $_.AddressState -eq "Preferred" }).IPAddress
$domain=(Get-WmiObject Win32_ComputerSystem).Domain

#local data for saving to outfile
$Date = Get-Date -Format "yyyyMMdd"
$PathString = "C:\users\"+[string]$Env:USERNAME + "\Desktop\" + "$Date" + "_Tasks.csv"

$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

if ($productType -eq 2) {
    Write-Host "This computer is a Domain Controller."
} elseif ($productType -eq 3) {
    Write-Host "This computer is a Member Server."
} else {
    Write-Host "This computer is neither a Domain Controller nor a Member Server (e.g., Workstation)."
}

#SMB shares
Get-SmbShare | Where-Object { $_.Name -match "\$" }

#network connections
Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object Name, Status, MacAddress, LinkSpeed

#check AV
$avProcesses = @("MsMpEng", "avp", "McShield", "savservice", "egui")
Get-Process | Where-Object { $avProcesses -contains $_.Name } | Select-Object Name, Id, StartTime

#enumerate local users to check if Admin
$localusers = Get-CimInstance -ClassName Win32_UserAccount
foreach ($user in $localusers) {
    Get-LocalGroupMember -Member $user.Name
    $isadmin = Get-LocalGroupMember -Group 'Administrators' | where {$_.Name -eq $user.Caption}
    if ($isadmin.Length -eq 1) {
        [PSCustomObject]@{
                LocalUser = $user.Caption
                Privilege = "Admin"
            }
        }
    if ($isadmin.Length -ne 1) {
        [PSCustomObject]@{
                LocalUser = $user.Caption
                Privilege = "User"
            }
        }
    }


Get-ScheduledTask | ForEach-Object {
    $taskName = $_.TaskName
    $taskPath = $_.TaskPath
    $triggers = $_.Triggers
    foreach ($action in $_.Actions) {
            $imagePath = $action.Path
            $arguments = $action.Arguments
            
            [PSCustomObject]@{
                TaskName = $taskName
                TaskPath = $taskPath
                ImagePath = $imagePath
                Arguments = $arguments
                Triggers = $triggers
            }
        }
    }

#get sched tasks and hash
Get-ScheduledTask | ForEach-Object { 
    if ($_.TaskPath -notlike '*\Microsoft\*') {
        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            Command = (cmd /c "echo" $_.Actions.Execute) -replace '"','' 
            Arguments = $_.Actions.Arguments
            Hash=(Get-FileHash -Path ((cmd /c "echo" $_.Actions.Execute) -replace '"','' ) -ErrorAction SilentlyContinue).hash
        }
    }
}  | fl *


#get processes and hashes, if no owner or Path it was launched at boot
$processes = Get-CimInstance -ClassName win32_Process
foreach ($process in $processes) {
$owner = $process | Invoke-CimMethod -methodname GetOwner | select User -ExpandProperty User
$process | Select-Object -property ProcessName,
                                ProcessID,
                                Path,
                                CommandLine,
                                @{n="Owner";e={$owner}},
                                @{n="Hash";e={(Get-FileHash -Path $_.Path).hash}},
                                ParentProcessID,
                                @{n="ParentProcessName";e={(Get-Process -ErrorAction Ignore -Id $_.ParentProcessID).name}},
                                @{n="ParentProcessPath";e={(Get-Process -ErrorAction Ignore -Id $_.ParentProcessID).path}}
}



$Date = Get-Date -Format "yyyyMMdd"
$PathString = "C:\users\"+[string]$Env:USERNAME + "\Desktop\" + "$Date" + "_Tasks.csv"
$Rules = Get-NetFirewallRule
$Ports = Get-NetFirewallPortFilter
$Addresses =  Get-NetFirewallAddressFilter
foreach ($Rule in $Rules) {
    foreach ($Port in $Ports) {
        if ($Rule.InstanceID -eq $Port.InstanceID) {
        $Protocol      = $Port.Protocol
        $LocalPort     = $Port.LocalPort
        $RemotePort    = $Portr.RemotePort
        break
        }
    }
    foreach ($Address in $Addresses) {
    if ($Rule.InstanceID -eq $Address.InstanceID) {
        $LocalAddress      = $Address.LocalAddress
        $RemoteAddress     = $Address.RemoteAddress
        break
        }

    }
$PortFilter = $Rule | Get-NetFirewallPortFilter
$AddressFilter = $Rule | Get-NetFirewallAddressFilter
$Final = @()
$ConsolidatedInfo = [PSCustomObject]@{
    Name          = $Rule.DisplayName
    Direction     = $Rule.Direction
    Action        = $Rule.Action
    Protocol      = $Protocol
    LocalPort     = $LocalPort
    RemotePort    = $RemotePort
    LocalAddress  = $LocalAddress
    RemoteAddress = $RemoteAddress

}
Write-Host $ConsolidatedInfo 
$Final += $ConsolidatedInfo
}
$Final | Export-Csv -Path $PathString -Append -NoTypeInformation

foreach ($rule in (Get-NetFirewallRule)) {
    $addressDetail = $rule | Get-NetFirewallAddressFilter
    $portDetail = $rule | Get-NetFirewallPortFilter
    [PSCustomObject]@{
        Name = $rule.Name
        Direction = $rule.Direction
        Action = $rule.Action
        Enabled = $rule.Enabled
        LocalAddress = $addressDetail.LocalAddress
        RemoteAddress = $addressDetail.RemoteAddress
        LocalPort = $portDetail.LocalPort
        RemotePort = $portDetail.RemotePort
        Protocol = $portDetail.Protocol
    }
}

Get-WinEvent -LogName system | Where-Object -Property ID -EQ 7045 | Select-Object ID, Message, MachineName -ErrorAction SilentlyContinue| Format-List 
Get-WinEvent -LogName security | Where-Object -Property ID -EQ 4946 -ErrorAction SilentlyContinue 

Get-WinEvent -LogName system -ErrorAction SilentlyContinue | Where-Object -Property ID -EQ 7045 -ErrorAction SilentlyContinue | ForEach-Object {
        $messageLines = $_.Message.Split("`n")
        $serviceName = ($messageLines | Where-Object { $_ -like "*Service Name:*" }).Trim().Replace("Service Name:  ", "")
        $serviceFileName = ($messageLines | Where-Object { $_ -like "*Service File Name:*" }).Trim().Replace("Service File Name:  ", "")
        
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ServiceName = $serviceName
            ServiceFileName = $serviceFileName -replace "\.exe.*",".exe" -replace '"', ''
            Hash=(Get-FileHash -Path ($ServiceFileName -replace "\.exe.*",".exe" -replace '"', '') -ErrorAction SilentlyContinue).hash
        }


    } -ErrorAction SilentlyContinue| fl *

    $rules         = Get-NetFirewallRule
    $portfilter    = Get-NetFirewallPortFilter
    $addressfilter = Get-NetFirewallAddressFilter

    ForEach ($rule in $rules){
        $ruleport    = $portfilter |
                           Where-Object {$_.InstanceID -eq $rule.InstanceID}
        $ruleaddress = $addressfilter |
                           Where-Object {$_.InstanceID -eq $rule.InstanceID}
        $data        = @{
            InstanceID    = $rule.InstanceID.ToString()
            Enabled       = $rule.Enabled.ToString()
            Direction     = $rule.Direction.ToString()
            Action        = $rule.Action.ToString()
            LocalAddress  = $ruleaddress.LocalAddress -join ","
            RemoteAddress = $ruleaddress.RemoteAddress -join ","
            Protocol      = $ruleport.Protocol.ToString()
            LocalPort     = $ruleport.LocalPort -join ","
            RemotePort    = $ruleport.RemotePort -join ","
        }

        New-Object -TypeName psobject -Property $data

    }
# get services
Get-CimInstance -ClassName Win32_Service |
        Select-Object -Property @{n="ServiceName";e={$_.name}},
                                @{n="Status";e={$_.state}},
                                @{n="StartType";e={$_.startmode}},
                                @{n="Hash";e={(Get-FileHash -Path ($_.PathName -replace "\.exe.*",".exe" -replace '"', '')).hash}},
                                @{n="ProcessName";e={(Get-Process -Id $_.ProcessID).ProcessName}},
                                PathName,
                                ProcessId


#Get scheduled tasks
schtasks /query /V /FO CSV | ConvertFrom-Csv |
    Where-Object {$_."Scheduled Task State" -eq "Enabled"} |
        Select-Object -Property TaskName,
                                Status,
                                "Run As User",
                                "Schedule Time",
                                "Next Run Time",
                                "Last Run Time",
                                "Start Time",
                                "End Time",
                                "End Date",
                                "Task to Run",
                                @{n="Hash";e={(Get-FileHash -Path (($_."Task to Run") -replace "\.exe.*",".exe" -replace '"', '') -ErrorAction SilentlyContinue).hash}}

#get tcp connections
Get-NetTCPConnection | where {$_.state -eq "Established" -and $_.RemotePort -lt 49000 -or $_.LocalPort -lt 49000} |
        Select-Object -Property LocalAddress,
                                LocalPort,
                                RemoteAddress,
                                RemotePort,
                                State,
                                @{n="ProcessID";e={$_.OwningProcess}},
                                @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}} | ft *

#autoreg finder. must have autorunkeys.txt
param ([string[]]$AutoRunKeys)

ForEach ($Key in Get-Item -Path $AutoRunKeys -ErrorAction SilentlyContinue){
    $Key.GetValueNames() |
        Select-Object -Property @{n="Key_Location";e={$Key}},
                                @{n="Key_ValueName";e={$_}},
                                @{n="Key_Value";e={$Key.GetValue($_)}}
}

#autorun keys.txt
<#
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Window
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
#>        

# get stored wifi creds
(netsh wlan show profiles) | Select-String ":(.+)$" | ForEach-Object {
    $profile = $_.Matches.Groups[1].Value.Trim()
    netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" 
}       

# get installed programs
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, PSChildName, DisplayVersion, Publisher | Format-Table -AutoSize   

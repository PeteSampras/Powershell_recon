Get-ScheduledTask | Where-Object TaskPath -NotLike "\Microsoft\*" | Select-Object TaskName, TaskPath, State, Description, Triggers
#remote data
$winversion=(Get-CimInstance Win32_OperatingSystem).Version
$computername=(Get-CimInstance -ClassName Win32_ComputerSystem).Name
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq "Ethernet" -and $_.AddressState -eq "Preferred" }).IPAddress
#local data for saving to outfile
$Date = Get-Date -Format "yyyyMMdd"
$PathString = "C:\users\"+[string]$Env:USERNAME + "\Desktop\" + "$Date" + "_Tasks.csv"

$localadmins = Get-LocalGroupMember -Group 'Administrators' | select name
$localusers = Get-CimInstance -ClassName Win32_UserAccount
foreach ($user in $localusers) {
    $isadmin = Get-LocalGroupMember -Group 'Administrators' | where {$_.Name -eq $user.Caption}
    if ($isadmin.Length -eq 1) {
        [PSCustomObject]@{
                LocalUser = $user.Caption
                Privilege = "Admin"
            }
        }
    if ($isadmin.Length -eq 0) {
        [PSCustomObject]@{
                User = $user.Caption
                Privilege = "User"
            }
        }
    }
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUser = [System.Security.Principal.WindowsIdentity]::Impersonate("Administrator")
$isAdmin = (New-Object System.Security.Principal.WindowsPrincipal $currentUser).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    "The current user $($currentUser.Name) has administrative rights."
} else {
    "The current user $($currentUser.Name) does NOT have administrative rights."
}
[System.Security.Principal.WindowsIdentity]::Equals("administrator")


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

Get-CimInstance -ClassName win32_Process | #Invoke-CimMethod -methodname GetOwner | select User
        Select-Object -Property ProcessName,
                                ProcessID,
                                Path,
                                CommandLine,
                                @{n="Owner";e={Get-CimInstance -ClassName win32_Process -Filter "ID = '$_.ProcessID'" | Invoke-CimMethod -methodname GetOwner | select User},
                                #@{n="Owner";e={Get-Process -IncludeUserName | where {$_.Id -eq $_.ProcessID} | select UserName -ExpandProperty UserName},
                                @{n="Hash";e={(Get-FileHash -Path $_.Path).hash}},
                                @{n="ParentProcessName";e={(Get-Process -ErrorAction Ignore -Id $_.ParentProcessID).name}}

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

    Get-CimInstance -ClassName Win32_Service |
        Select-Object -Property @{n="ServiceName";e={$_.name}},
                                @{n="Status";e={$_.state}},
                                @{n="StartType";e={$_.startmode}},
                                @{n="Hash";e={(Get-FileHash -Path ($_.PathName -replace "\.exe.*",".exe" -replace '"', '')).hash}},
                                @{n="ProcessName";e={(Get-Process -Id $_.ProcessID).ProcessName}},
                                PathName,
                                ProcessId

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

    Get-CimInstance -ClassName Win32_Service |
        Select-Object -Property @{n="ServiceName";e={$_.name}},
                                @{n="Status";e={$_.state}},
                                @{n="StartType";e={$_.startmode}},
                                @{n="Hash";e={(Get-FileHash -Path ($_.PathName -replace "\.exe.*",".exe" -replace '"', '')).hash}},
                                @{n="ProcessName";e={(Get-Process -Id $_.ProcessID).ProcessName}},
                                PathName,
                                ProcessId

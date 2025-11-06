# this script assumes you have a list of IPs with a column header of ip.

#date and time stamps
$Date = Get-Date -Format "yyyyMMdd"
$Time = Get-Date -Format "hhMMss"

#comment $creds out if you are using in multiple scripts or it will be super annoying
#$creds = Get-Credential

#change csv files to match what you need
$inputfile = ".\AllHosts.csv"
$outputfile = ".\"+$Date+"_"+$Time+"_Firewalls.csv"

$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique

#invoke command
Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
$HostName =(Get-CimInstance -ClassName Win32_ComputerSystem).Name 
$rules         = Get-NetFirewallRule
$portfilter    = Get-NetFirewallPortFilter
$addressfilter = Get-NetFirewallAddressFilter

    ForEach ($rule in $rules){
        $ruleport    = $portfilter |
                           Where-Object {$_.InstanceID -eq $rule.InstanceID}
        $ruleaddress = $addressfilter |
                           Where-Object {$_.InstanceID -eq $rule.InstanceID}
        $data        = @{
            Domain        = $Domain
            HostName      = $HostName 
            InstanceID    = $rule.InstanceID.ToString()
            Enabled       = $rule.Enabled.ToString()
            Direction     = $rule.Direction.ToString()
            Action        = $rule.Action.ToString()
            LocalAddress  = $ruleaddress.LocalAddress -join ","
            RemoteAddress = $ruleaddress.RemoteAddress -join ","
            Protocol      = $ruleport.Protocol.ToString()
            LocalPort     = $ruleport.LocalPort -join ","
            RemotePort    = $ruleport.RemotePort -join ","
            Date = $Date
            Time = $Time
        }
        New-Object -TypeName psobject -Property $data
    }
} | Export-Csv -Path $outputfile

# this script assumes you have a list of IPs with a column header of ip.

#date and time stamps
$Date = Get-Date -Format "yyyyMMdd"
$Time = Get-Date -Format "hhMMss"

#comment $creds out if you are using in multiple scripts or it will be super annoying
#$creds = Get-Credential

#change csv files to match what you need
$inputfile = ".\AllHosts.csv"
$outputfile = ".\"+$Date+"_"+$Time+"_Local_Users.csv"

$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique


Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
#enumerate local users to check if Admin
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain
$HostName =(Get-CimInstance -ClassName Win32_ComputerSystem).Name 
$localusers = Get-CimInstance -ClassName Win32_UserAccount
foreach ($user in $localusers) {
    #Get-LocalGroupMember -Member $user.Name
    $isadmin = Get-LocalGroupMember -Group 'Administrators' | where {$_.Name -eq $user.Caption}
    $privilege = "User"
    if ($isadmin.Length -eq 1) {
        $privilege = "Admin"
    }
    [PSCustomObject]@{
        Domain = $Domain
        HostName = $HostName
        LocalUser = $user.Caption
        Privilege = $privilege
        Date = $Date
        Time = $Time
    }
}
} | Export-Csv -Path $outputfile

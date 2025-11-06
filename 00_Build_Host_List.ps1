# this script assumes you have a list of IPs with a column header of ip.
# the purpose of this output is to provide additional information beyond an IP for your network so you can make more informed queries later

#comment $creds out if you are using in multiple scripts or it will be super annoying
$creds = Get-Credential
#change csv files to match what you need
$inputfile = ".\hosts.csv"
$outputfile = ".\AllHosts.csv"
$targets = Import-Csv $inputfile | select -ExpandProperty ip | Sort-Object -Unique
#build out initial computer info
Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object Name, Status, MacAddress, LinkSpeed
foreach ($adapter in $adapters) {
[PSCustomObject]@{
        Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        HostName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        ProductType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
        Interface = $adapter.Name
        IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq $adapter.Name -and $_.AddressState -eq "Preferred" }).IPAddress
        MAC = $adapter.MacAddress
        Date = $Date
        Time = $Time
        }
} 
} | Export-Csv -Path $outputfile

# Powershell_recon
powershell scripts for data collection as red, blue, purple team


## Network connections
`Write-Host "[+] Enumerating Active Network Connections..."
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
`

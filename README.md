# Powershell_recon
powershell scripts for data collection as red, blue, purple team
### Credit: https://www.linkedin.com/pulse/powershell-cybersecurity-reconnaissance-enumeration-scripts-pacheco-qluec

# 1. Network
## Network connections
Purpose: Identifies active TCP connections and potential Command & Control (C2) traffic.

```
Write-Host "[+] Enumerating Active Network Connections..."
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
```

## Retrieve Network Adapter Information
Purpose: Identifies network interfaces, MAC addresses, and link speeds for device fingerprinting and lateral movement.

```
Write-Host "[+] Enumerating Network Adapter Information..."
Get-NetAdapter | Select Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Format-Table -AutoSize        
```

## Enumerate DNS Cache for Potential Targets
Purpose: Reveals recently resolved domain names, which can be useful for phishing and internal targeting.

```
Write-Host "[+] Dumping DNS Cache for Reconnaissance..."
Get-DnsClientCache | Format-Table -AutoSize     
```

# 2. System and Host Enumeration
## List installed Programs
Purpose: Identifies installed software, including security tools, outdated applications, or vulnerabilities.

```
Write-Host "[+] Enumerating Installed Programs..."
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize        
```
## Enumerate Running Processes
Purpose: Detects high-privilege or suspicious processes that could indicate security tools, monitoring software, or vulnerable applications.
```
Write-Host "[+] Enumerating Running Processes..."
Get-Process | Select-Object Name, Id, Path | Format-Table -AutoSize
```

## List Startup Applications
Purpose: Identifies programs that execute at startup, which could be used for persistence mechanisms.
```
Write-Host "[+] Enumerating Startup Applications..."
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location | Format-Table -AutoSize
```
## Enumerate Scheduled Tasks
Purpose: Identies scheduled tasks with command path (Stranger danger example ignores tasks in Microsoft path, which attacker could abuse)
```
Get-ScheduledTask | ForEach-Object { 
    if ($_.TaskPath -notlike '*\Microsoft\*') {
        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            Command = $_.Actions.Execute
            Arguments = $_.Actions.Arguments
        }
    }
}  | ft * -AutoSize
```

# 3. User and Credential Enumeration
## List Local Accounts
Purpose: Identifies local user accounts and their last login activity.
```
Write-Host "[+] Enumerating Local Users..."
Get-LocalUser | Select Name, Enabled, LastLogon | Format-Table -AutoSize
```
## List Administrators and Privileged Groups
Purpose: Identifies administrator-level users who have elevated privileges.
```
Write-Host "[+] Enumerating Privileged Groups..."
Get-LocalGroupMember -Group "Administrators" | Select Name, ObjectClass | Format-Table -AutoSize
```

## Dump WiFi passwords
Purpose: Extracts saved WiFi passwords, useful for network lateral movement.
```
Write-Host "[+] Extracting Stored WiFi Credentials..."
(netsh wlan show profiles) | Select-String ":(.+)$" | ForEach-Object {
    $profile = $_.Matches.Groups[1].Value.Trim()
    netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" 
}
```
# 4. Security and Defense Enumeration
## Enumerate Running Windows Defender Settings
Purpose: Checks Windows Defender settings, including real-time protection and exclusion policies.
```
Write-Host "[+] Checking Windows Defender Status..."
Get-MpPreference | Format-List
```


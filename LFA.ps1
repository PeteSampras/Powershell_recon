
#this script will take the output of the processes, services, autoruns, and scheduled tasks scripts and find any anomalous activity based on the $least_amount

# if anything appears this many times or fewer, it will be considered anomalous
$least_amount = 2
$csv_path = ".\"
$all_csv_services = @()
Get-ChildItem -Path $Path -Filter "*_Services.csv" | ForEach-Object {
    $all_csv_services += Import-Csv -LiteralPath $_.FullName
}
$all_csv_processes = @()
Get-ChildItem -Path $Path -Filter "*_Proccesses.csv" | ForEach-Object {
    $all_csv_processes += Import-Csv -LiteralPath $_.FullName
}
$all_csv_autoruns = @()
Get-ChildItem -Path $Path -Filter "*_AutoRuns.csv" | ForEach-Object {
    $all_csv_autoruns += Import-Csv -LiteralPath $_.FullName
}
$all_csv_scheduled_tasks = @()
Get-ChildItem -Path $Path -Filter "*_Scheduled_Tasks.csv" | ForEach-Object {
    $all_csv_scheduled_tasks += Import-Csv -LiteralPath $_.FullName
}

$all_csv_processes | Sort-Object -Property Domain,HostName, hash -Unique | Group-Object hash | Where-Object {$_.count -le $least_amount} | Select-Object -ExpandProperty Group | Export-Csv -Path ".\LFA_Processes.csv"
$all_csv_services | Sort-Object -Property Domain,HostName, servicename -Unique | Group-Object servicename | Where-Object {$_.count -le $least_amount} | Select-Object -ExpandProperty Group| Export-Csv -Path ".\LFA_Services.csv"
$all_csv_autoruns | Sort-Object -Property Domain,HostName, Key_ValueName -Unique | Group-Object Key_ValueName | Where-Object {$_.count -le $least_amount} | Select-Object -ExpandProperty Group| Export-Csv -Path ".\LFA_Autoruns.csv"
$all_csv_scheduled_tasks | Sort-Object -Property Domain,HostName, taskname  -Unique | Group-Object taskname  | Where-Object {$_.count -le $least_amount} | Select-Object -ExpandProperty Group| Export-Csv -Path ".\LFA_Scheduled_Tasks.csv"

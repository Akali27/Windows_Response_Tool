<#
.SYNOPSIS
    A script to collect valuable system data for incident response analysis.

.DESCRIPTION
    This script collects various system data related to hardware, operating system, 
    user accounts, processes, services, installed programs, prefetch listings, security updates, 
    TCP/UDP connections, neighbor cache entries, reachable network adapters, and security event logs. 
    The data is stored in a text file for further analysis.

.PARAMETER Path
    Specifies the output path for the incident response data file. If the path doesn't exist, it will be created.

.EXAMPLE
    .\IncidentResponse.ps1 -Path "D:\Output"
    Collects the system data and stores it in the "D:\Output" folder.

.NOTES
    This script requires administrator privileges to run.

.AUTHOR
    Created by: Ahmed K. Ali
    Date: 2022-04-22
#>


#---------------------------------------------------------[Initializations]--------------------------------------------------------

$VerbosePreference = "SilentlyContinue"

# Ask the user where the output should be written
$Path = Read-Host -Prompt "Enter the output path for the Incident Response data (e.g., D:\Output)"

# Create the output directory if it does not exist, including any parent directories
New-Item -ItemType Directory -Path $Path -Force | Out-Null

$OutputFile = "$Path\IncidentResponse.txt"
$HashOutputFile = "$Path\IncidentResponse_Hash.txt"

#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Get-IncidentResponseData($Path)
{
    "                                                                                                                         " | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------------------------------------------------------------------------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "                                                           Begin Report                                                  " | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------------------------------------------------------------------------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "                                                                                                                         " | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append

    #The following cmdlet will fetch the computer hardware information. 
    
    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Computer System Information...")
    "---------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Computer System Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "---------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-ComputerInfo -Property "TimeZone","OsLocalDateTime","CsManufacturer","CsModel","BiosName","CsDomain", `
    "CsUserName","LogonServer","WindowsRegisteredOwner","WindowsProductName","OsArchitecture","OsVersion","CsProcessors", `
    "CsNumberOfLogicalProcessors" | Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch operating system information. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Operating System Information...")
    "----------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Operating System Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "----------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-WmiObject -Class Win32_OperatingSystem | Select-Object PSComputerName, Status, Caption, OSArchitecture, Version |
    Format-Table | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green
 
    #The following cmdlet will fetch user account information.

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering User Account Information...")
    "------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "User Account Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-WmiObject -Class Win32_UserAccount | Select-Object Name, FullName, SID, AccountType, Disabled, Lockout, PasswordRequired, PasswordExpires | Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green


    #The following cmdlet will fetch the processes that are running on the computer. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Running Processes Information...")
    "-----------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Running Processes Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-----------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-Process | Select-Object StartTime, ProcessName, ID, Path | Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch all the services that are running on the computer. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Windows Service Information...")
    "----------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Windows Services Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "----------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch a list of the installed programs on the computer. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Installed Programs Information...")
    "------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Installed Programs Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-WMIObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource | Format-Table | 
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch prefetch listings from the computer.

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Prefetch Listings...")
    "---------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Prefetch Listings" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "---------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-ChildItem -Path "C:\Windows\Prefetch" -Filter *.pf -ErrorAction SilentlyContinue |
    Select-Object Name, Length, LastAccessTime, LastWriteTime, CreationTime | Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch security update information. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Security Update Information...")
    "---------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Security Update Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "---------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-HotFix | Select-Object Description, HotFixID, InstalledBy, InstalledOn |
    Where-Object {($_.InstalledOn -gt (Get-Date 2020-01-01)) -and ($_.InstalledOn -lt (Get-Date 2021-12-31)) -and ($_.Description -like "*Security*")} | 
    Format-Table | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch TCP/UDP connections information. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering TCP/UDP Connections Information...")
    "-------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "TCP/UDP Connections Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-NetTCPConnection | 
    Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddres, RemotePort, OwningProcess, State | 
    Format-Table | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch neighbor cache information. 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Neighbor Cache Entries Information...")
    "----------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Neighbor Cache Entries Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "----------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-NetNeighbor | Where-Object AddressFamily -EQ IPv4 | 
    Select-Object ifIndex, IPAddress, LinkLayerAddress, State, PolicyStore, InterfaceAlias, InterfaceIndex, EnabledDefault, EnabledState, `
    RequestedState, TimeOfLastStateChange, TransitioningToState, AccessContext | Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet will fetch neighbors with reachable neighbors data 

    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Network Adapters Having Reachable Neighbors Information...")
    "-------------------------------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Network Adapters Having Reachable Neighbors Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-NetNeighbor -State Reachable | Get-NetAdapter| Format-Table |
    Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green

    #The following cmdlet is to fetch event logs, depending on the amount the user specifies. 
    
    $Count = Read-Host -Prompt "How Much Event Logs Do You Need (1-1000)"
    [Console]::Write("$($env:COMPUTERNAME.ToUpper()) - Gathering Security Event Logs Information...")
    "-------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "Security Event Logs Information" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Get-EventLog Security -Newest $Count | Sort-Object -Property TimeGenerated -Unique | ForEach-Object `
    {
        $Message = ($_.Message -Split '\n')[0]
        "$($_.Index), $($_.TimeGenerated), $($_.EntryType), $($_.Source), $($_.InstanceId), $Message" | 
        Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    }
    "                                                                                                                         " | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------------------------------------------------------------------------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "                                                           End Report                                                    " | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "-------------------------------------------------------------------------------------------------------------------------" | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    "                                                                                                                         " | Out-File -Width ([int]::MaxValue-1) -FilePath $Path\IncidentResponse.txt -Append
    Write-Host "Completed" -ForegroundColor Green
    Write-Host "`n"
    Write-Output "The Data File Can Be Found At This Path: $Path"

    notepad.exe $Path\IncidentResponse.txt

}

Try
{
    if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    {
        Throw "Administrator Privileges Are Required. Please Run This Script With Elevated Rights."
    }
    Remove-Item -Path $Path\IncidentResponse.txt -Force -ErrorAction Ignore
    Get-IncidentResponseData -Path $Path

    # Hash the Output
    $Hash = (Get-FileHash -Path $OutputFile -Algorithm SHA256).Hash
    "Output File Saved to $OutputFile 
    Hash(SHA256): $Hash" | Out-File -Width ([int]::MaxValue-1) -FilePath $HashOutputFile
}
Catch
{
    $_.Exception.Message
}
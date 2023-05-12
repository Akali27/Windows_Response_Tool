# Windows Incident Response Data Collection

"In case of emergency insert the USB" 

This is a PowerShell tool that's created for quick use during incident response on a Windows system. It will collect useful volatile and non-volatile data before you shut down the infected device. 

It is recommended that you save this script on a USB and store it in a place where it can be quickly accessed if a breach or compromise are suspected. 

## Features

The script will collect the following data from your Windows system: 

- Computer hardware info
- Operating system 
- User accounts 
- Running processes 
- Windows services 
- Installed programs 
- Prefetch listings
- Security updates 
- TCP/UDP connections 
- Neighbor cache entries 
- Network adapters having reachable neighbors 
- Security event logs 

## Prerequisites

PowerShell and Administrator privileges on target system. 

## Executing

Don't save the script or its output to the target computer. This will make unnecessary noise (data) that will get recorded. Execute from and save to an external drive like a USB flash drive with enough space on it. 

1) Open a PowerShell console with administrator privileges on the affected machine or a machine connected to the affected network. 
2) Navigate to the folder containing the script on the connected external drive. 
3) Run the script using '.\app'
4) Enter the output path for the incident response data when prompted (e.g., D:\Output). You can enter a nonexistent directory, like "Output" and the program will create it. 
5) Specify the number of security event logs to collect when prompted (1-1000).
6) After the program has finished running, remove the external drive and shutdown the computer. 

## Verification 

To ensure no tampering occurs to the output file, the program will hash IncidentResponse.txt using SHA256. It will then save the hash to IncidentResponse_Hash.txt in the same directory as the output. On a separate computer, use a software to calculate the hash value of the IncidentResponse.txt file and compare it to the hash value found in IncidentResponse_Hash.txt. The two hashes should match. 

## Troubleshooting

If you cannot run the script from PowerShell even after launching it as administrator, try 'set-executionpolicy remotesigned' to run unsigned scripts.

## Authors

Ahmed Ali  
https://medium.com/@Akali27




Import-Module -Name 'NetSecurity'

## Define the OpenSSH latest release url
$url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'

## Create a web request to retrieve the latest release download link
$request = [System.Net.WebRequest]::Create($url)
$request.AllowAutoRedirect=$false
$response=$request.GetResponse()
$source = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + '/OpenSSH-Win64.zip'

## Download the latest OpenSSH for Windows package to the current working directory
$webClient = [System.Net.WebClient]::new()
$webClient.DownloadFile($source, (Get-Location).Path + '\OpenSSH-Win64.zip')

# Extract the ZIP to a temporary location
Expand-Archive -Path .\OpenSSH-Win64.zip -DestinationPath ($env:temp) -Force

# Move the extracted ZIP contents from the temporary location to C:\Program Files\OpenSSH\
Move-Item "$($env:temp)\OpenSSH-Win64" -Destination "$($env:ProgramFiles)\OpenSSH\" -Force

# Unblock the files in C:\Program Files\OpenSSH\
Get-ChildItem -Path "$($env:ProgramFiles)\OpenSSH\" | Unblock-File

& 'C:\Program Files\OpenSSH\install-sshd.ps1'

# Configure PowerShell as the default shell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "$($env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

%{ if length(ssh_public_key) > 0 }
# Configure SSH public key

$content = @"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDRYCV99Ge9LI5Y61t95pkcG7trsDyg/eAHLfTGDMHOGxPDdXSk7wW/OCNsKWeJV20wjayoti2JYB+u4FRvsuyccjRZPlRTsul67QOJEzXfORCHD4EYDTR45l0n08zkUPRfs70yo5L5YG9HYgVr6+EK/F8fFReFDvhZwy8LW/hJSeyVCWlbszmuQYcHRmCkWBeAgEiPqx0Mx17txjw9p4RK/LbweYxN4fGu5Nh2Dz9uSBi2IfGds3rPcQvjnJBzt2GEDoZXdXgwXl4T5B0xEDJVMqS/Q+gArcL82cGsY7zpoWpKfOuVy88GD1qaHZgMvQ3LQRyxVysfhxvzSXRX0eF8518/8hGNLxmSak3dZyi5J2ojPdaYzOxtn4JTDFUKNCBQNLHJZCBl1J7HvilTnwQDbgWm0UoFB0dWG3fX4u1wGm11L9sX0kzQ+NZH2Q+9HVX+1vJWZJuNjlhogcsmXG1hecLZPD7WFl82nbmN7zBQwHtUbjUNERMHvXuUvjPnkjJh0avZVtUCRupJhNgyhTR0cWpzffmA2nzdQpIn6z93zVrgefwIpfr+Grk/XQTOXisIfYz/3sofQ9a2hTdPTj0UwKzULB0Pvsf/aYvVEG7zC0sRfPG/pj5cGeFnOB3Ar2/jd58EB7mLzm45MZ+ztSNRW+Eg32Lq1WgOJZ15TiH/pQ== prianto_autodeploy_id_2018
"@ 

# Write public key to file
$content | Set-Content -Path "$Env:ProgramData\ssh\administrators_authorized_keys"

# set acl on administrators_authorized_keys
$admins = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate( [System.Security.Principal.NTAccount]).Value
$acl = Get-Acl $Env:ProgramData\ssh\administrators_authorized_keys
$acl.SetAccessRuleProtection($true, $false)
$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule($admins,"FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl

%{ endif }

# Open firewall port 22
$FirewallParams = @{ 
  "DisplayName"       = 'OpenSSH SSH Server (sshd)' 
  "Direction"         = 'Inbound' 
  "Action"            = 'Allow' 
  "Protocol"          = 'TCP'
  "LocalPort"         = '22' 
}
New-NetFirewallRule @FirewallParams

# Set service to automatic and start
Set-Service sshd -StartupType Automatic
Start-Service sshd

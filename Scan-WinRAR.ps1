#
# Scan for WinRAR Files affected to CVE-2023-40477
#
# Version: 
#   1.3
# Date:
#   29.08.2023
# Author:
#   Winkler, Lars
#

# List all FileSystem without Network
$Path=([IO.DriveInfo]::getdrives() | ? {$_.DriveType -ne 'Network' -and $_.TotalSize -ne $null}).Name

$Files=(
  'unrar.dll', 'unrar64.dll',
  'unrar_nocrypt.dll','unrar64_nocrypt.dll',
  'unrar.exe','winrar.exe','rar.exe'
  )

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
# put your code below this line

Write-Host "Searching $Path for files ($Files) ..."

Get-ChildItem -Path $Path -Recurse -Force -File -ErrorAction SilentlyContinue -OutVariable Findings -Include $Files

Write-Host "`nList versions.`n6.23 and above are not affected to CVE-2023-40477`n"
ForEach ($f in $Findings) {
  Write-Host "$f ($((Get-Item $f.FullName).VersionInfo.FileVersion))"
}

Write-Host "`nPress Enter key to exit"
Read-Host
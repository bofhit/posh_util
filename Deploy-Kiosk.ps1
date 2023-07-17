<#
.SYNOPSIS
    Set up a PC for kiosk use.
.DESCRIPTION
    Set the baseline config for a general purpose kiosk PC.
#>

# Local admin account.
$ADMIN_ACCOUNT = 'admiot'
# Directory for Powershell scripts.
$POSH_DIR = 'C:\Powershell'
$TIMEZONE = 'Eastern Standard Time'

# ============================================================================
# Pre-run checks.

# Check for elevation.
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($id)

if (-not($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))){
    throw 'Please run this script as an administrator.'
}

# ============================================================================

# Set-Timezone
Write-host "Setting timezone to $TIMEZONE"
Set-TimeZone -Id $TIMEZONE

# Set password for admin account. Create if needed.
Write-Host 'Set password for local admin account.'
$password = Read-Host -AsSecureString -Prompt "Enter password for $ADMIN_ACCOUNT"   
$localusers = (Get-LocalUser) | Foreach-Object   {$_.name}
if (-not($localusers.Contains($ADMIN_ACCOUNT))) {
    New-LocalUser $ADMIN_ACCOUNT -FullName 'IT Admin' -Password $password
} else {
    Set-LocalUser $ADMIN_ACCOUNT -Password $password
}

$localadmins = Get-LocalGroupMember -Group administrators | ForEach-Object {$_.name}
$csname = Get-ComputerInfo | Select-Object -ExpandProperty CsName
if (-not($localadmins.Contains("$csname\$ADMIN_ACCOUNT"))) {
    Add-LocalGroupMember -Group administrators -Member $ADMIN_ACCOUNT
}

# Enable Remote Desktop
Write-Host 'Enabling Remote Desktop'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Set power options, timeout of 0 -eq Never
Write-Host 'Setting sleep, screen off options.'
powercfg.exe -x -monitor-timeout-ac 0
powercfg.exe -x -monitor-timeout-dc 0
powercfg.exe -x -disk-timeout-ac 0
powercfg.exe -x -disk-timeout-dc 0
powercfg.exe -x -standby-timeout-ac 0
powercfg.exe -x -standby-timeout-dc 0
powercfg.exe -x -hibernate-timeout-ac 0
powercfg.exe -x -hibernate-timeout-dc 0

# Create folder for Powershell scripts.
if (-not(Test-Path $POSH_DIR)) {
    New-Item -Path $POSH_DIR -ItemType Directory-ItemType Directory-ItemType Directory-ItemType Directory-ItemType Directory-ItemType Directory-ItemType Directory-ItemType Directory   
}
<#
.SYNOPSIS
    Set up a PC for kiosk use.
.DESCRIPTION
    Set the baseline config for a general purpose kiosk PC.
#>

$ADMIN_ACCOUNT = 'admiot'
$ALLOWED_ACCOUNTS = @(
    $ADMIN_ACCOUNT,
    'Administrator',
    'DefaultAccount',
    'Guest'
)
# ============================================================================
# Pre-flight checks.

# Check for elevation.
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($id)

if (-not($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))){
    throw 'Please run this script as an administrator.'
}

# Check that script execution is enabled.
$executionPolicy = Get-ExecutionPolicy
if (-not($executionPolicy -eq 'RemoteSigned')) {
    throw 'Please set Execution-Policy to RemoteSigned'
}

# ============================================================================

# Set-Timezone
Set-TimeZone -Id 'Eastern Standard Time'

# Add admin account.
Write-Host "Adding account $ADMIN_ACCOUNT"
$password = Read-Host -AsSecureString -Prompt 'Enter password'
New-LocalUser $ADMIN_ACCOUNT -FullName 'IT Admin' -Password $password
Add-LocalGroupMember -Group administrators -Member $ADMIN_ACCOUNT

# Remove all other accounts.
Get-LocalUser | ForEach-Object {if (-not($ALLOWED_ACCOUNTS.Contains($_))){Remove-LocalUser $_}}

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


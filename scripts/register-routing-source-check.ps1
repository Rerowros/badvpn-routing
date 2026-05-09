param(
    [string]$TaskName = "BadVPN Routing Source Check",
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$Time = "06:30"
)

$ErrorActionPreference = "Stop"

$uv = Get-Command uv -ErrorAction Stop
$scriptPath = Join-Path $ProjectRoot "scripts\sync_sources.py"
$logDir = Join-Path $ProjectRoot "logs"
$logPath = Join-Path $logDir "routing-source-check.log"

if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "sync_sources.py not found at $scriptPath"
}

New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$arguments = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "& '$($uv.Source)' run '$scriptPath' --check *>> '$logPath'"
) -join " "

$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument $arguments -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 20)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Checks BadVPN Mihomo routing upstream sources." -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' at $Time."
Write-Host "Log file: $logPath"

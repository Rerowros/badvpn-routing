param(
    [string]$SourceDir = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "rulesets"),
    [string]$TargetDir = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\badvpn\public")).Path "rulesets")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SourceDir)) {
    throw "Source rulesets directory not found: $SourceDir"
}

New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null

Get-ChildItem -LiteralPath $TargetDir -Recurse -File -Filter *.yaml -ErrorAction SilentlyContinue |
    Remove-Item -Force

Get-ChildItem -LiteralPath $SourceDir | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $TargetDir -Recurse -Force
}

Write-Host "Exported rulesets from $SourceDir"
Write-Host "Target: $TargetDir"

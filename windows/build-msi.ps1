# Builds the Windows desktop app and wraps it in an MSI.
#   powershell -ExecutionPolicy Bypass -File windows\build-msi.ps1 [-Version 1.2.0]
# Output: windows\artifacts\msi\ZeroLeakage-<version>-x64.msi
param([string]$Version = "1.2.0")
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { $dotnet = Join-Path $env:ProgramFiles "dotnet\dotnet.exe" }
if (-not (Test-Path $dotnet)) { throw ".NET SDK not found - install it with: winget install Microsoft.DotNet.SDK.10" }
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$publish = Join-Path $root "artifacts\publish"
$msiOut = Join-Path $root "artifacts\msi"

if (Test-Path $publish) { Remove-Item -Recurse -Force $publish }

Write-Host "==> Publishing ZeroLeakage.UI (self-contained win-x64)" -ForegroundColor Cyan
& $dotnet publish (Join-Path $root "ZeroLeakage.UI\ZeroLeakage.UI.csproj") -c Release -o $publish -p:Version=$Version
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Write-Host "==> Building MSI" -ForegroundColor Cyan
& $dotnet build (Join-Path $root "ZeroLeakage.Installer\ZeroLeakage.Installer.wixproj") -c Release -o $msiOut `
    -p:AppPublishDir=$publish -p:ProductVersion=$Version
if ($LASTEXITCODE -ne 0) { throw "MSI build failed" }

Get-ChildItem $msiOut -Filter *.msi | ForEach-Object { Write-Host "MSI: $($_.FullName) ($([math]::Round($_.Length / 1MB, 1)) MB)" -ForegroundColor Green }

#Requires -Version 5.1

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArgs
)

$ErrorActionPreference = "SilentlyContinue"

if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Setting execution policy..." -ForegroundColor Yellow
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
}

$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ProjectPath = Join-Path $DesktopPath "ReconRaptor"

if (Test-Path $ProjectPath) {
    Remove-Item $ProjectPath -Recurse -Force
}
New-Item -ItemType Directory -Path $ProjectPath -Force | Out-Null
Set-Location $ProjectPath

Write-Host "Installing dependencies..." -ForegroundColor Green

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "Installing winget..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile "winget.msixbundle"
    Add-AppxPackage -Path "winget.msixbundle" -Force
    Remove-Item "winget.msixbundle" -Force
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Git..." -ForegroundColor Yellow
    winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements --silent
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    Start-Sleep -Seconds 5
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Go..." -ForegroundColor Yellow
    winget install --id GoLang.Go -e --source winget --accept-package-agreements --accept-source-agreements --silent
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    Start-Sleep -Seconds 5
}

Write-Host "Cloning repository..." -ForegroundColor Green
git clone https://github.com/0xb0rn3/r3cond0g.git . --quiet

if (-not (Test-Path "main.go")) {
    Write-Host "Repository structure error" -ForegroundColor Red
    exit 1
}

Write-Host "Setting up Go module..." -ForegroundColor Green
go mod init r3cond0g
go mod tidy

Write-Host "Compiling binary..." -ForegroundColor Green
$buildProcess = Start-Process -FilePath "go" -ArgumentList "build", "-ldflags=-s -w", "-o", "r3cond0g.exe", "main.go" -NoNewWindow -PassThru -Wait

if ($buildProcess.ExitCode -ne 0) {
    Write-Host "Compilation failed" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path "r3cond0g.exe")) {
    Write-Host "Binary not found after compilation" -ForegroundColor Red
    exit 1
}

Write-Host "Launching ReconRaptor..." -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta

if ($ToolArgs) {
    & ".\r3cond0g.exe" @ToolArgs
} else {
    & ".\r3cond0g.exe"
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "Execution completed. Files located at: $ProjectPath" -ForegroundColor Green

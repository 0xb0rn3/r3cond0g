#Requires -Version 5.1

param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ToolArgs)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath' $args`""; exit
}

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

$desktopPath = [Environment]::GetFolderPath("Desktop")
$workDir = Join-Path $desktopPath "ReconRaptor"
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
Set-Location $workDir

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Git.Git -e --accept-package-agreements --accept-source-agreements --force | Out-Null
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install git -y --force | Out-Null
    }
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id GoLang.Go -e --accept-package-agreements --accept-source-agreements --force | Out-Null
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install golang -y --force | Out-Null
    }
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
}

if (-not (Test-Path ".git") -or -not (Test-Path "main.go")) {
    if (Test-Path ".git") { Remove-Item -Recurse -Force .git }
    git clone https://github.com/0xb0rn3/r3cond0g.git . --force 2>&1 | Out-Null
}

if (-not (Test-Path "go.mod")) {
    go mod init r3cond0g 2>&1 | Out-Null
}

go mod tidy 2>&1 | Out-Null

if (Test-Path "r3cond0g.exe") { Remove-Item "r3cond0g.exe" -Force }

go build -ldflags="-s -w" -o r3cond0g.exe main.go

if (Test-Path "r3cond0g.exe") {
    if ($ToolArgs) {
        & ".\r3cond0g.exe" @ToolArgs
    } else {
        & ".\r3cond0g.exe"
    }
} else {
    Write-Host "Compilation failed" -ForegroundColor Red
    exit 1
}

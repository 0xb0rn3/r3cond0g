#Requires -Version 5.1

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArgs
)

$Config = @{
    RepoUrl = "https://github.com/0xb0rn3/r3cond0g.git"
    RepoName = "r3cond0g"
    ToolExecutableName = "r3cond0g.exe"
    MainGoFile = "main.go"
    DesktopPath = [Environment]::GetFolderPath("Desktop")
}

Write-Host "ReconRaptor Setup - Requesting Permission" -ForegroundColor Cyan
$permission = Read-Host "Do you want to proceed with setup? (Y/N)"
if ($permission -notmatch '^[Yy]') {
    Write-Host "Setup cancelled." -ForegroundColor Red
    exit 1
}

$workDir = Join-Path $Config.DesktopPath "ReconRaptor"
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}
Set-Location $workDir

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git not found. Install Git and retry." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Go not found. Install Go and retry." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $Config.RepoName)) {
    Write-Host "Cloning repository..." -ForegroundColor Yellow
    git clone $Config.RepoUrl $Config.RepoName 2>&1 | Out-Null
}

Set-Location $Config.RepoName

if (Test-Path "go.mod") {
    go mod tidy 2>&1 | Out-Null
}

Write-Host "Compiling..." -ForegroundColor Yellow
go build -ldflags="-s -w" -o $Config.ToolExecutableName $Config.MainGoFile 2>&1 | Out-Null

if (-not (Test-Path $Config.ToolExecutableName)) {
    Write-Host "Compilation failed." -ForegroundColor Red
    exit 1
}

Write-Host "Launching ReconRaptor..." -ForegroundColor Green
if ($ToolArgs) {
    & ".\$($Config.ToolExecutableName)" @ToolArgs
} else {
    & ".\$($Config.ToolExecutableName)"
}

Write-Host "Setup complete. Files located at: $workDir" -ForegroundColor Green

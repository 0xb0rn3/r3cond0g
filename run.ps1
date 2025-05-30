#Requires -Version 5.1

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArgs
)

$RepoUrl = "https://github.com/0xb0rn3/r3cond0g.git"
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ProjectPath = Join-Path $DesktopPath "ReconRaptor"

function Request-ExecutionPermission {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    if ($currentPolicy -eq "Restricted" -or $currentPolicy -eq "AllSigned") {
        Write-Host "Requesting execution permission..." -ForegroundColor Yellow
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            Write-Host "Execution policy updated." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to set execution policy. Please run as administrator." -ForegroundColor Red
            exit 1
        }
    }
}

function Install-Dependencies {
    $dependencies = @(
        @{Name = "Git"; Command = "git"; WingetId = "Git.Git"; ChocoName = "git"},
        @{Name = "Go"; Command = "go"; WingetId = "GoLang.Go"; ChocoName = "golang"}
    )
    
    foreach ($dep in $dependencies) {
        if (-not (Get-Command $dep.Command -ErrorAction SilentlyContinue)) {
            Write-Host "Installing $($dep.Name)..." -ForegroundColor Yellow
            
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                winget install --id $dep.WingetId -e --accept-package-agreements --accept-source-agreements --silent | Out-Null
            }
            elseif (Get-Command choco -ErrorAction SilentlyContinue) {
                choco install $dep.ChocoName -y | Out-Null
            }
            else {
                Write-Host "$($dep.Name) installation failed. Install manually." -ForegroundColor Red
                exit 1
            }
            
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            Start-Sleep 2
            
            if (-not (Get-Command $dep.Command -ErrorAction SilentlyContinue)) {
                Write-Host "$($dep.Name) not found after installation." -ForegroundColor Red
                exit 1
            }
        }
    }
}

function Setup-Project {
    if (Test-Path $ProjectPath) {
        Remove-Item $ProjectPath -Recurse -Force
    }
    
    New-Item -ItemType Directory -Path $ProjectPath -Force | Out-Null
    Set-Location $ProjectPath
    
    Write-Host "Cloning repository..." -ForegroundColor Yellow
    git clone $RepoUrl . 2>&1 | Out-Null
    
    if (-not (Test-Path "main.go")) {
        Write-Host "Repository clone failed." -ForegroundColor Red
        exit 1
    }
}

function Build-Tool {
    Write-Host "Initializing Go module..." -ForegroundColor Yellow
    go mod init r3cond0g 2>&1 | Out-Null
    go mod tidy 2>&1 | Out-Null
    
    Write-Host "Compiling..." -ForegroundColor Yellow
    go build -ldflags="-s -w" -o r3cond0g.exe main.go 2>&1 | Out-Null
    
    if (-not (Test-Path "r3cond0g.exe")) {
        Write-Host "Compilation failed." -ForegroundColor Red
        exit 1
    }
}

function Run-Tool {
    Write-Host "Launching ReconRaptor..." -ForegroundColor Green
    Write-Host "Project location: $ProjectPath" -ForegroundColor Cyan
    
    if ($ToolArgs) {
        & ".\r3cond0g.exe" @ToolArgs
    } else {
        & ".\r3cond0g.exe"
    }
}

Request-ExecutionPermission
Install-Dependencies
Setup-Project
Build-Tool
Run-Tool

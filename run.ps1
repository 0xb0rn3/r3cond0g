#Requires -Version 5.1
<#
.SYNOPSIS
    ReconRaptor (r3cond0g) - Enhanced Runner & Setup Script for Windows
.DESCRIPTION 
    PowerShell script that automates the setup, update, compilation, and execution of ReconRaptor on Windows systems.
    Can be deployed via: irm https://raw.githubusercontent.com/0xb0rn3/r3cond0g/main/run.ps1 | iex
.PARAMETER SkipUpdateCheck
    Skip the update check entirely for this run
.PARAMETER ForceUpdateCheck  
    Force check for updates, bypassing the time interval
.PARAMETER Rebuild
    Force recompilation of the tool
.PARAMETER Help
    Show help information and exit
.NOTES
    Script Version: 0.2.2
    Target Tool Version: 0.2.2 ReconRaptor
    Author: 0xb0rn3 & 0xbv1
    Requires: PowerShell 5.1+, Git, Go 1.18+
#>

[CmdletBinding()]
param(
    [switch]$SkipUpdateCheck,
    [switch]$ForceUpdateCheck, 
    [switch]$Rebuild,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArgs
)

# --- Configuration ---
$Global:Config = @{
    RepoUrl = "https://github.com/0xb0rn3/r3cond0g.git"
    RepoName = "r3cond0g" 
    ToolExecutableName = "r3cond0g.exe"
    MainGoFile = "main.go"
    GoModFile = "go.mod"
    UpdateCheckFile = ".last_update_check"
    UpdateCheckInterval = 3600  # Check for updates every 1 hour (3600 seconds)
    ScriptVersion = "0.2.2"
    ToolVersion = "0.2.2"
}

# --- Color Configuration for Enhanced Visual Feedback ---
$Global:Colors = @{
    Red = 'Red'
    Green = 'Green' 
    Yellow = 'Yellow'
    Blue = 'Blue'
    Cyan = 'Cyan'
    Magenta = 'Magenta'
    White = 'White'
    Gray = 'Gray'
}

# --- Helper Functions for Enhanced Console Output ---
function Write-Header {
    Write-Host "╔═════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $Global:Colors.Magenta
    Write-Host "║                      " -ForegroundColor $Global:Colors.Magenta -NoNewline
    Write-Host "ReconRaptor (r3cond0g) Runner" -ForegroundColor $Global:Colors.Cyan -NoNewline  
    Write-Host "                      ║" -ForegroundColor $Global:Colors.Magenta
    Write-Host "║                     " -ForegroundColor $Global:Colors.Magenta -NoNewline
    Write-Host "Enhanced Environment Setup & Launch" -ForegroundColor $Global:Colors.Blue -NoNewline
    Write-Host "                 ║" -ForegroundColor $Global:Colors.Magenta
    Write-Host "║                          " -ForegroundColor $Global:Colors.Magenta -NoNewline
    Write-Host "Script Version: $($Global:Config.ScriptVersion)" -ForegroundColor $Global:Colors.Yellow -NoNewline
    Write-Host "                           ║" -ForegroundColor $Global:Colors.Magenta
    Write-Host "╚═════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $Global:Colors.Magenta
    Write-Host ""
}

function Write-Status {
    param([string]$Message)
    Write-Host "[⚙️ INFO] " -ForegroundColor $Global:Colors.Blue -NoNewline
    Write-Host $Message -ForegroundColor $Global:Colors.White
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓ OKAY] " -ForegroundColor $Global:Colors.Green -NoNewline
    Write-Host $Message -ForegroundColor $Global:Colors.White
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗ FAIL] " -ForegroundColor $Global:Colors.Red -NoNewline
    Write-Host $Message -ForegroundColor $Global:Colors.White
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[⚠️ WARN] " -ForegroundColor $Global:Colors.Yellow -NoNewline
    Write-Host $Message -ForegroundColor $Global:Colors.White
}

function Write-Update {
    param([string]$Message)
    Write-Host "[🔄 UPDATE] " -ForegroundColor $Global:Colors.Cyan -NoNewline
    Write-Host $Message -ForegroundColor $Global:Colors.White
}

# --- System Requirements and Dependency Management ---
function Test-Administrator {
    # Check if running as administrator for certain operations
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-GitForWindows {
    Write-Status "Git not found. Attempting to install Git for Windows..."
    
    # Check if we can use winget (Windows Package Manager)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            Write-Status "Installing Git using Windows Package Manager..."
            winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements
            
            # Refresh PATH environment variable  
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            if (Get-Command git -ErrorAction SilentlyContinue) {
                Write-Success "Git installed successfully via winget."
                return $true
            }
        }
        catch {
            Write-Warning "winget installation failed: $($_.Exception.Message)"
        }
    }
    
    # Fallback: Check if we can use Chocolatey
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            Write-Status "Installing Git using Chocolatey..."
            choco install git -y
            
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            if (Get-Command git -ErrorAction SilentlyContinue) {
                Write-Success "Git installed successfully via Chocolatey."
                return $true
            }
        }
        catch {
            Write-Warning "Chocolatey installation failed: $($_.Exception.Message)"
        }
    }
    
    # Manual installation guidance
    Write-Error "Automatic Git installation failed."
    Write-Warning "Please manually install Git from: https://git-scm.com/download/win"
    Write-Warning "After installation, restart PowerShell and run this script again."
    return $false
}

function Install-GoLanguage {
    Write-Status "Go not found. Attempting to install Go for Windows..."
    
    # Check if we can use winget
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            Write-Status "Installing Go using Windows Package Manager..."
            winget install --id GoLang.Go -e --source winget --accept-package-agreements --accept-source-agreements
            
            # Refresh PATH environment variable
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            if (Get-Command go -ErrorAction SilentlyContinue) {
                Write-Success "Go installed successfully via winget."
                return $true
            }
        }
        catch {
            Write-Warning "winget installation failed: $($_.Exception.Message)"
        }
    }
    
    # Fallback: Check if we can use Chocolatey
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        try {
            Write-Status "Installing Go using Chocolatey..."
            choco install golang -y
            
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            if (Get-Command go -ErrorAction SilentlyContinue) {
                Write-Success "Go installed successfully via Chocolatey."
                return $true
            }
        }
        catch {
            Write-Warning "Chocolatey installation failed: $($_.Exception.Message)"
        }
    }
    
    # Manual installation guidance
    Write-Error "Automatic Go installation failed."
    Write-Warning "Please manually install Go from: https://golang.org/dl/"
    Write-Warning "After installation, restart PowerShell and run this script again."
    return $false
}

function Test-Dependencies {
    Write-Status "Checking system dependencies..."
    
    # Check Git
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        if (-not (Install-GitForWindows)) {
            return $false
        }
    } else {
        $gitVersion = git --version 2>$null
        Write-Success "Git found: $gitVersion"
    }
    
    # Check Go
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        if (-not (Install-GoLanguage)) {
            return $false
        }
    } else {
        $goVersion = go version 2>$null
        Write-Success "Go found: $goVersion"
    }
    
    return $true
}

# --- Repository and Update Management ---
function Get-GitCommitHash {
    try {
        $hash = git rev-parse HEAD 2>$null
        return $hash
    }
    catch {
        return "unknown"
    }
}

function Get-RemoteCommitHash {
    try {
        $result = git ls-remote $Global:Config.RepoUrl HEAD 2>$null
        if ($result) {
            return ($result -split '\s+')[0]
        }
        return "remote_unknown"
    }
    catch {
        return "remote_unknown" 
    }
}

function Test-ShouldCheckForUpdates {
    if (-not (Test-Path $Global:Config.UpdateCheckFile)) {
        return $true
    }
    
    try {
        $lastCheck = Get-Content $Global:Config.UpdateCheckFile -ErrorAction SilentlyContinue
        $currentTime = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        
        if ($lastCheck -and (($currentTime - [int]$lastCheck) -gt $Global:Config.UpdateCheckInterval)) {
            return $true
        }
        return $false
    }
    catch {
        return $true
    }
}

function Update-LastCheckTimestamp {
    $currentTime = [DateTimeOffset]::Now.ToUnixTimeSeconds()
    $currentTime | Out-File -FilePath $Global:Config.UpdateCheckFile -Encoding UTF8
}

function Test-UpdatesAvailable {
    $localCommit = Get-GitCommitHash
    $remoteCommit = Get-RemoteCommitHash
    
    Update-LastCheckTimestamp
    
    if ($localCommit -eq "unknown" -or $remoteCommit -eq "remote_unknown") {
        Write-Warning "Could not determine local or remote version. Skipping update check."
        return $false
    }
    
    if ($localCommit -ne $remoteCommit) {
        Write-Update "A new version is available!"
        Write-Update "  Current: $($localCommit.Substring(0, [Math]::Min(12, $localCommit.Length)))"
        Write-Update "  Latest:  $($remoteCommit.Substring(0, [Math]::Min(12, $remoteCommit.Length)))"
        return $true
    }
    
    Write-Success "Your ReconRaptor is up to date (commit: $($localCommit.Substring(0, [Math]::Min(7, $localCommit.Length))))."
    Clear-Host
    return $false
}

function Invoke-UpdateProcess {
    Write-Host ""
    Write-Update "╔════════════════════════════════════════════════════════════╗"
    Write-Update "║                     UPDATE AVAILABLE                       ║"
    Write-Update "║  A new version of ReconRaptor is available.                ║"
    Write-Update "║  Would you like to download and apply the update now?      ║"
    Write-Update "╚════════════════════════════════════════════════════════════╝"
    Write-Host ""
    
    do {
        $response = Read-Host "[❓ PROMPT] Install update? (Y/es to update, N/o to skip)"
        switch ($response.ToLower()) {
            { $_ -in @('y', 'yes') } {
                Write-Status "Attempting to update ReconRaptor..."
                try {
                    git pull --ff-only
                    Write-Success "Update downloaded. Restarting script..."
                    
                    # Restart the script with original arguments
                    $scriptArgs = @()
                    if ($SkipUpdateCheck) { $scriptArgs += '-SkipUpdateCheck' }
                    if ($ForceUpdateCheck) { $scriptArgs += '-ForceUpdateCheck' }
                    if ($Rebuild) { $scriptArgs += '-Rebuild' }
                    if ($ToolArgs) { $scriptArgs += $ToolArgs }
                    
                    & $PSCommandPath @scriptArgs
                    exit 0
                }
                catch {
                    Write-Error "Automatic update failed. Git pull encountered issues: $($_.Exception.Message)"
                    Write-Warning "You might need to resolve conflicts manually or try 'git reset --hard origin/main'."
                    Write-Status "Continuing with the current version."
                    return $false
                }
            }
            { $_ -in @('n', 'no') } {
                Write-Status "Update declined. Continuing with the current version."
                return $false
            }
            default {
                Write-Host "Please answer (Y)es or (N)o." -ForegroundColor $Global:Colors.Yellow
            }
        }
    } while ($true)
}

function Invoke-UpdateWorkflow {
    param([bool]$ForceCheck)
    
    if ($ForceCheck -or (Test-ShouldCheckForUpdates)) {
        Write-Status "Checking for ReconRaptor updates..."
        if (Test-UpdatesAvailable) {
            Invoke-UpdateProcess
        }
    } else {
        Write-Status "Skipping update check (checked recently)."
    }
}

# --- Go Project Management Functions ---
function Initialize-GoModule {
    if (-not (Test-Path $Global:Config.GoModFile)) {
        Write-Status "Go module file ('$($Global:Config.GoModFile)') not found. Initializing..."
        try {
            $moduleName = Split-Path -Leaf (Get-Location)
            go mod init $moduleName
            Write-Success "Go module initialized."
        }
        catch {
            Write-Warning "Could not auto-initialize go module. 'go mod tidy' might fail."
        }
    } else {
        Write-Success "Go module file ('$($Global:Config.GoModFile)') found."
    }
}

function Invoke-GoModTidy {
    Write-Status "Managing Go dependencies..."
    
    try {
        # Get critical dependencies that might be missing
        Write-Status "Ensuring critical dependencies are available..."
        go get golang.org/x/time/rate 2>$null
        
        # Tidy up the module
        go mod tidy
        Write-Success "Go dependencies are tidy."
        return $true
    }
    catch {
        Write-Warning "'go mod tidy' encountered issues: $($_.Exception.Message). Compilation may fail."
        return $false
    }
}

function Test-NeedsRecompilation {
    if (-not (Test-Path $Global:Config.ToolExecutableName)) {
        return $true
    }
    
    $binaryTime = (Get-Item $Global:Config.ToolExecutableName).LastWriteTime
    
    # Check if any .go file or go.mod/go.sum is newer than the binary
    $sourceFiles = @('*.go', $Global:Config.GoModFile, 'go.sum')
    
    foreach ($pattern in $sourceFiles) {
        $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            if ($file.LastWriteTime -gt $binaryTime) {
                Write-Status "Changes detected in '$($file.Name)'. Recompilation needed."
                return $true
            }
        }
    }
    
    return $false
}

function Invoke-CompileTool {
    Write-Status "Compiling ReconRaptor ($($Global:Config.ToolExecutableName) from $($Global:Config.MainGoFile))..."
    
    try {
        # Build with optimization flags to reduce binary size
        $buildArgs = @(
            'build',
            '-ldflags="-s -w"',  # -s: Omit symbol table, -w: Omit DWARF debug info
            '-o', $Global:Config.ToolExecutableName,
            $Global:Config.MainGoFile
        )
        
        & go @buildArgs
        
        if (Test-Path $Global:Config.ToolExecutableName) {
            Write-Success "ReconRaptor compiled successfully: $($Global:Config.ToolExecutableName)"
            Clear-Host
            return $true
        } else {
            throw "Binary not found after compilation"
        }
    }
    catch {
        Write-Error "Compilation failed! Check Go environment and source code: $($_.Exception.Message)"
        return $false
    }
}

# --- Help and Usage Information ---
function Show-HelpInformation {
    Write-Header
    Write-Host "This script automates the setup, update, compilation, and execution of ReconRaptor on Windows." -ForegroundColor $Global:Colors.Green
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor $Global:Colors.Yellow -NoNewline
    Write-Host " .\run.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor $Global:Colors.Cyan
    Write-Host "  " -NoNewline
    Write-Host "-ForceUpdateCheck" -ForegroundColor $Global:Colors.Green -NoNewline
    Write-Host "      Force check for updates, bypassing the time interval."
    Write-Host "  " -NoNewline  
    Write-Host "-SkipUpdateCheck" -ForegroundColor $Global:Colors.Green -NoNewline
    Write-Host "       Skip the update check entirely for this run."
    Write-Host "  " -NoNewline
    Write-Host "-Rebuild" -ForegroundColor $Global:Colors.Green -NoNewline
    Write-Host "              Force recompilation of the tool."
    Write-Host "  " -NoNewline
    Write-Host "-Help" -ForegroundColor $Global:Colors.Green -NoNewline  
    Write-Host "                 Show this help message and exit."
    Write-Host ""
    Write-Host "Remote Execution:" -ForegroundColor $Global:Colors.Blue
    Write-Host "  irm https://raw.githubusercontent.com/0xb0rn3/r3cond0g/main/run.ps1 | iex"
    Write-Host ""
    Write-Host "Workflow:" -ForegroundColor $Global:Colors.Blue
    Write-Host "  1. Checks/installs Git and Go using Windows Package Manager or Chocolatey."
    Write-Host "  2. Checks for remote updates (if applicable) and prompts to apply."
    Write-Host "  3. Initializes Go module and tidies dependencies."
    Write-Host "  4. Compiles ReconRaptor if needed or if source files have changed."
    Write-Host "  5. Executes the compiled ReconRaptor tool."
    Write-Host ""
    exit 0
}

# --- Repository Setup for Remote Execution ---
function Initialize-Repository {
    if (-not (Test-Path $Global:Config.GoModFile)) {
        Write-Status "ReconRaptor not found locally. Cloning repository..."
        try {
            git clone $Global:Config.RepoUrl $Global:Config.RepoName
            Set-Location $Global:Config.RepoName
            Write-Success "Repository cloned successfully."
        }
        catch {
            Write-Error "Failed to clone repository: $($_.Exception.Message)"
            Write-Warning "Please ensure you have internet connectivity and Git is properly installed."
            exit 1
        }
    }
}

# --- Main Execution Flow ---
function Invoke-MainWorkflow {
    # Handle help request immediately
    if ($Help) {
        Show-HelpInformation
    }
    
    Write-Header
    
    # Initialize repository if needed (for remote execution)
    Initialize-Repository
    
    # Verify main Go file exists
    if (-not (Test-Path $Global:Config.MainGoFile)) {
        Write-Error "$($Global:Config.MainGoFile) not found. Ensure you are in the ReconRaptor root directory."
        Write-Warning "If this is a fresh clone, there might be an issue with the repository structure or clone process."
        exit 1
    }
    
    # Step 1: Ensure dependencies are available
    if (-not (Test-Dependencies)) {
        Write-Error "Required dependencies are not available. Please install them manually and try again."
        exit 1
    }
    
    # Step 2: Handle updates (if not skipped)
    if (-not $SkipUpdateCheck) {
        Invoke-UpdateWorkflow -ForceCheck $ForceUpdateCheck.IsPresent
    } else {
        Write-Status "Update check skipped by user."
    }
    
    # Step 3: Go module initialization and dependency management
    Initialize-GoModule
    Invoke-GoModTidy | Out-Null
    
    # Step 4: Compile binary if needed
    if ($Rebuild -or (Test-NeedsRecompilation)) {
        if ($Rebuild) {
            Write-Status "Forcing rebuild as requested."
        }
        
        if (-not (Invoke-CompileTool)) {
            exit 1
        }
    } else {
        Write-Success "ReconRaptor binary is up to date. No recompilation needed."
        Clear-Host
    }
    
    # Step 5: Execute ReconRaptor
    Write-Host ""
    Write-Status "Launching ReconRaptor..."
    Write-Host "═════════════════════════════════════════════════════════════════════════════" -ForegroundColor $Global:Colors.Magenta
    Write-Host ""
    
    # Clear screen before launching for cleaner UI
    Clear-Host
    
    # Execute the compiled binary with arguments
    try {
        if ($ToolArgs) {
            & ".\$($Global:Config.ToolExecutableName)" @ToolArgs
        } else {
            & ".\$($Global:Config.ToolExecutableName)"
        }
    }
    catch {
        Write-Error "Failed to execute ReconRaptor: $($_.Exception.Message)"
        exit 1
    }
    
    Write-Host ""
    Write-Host "═════════════════════════════════════════════════════════════════════════════" -ForegroundColor $Global:Colors.Magenta
    Write-Success "ReconRaptor session ended."
}

# --- Script Entry Point ---
try {
    Invoke-MainWorkflow
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Stack Trace:" -ForegroundColor $Global:Colors.Red
    Write-Host $_.ScriptStackTrace -ForegroundColor $Global:Colors.Gray
    exit 1
}

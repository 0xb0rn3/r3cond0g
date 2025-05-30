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
    Script Version: 0.2.3
    Target Tool Version: 0.2.2 ReconRaptor
    Author: 0xb0rn3 & 0xbv1
    Requires: PowerShell 5.1+, Git, Go 1.18+
#>

# Handle parameters more robustly for remote execution
param(
    [switch]$SkipUpdateCheck,
    [switch]$ForceUpdateCheck, 
    [switch]$Rebuild,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArgs
)

# Check if we're running via iex (remote execution) by examining the call stack
$Global:IsRemoteExecution = $false
try {
    $callStack = Get-PSCallStack
    if ($callStack.Count -gt 1 -and $callStack[1].Command -eq "Invoke-Expression") {
        $Global:IsRemoteExecution = $true
        Write-Host "[REMOTE] Detected remote execution via Invoke-Expression" -ForegroundColor Cyan
    }
} catch {
    # Fallback detection - if we can't determine, assume local
    $Global:IsRemoteExecution = $false
}

# --- Configuration ---
$Global:Config = @{
    RepoUrl = "https://github.com/0xb0rn3/r3cond0g.git"
    RepoName = "r3cond0g" 
    ToolExecutableName = "r3cond0g.exe"
    MainGoFile = "main.go"
    GoModFile = "go.mod"
    UpdateCheckFile = ".last_update_check"
    UpdateCheckInterval = 3600  # Check for updates every 1 hour (3600 seconds)
    ScriptVersion = "0.2.3"
    ToolVersion = "0.2.2"
    WorkingDirectory = $null  # Will be set during initialization
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
    if ($Global:IsRemoteExecution) {
        Write-Host "║                            " -ForegroundColor $Global:Colors.Magenta -NoNewline
        Write-Host "REMOTE EXECUTION MODE" -ForegroundColor $Global:Colors.Cyan -NoNewline
        Write-Host "                            ║" -ForegroundColor $Global:Colors.Magenta
    }
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

# --- Enhanced Working Directory Management ---
function Initialize-WorkingDirectory {
    # For remote execution, we need to set up a proper working directory
    if ($Global:IsRemoteExecution) {
        # Create a temporary directory for the project
        $tempPath = [System.IO.Path]::GetTempPath()
        $projectPath = Join-Path $tempPath "ReconRaptor-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        
        # Create the directory
        New-Item -ItemType Directory -Path $projectPath -Force | Out-Null
        Set-Location $projectPath
        $Global:Config.WorkingDirectory = $projectPath
        
        Write-Status "Initialized working directory: $projectPath"
        return $projectPath
    } else {
        # For local execution, use current directory
        $Global:Config.WorkingDirectory = Get-Location
        Write-Status "Using current directory: $(Get-Location)"
        return Get-Location
    }
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
            $result = winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements 2>&1
            
            # Refresh PATH environment variable  
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            # Wait a moment for the installation to complete
            Start-Sleep -Seconds 3
            
            if (Get-Command git -ErrorAction SilentlyContinue) {
                Write-Success "Git installed successfully via winget."
                return $true
            } else {
                Write-Warning "Git installation completed but git command not found in PATH. You may need to restart PowerShell."
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
            choco install git -y 2>&1 | Out-Null
            
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            # Wait a moment for the installation to complete
            Start-Sleep -Seconds 3
            
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
            $result = winget install --id GoLang.Go -e --source winget --accept-package-agreements --accept-source-agreements 2>&1
            
            # Refresh PATH environment variable
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            # Wait a moment for the installation to complete
            Start-Sleep -Seconds 3
            
            if (Get-Command go -ErrorAction SilentlyContinue) {
                Write-Success "Go installed successfully via winget."
                return $true
            } else {
                Write-Warning "Go installation completed but go command not found in PATH. You may need to restart PowerShell."
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
            choco install golang -y 2>&1 | Out-Null
            
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
            
            # Wait a moment for the installation to complete
            Start-Sleep -Seconds 3
            
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
        Write-Warning "Git not found. Attempting automatic installation..."
        if (-not (Install-GitForWindows)) {
            Write-Error "Git installation failed. Cannot proceed without Git."
            return $false
        }
    } else {
        $gitVersion = git --version 2>$null
        Write-Success "Git found: $gitVersion"
    }
    
    # Check Go
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Warning "Go not found. Attempting automatic installation..."
        if (-not (Install-GoLanguage)) {
            Write-Error "Go installation failed. Cannot proceed without Go."
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
    
    # For remote execution, auto-update to avoid user interaction issues
    if ($Global:IsRemoteExecution) {
        Write-Status "Remote execution detected. Auto-updating to latest version..."
        try {
            git pull --ff-only 2>&1 | Out-Null
            Write-Success "Update applied successfully."
            return $true
        }
        catch {
            Write-Warning "Auto-update failed: $($_.Exception.Message)"
            Write-Status "Continuing with current version."
            return $false
        }
    }
    
    # For local execution, prompt user
    do {
        $response = Read-Host "[❓ PROMPT] Install update? (Y/es to update, N/o to skip)"
        switch ($response.ToLower()) {
            { $_ -in @('y', 'yes') } {
                Write-Status "Attempting to update ReconRaptor..."
                try {
                    git pull --ff-only 2>&1 | Out-Null
                    Write-Success "Update downloaded successfully."
                    return $true
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
            go mod init $moduleName 2>&1 | Out-Null
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
    Write-Status "Managing Go dependencies... (this may take a moment)"
    
    try {
        # Get critical dependencies that might be missing
        Write-Status "Ensuring critical dependencies are available..."
        go get golang.org/x/time/rate 2>&1 | Out-Null
        
        # Tidy up the module
        go mod tidy 2>&1 | Out-Null
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
            '-ldflags=-s -w',  # -s: Omit symbol table, -w: Omit DWARF debug info
            '-o', $Global:Config.ToolExecutableName,
            $Global:Config.MainGoFile
        )
        
        $buildOutput = & go @buildArgs 2>&1
        
        if (Test-Path $Global:Config.ToolExecutableName) {
            Write-Success "ReconRaptor compiled successfully: $($Global:Config.ToolExecutableName)"
            return $true
        } else {
            throw "Binary not found after compilation. Output: $buildOutput"
        }
    }
    catch {
        Write-Error "Compilation failed! Check Go environment and source code: $($_.Exception.Message)"
        return $false
    }
}

# --- Enhanced Repository Setup for Remote Execution ---
function Initialize-Repository {
    # Always check if we're in a valid repository or need to clone
    $needsClone = $false
    
    # Check if we have a go.mod file OR if we're in a git repository
    if (-not (Test-Path $Global:Config.GoModFile) -and -not (Test-Path ".git")) {
        $needsClone = $true
    }
    
    # Additional check: if we have .git but no main.go, we might be in wrong directory
    if ((Test-Path ".git") -and (-not (Test-Path $Global:Config.MainGoFile))) {
        Write-Warning "Found .git directory but no main.go file. Repository might be incomplete."
        $needsClone = $true
    }
    
    if ($needsClone) {
        Write-Status "ReconRaptor repository not found locally. Cloning from GitHub..."
        try {
            # For remote execution, clone into current directory
            # For local execution, clone into subdirectory
            if ($Global:IsRemoteExecution) {
                # Clone directly into current directory
                git clone $Global:Config.RepoUrl . 2>&1 | Out-Null
                Write-Success "Repository cloned to current directory."
            } else {
                # Clone into subdirectory
                git clone $Global:Config.RepoUrl $Global:Config.RepoName 2>&1 | Out-Null
                Set-Location $Global:Config.RepoName
                Write-Success "Repository cloned and entered directory: $($Global:Config.RepoName)"
            }
        }
        catch {
            Write-Error "Failed to clone repository: $($_.Exception.Message)"
            Write-Warning "Please ensure you have internet connectivity and Git is properly installed."
            Write-Warning "Repository URL: $($Global:Config.RepoUrl)"
            
            # If this is remote execution and clone fails, we need to exit
            if ($Global:IsRemoteExecution) {
                Write-Error "Cannot proceed without repository access in remote execution mode."
                exit 1
            }
            
            # For local execution, user might fix manually
            return $false
        }
    } else {
        Write-Success "Repository already available locally."
    }
    
    return $true
}

# --- Help and Usage Information ---
function Show-HelpInformation {
    Write-Header
    Write-Host "This script automates the setup, update, compilation, and execution of ReconRaptor on Windows." -ForegroundColor $Global:Colors.Green
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor $Global:Colors.Yellow -NoNewline
    Write-Host " .\run.ps1 [OPTIONS] [TOOL_ARGUMENTS]"
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
    Write-Host "Tool Arguments:" -ForegroundColor $Global:Colors.Blue
    Write-Host "  Any additional arguments will be passed directly to ReconRaptor."
    Write-Host ""
    Write-Host "Remote Execution:" -ForegroundColor $Global:Colors.Blue
    Write-Host "  irm https://raw.githubusercontent.com/0xb0rn3/r3cond0g/main/run.ps1 | iex"
    Write-Host ""
    Write-Host "Local Execution:" -ForegroundColor $Global:Colors.Blue
    Write-Host "  .\run.ps1                    # Basic execution"
    Write-Host "  .\run.ps1 -domain example.com -output results.txt  # With tool arguments"
    Write-Host ""
    Write-Host "Workflow:" -ForegroundColor $Global:Colors.Blue
    Write-Host "  1. Initializes proper working directory (temp for remote execution)"
    Write-Host "  2. Checks/installs Git and Go using Windows Package Manager or Chocolatey"
    Write-Host "  3. Clones repository if not available locally"
    Write-Host "  4. Checks for remote updates and applies them (auto-update for remote execution)"
    Write-Host "  5. Initializes Go module and tidies dependencies"
    Write-Host "  6. Compiles ReconRaptor if needed or if source files have changed"
    Write-Host "  7. Executes the compiled ReconRaptor tool with any provided arguments"
    Write-Host ""
    
    # Don't exit immediately in remote execution mode since the user can't easily re-run
    if (-not $Global:IsRemoteExecution) {
        exit 0
    }
}

# --- Main Execution Flow ---
function Invoke-MainWorkflow {
    # Handle help request
    if ($Help) {
        Show-HelpInformation
        if ($Global:IsRemoteExecution) {
            Write-Host "Continuing with normal execution..." -ForegroundColor $Global:Colors.Yellow
            Write-Host ""
        } else {
            exit 0
        }
    }
    
    Write-Header
    
    # Step 1: Initialize proper working directory
    Initialize-WorkingDirectory | Out-Null
    
    # Step 2: Ensure dependencies are available
    if (-not (Test-Dependencies)) {
        Write-Error "Required dependencies are not available. Please install them manually and try again."
        
        # For remote execution, provide more detailed guidance
        if ($Global:IsRemoteExecution) {
            Write-Host ""
            Write-Host "For remote execution, ensure you have:" -ForegroundColor $Global:Colors.Yellow
            Write-Host "  1. Git installed and in PATH"
            Write-Host "  2. Go 1.18+ installed and in PATH"
            Write-Host "  3. Internet connectivity for repository access"
            Write-Host ""
            Write-Host "You can install these via:"
            Write-Host "  winget install Git.Git GoLang.Go"
            Write-Host "  or"
            Write-Host "  choco install git golang"
        }
        
        exit 1
    }
    
    # Step 3: Initialize repository (clone if needed)
    if (-not (Initialize-Repository)) {
        Write-Error "Failed to initialize repository. Cannot proceed."
        exit 1
    }
    
    # Step 4: Verify main Go file exists
    if (-not (Test-Path $Global:Config.MainGoFile)) {
        Write-Error "$($Global:Config.MainGoFile) not found in current directory: $(Get-Location)"
        Write-Warning "Repository structure might be incomplete or clone failed."
        
        # List current directory contents for debugging
        Write-Status "Current directory contents:"
        Get-ChildItem | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor $Global:Colors.Gray }
        
        exit 1
    }
    
    # Step 5: Handle updates (if not skipped)
    if (-not $SkipUpdateCheck) {
        Invoke-UpdateWorkflow -ForceCheck $ForceUpdateCheck.IsPresent
    } else {
        Write-Status "Update check skipped by user."
    }
    
    # Step 6: Go module initialization and dependency management
    Initialize-GoModule
    Invoke-GoModTidy | Out-Null
    
    # Step 7: Compile binary if needed
    if ($Rebuild -or (Test-NeedsRecompilation)) {
        if ($Rebuild) {
            Write-Status "Forcing rebuild as requested."
        }
        
        if (-not (Invoke-CompileTool)) {
            Write-Error "Compilation failed. Cannot proceed."
            exit 1
        }
    } else {
        Write-Success "ReconRaptor binary is up to date. No recompilation needed."
    }
    
    # Step 8: Execute ReconRaptor
    Write-Host ""
    Write-Status "Launching ReconRaptor..."
    
    # Provide information about the execution context
    if ($Global:IsRemoteExecution) {
        Write-Status "Running from: $($Global:Config.WorkingDirectory)"
        if ($ToolArgs) {
            Write-Status "Tool arguments: $($ToolArgs -join ' ')"
        }
    }
    
    Write-Host "═════════════════════════════════════════════════════════════════════════════" -ForegroundColor $Global:Colors.Magenta
    Write-Host ""
    
    # Execute the compiled binary with arguments
    try {
        $executablePath = Join-Path (Get-Location) $Global:Config.ToolExecutableName
        
        if ($ToolArgs) {
            Write-Status "Executing: $executablePath $($ToolArgs -join ' ')"
            & $executablePath @ToolArgs
        } else {
            Write-Status "Executing: $executablePath"
            & $executablePath
        }
        
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0 -and $exitCode -ne $null) {
            Write-Warning "ReconRaptor exited with code: $exitCode"
        }
    }
    catch {
        Write-Error "Failed to execute ReconRaptor: $($_.Exception.Message)"
        Write-Status "Executable path: $executablePath"
        Write-Status "Current directory: $(Get-Location)"
        
        # Check if executable exists and is accessible
        if (Test-Path $executablePath) {
            Write-Status "Executable exists at: $executablePath"
        } else {
            Write-Error "Executable not found at: $executablePath"
        }
        
        exit 1
    }
    
    Write-Host ""
    Write-Host "═════════════════════════════════════════════════════════════════════════════" -ForegroundColor $Global:Colors.Magenta
    Write-Success "ReconRaptor execution completed."
    
    # For remote execution, provide cleanup information
    if ($Global:IsRemoteExecution) {
        Write-Host ""
        Write-Status "Remote execution completed. Files are located at:"
        Write-Host "  $($Global:Config.WorkingDirectory)" -ForegroundColor $Global:Colors.Cyan
        Write-Status "You can navigate to this directory to access any generated files."
        
        # Optionally show generated files
        $outputFiles = Get-ChildItem -Path $Global:Config.WorkingDirectory -File | Where-Object { 
            $_.Extension -in @('.txt', '.json', '.csv', '.xml', '.html') -or 
            $_.Name -like '*output*' -or 
            $_.Name -like '*result*' -or 
            $_.Name -like '*report*' 
        }
        
        if ($outputFiles) {
            Write-Status "Generated files detected:"
            $outputFiles | ForEach-Object {
                Write-Host "  📄 $($_.Name) ($([math]::Round($_.Length/1KB, 2)) KB)" -ForegroundColor $Global:Colors.Green
            }
        }
    }
}

# --- Enhanced Error Handling and Cleanup ---
function Invoke-Cleanup {
    # Cleanup function for graceful shutdown
    if ($Global:IsRemoteExecution -and $Global:Config.WorkingDirectory) {
        # Don't auto-delete in remote execution mode as user might want the files
        Write-Status "Working directory preserved: $($Global:Config.WorkingDirectory)"
    }
}

# --- Script Entry Point with Enhanced Error Handling ---
try {
    # Set up error handling
    $ErrorActionPreference = "Stop"
    
    # Register cleanup function
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Invoke-Cleanup
    } | Out-Null
    
    # Execute main workflow
    Invoke-MainWorkflow
}
catch {
    Write-Host ""
    Write-Error "Script execution failed: $($_.Exception.Message)"
    
    # Provide detailed error information for debugging
    Write-Host ""
    Write-Host "Error Details:" -ForegroundColor $Global:Colors.Red
    Write-Host "  Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor $Global:Colors.Gray
    Write-Host "  Location: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor $Global:Colors.Gray
    Write-Host "  Command: $($_.InvocationInfo.Line.Trim())" -ForegroundColor $Global:Colors.Gray
    
    if ($_.ScriptStackTrace) {
        Write-Host ""
        Write-Host "Stack Trace:" -ForegroundColor $Global:Colors.Red
        Write-Host $_.ScriptStackTrace -ForegroundColor $Global:Colors.Gray
    }
    
    # For remote execution, provide additional troubleshooting info
    if ($Global:IsRemoteExecution) {
        Write-Host ""
        Write-Host "Remote Execution Troubleshooting:" -ForegroundColor $Global:Colors.Yellow
        Write-Host "  1. Ensure you have Git and Go installed and in PATH"
        Write-Host "  2. Check your internet connection"
        Write-Host "  3. Verify repository access: $($Global:Config.RepoUrl)"
        Write-Host "  4. Try running locally: Download and run .\run.ps1"
        Write-Host ""
        Write-Host "Current Environment:" -ForegroundColor $Global:Colors.Blue
        Write-Host "  PowerShell Version: $($PSVersionTable.PSVersion)"
        Write-Host "  Execution Policy: $(Get-ExecutionPolicy)"
        Write-Host "  Working Directory: $(Get-Location)"
        Write-Host "  Is Administrator: $(Test-Administrator)"
    }
    
    # Cleanup and exit
    Invoke-Cleanup
    exit 1
}
finally {
    # Ensure cleanup runs even if there's an error
    Invoke-Cleanup
}

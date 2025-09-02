#Requires -RunAsAdministrator

# LitterBox Malware Analysis Platform - Automated Setup
# Automated installation and configuration script for LitterBox isolated malware analysis environment

# Configuration
$Script:Config = @{
    InstallDir          = "C:\LitterBox"
    RepoUrl            = "https://github.com/BlackSnufkin/LitterBox.git"
    DebloatRepoUrl     = "https://github.com/W4RH4WK/Debloat-Windows-10.git"
    DebloatPath        = "C:\Debloat-Windows-10"
    WebPort            = 1337
    MCPPort            = 8080
    LogFile            = "$env:TEMP\LitterBox-Setup.log"
}

# Logging functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $Script:Config.LogFile -Value $LogEntry
    
    switch ($Level) {
        "SUCCESS" { Write-Host "[+] $Message" -ForegroundColor Green }
        "WARNING" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[-] $Message" -ForegroundColor Red }
        default   { Write-Host "[*] $Message" -ForegroundColor Cyan }
    }
}

function Test-Administrator {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Environment {
    Write-Log "Initializing LitterBox setup environment" "SUCCESS"
    
    if (-not (Test-Administrator)) {
        Write-Log "Script must be run as Administrator" "ERROR"
        exit 1
    }
    
    # Set execution policy
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
        Write-Log "Execution policy configured"
    }
    catch {
        Write-Log "Failed to set execution policy: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    
    # Create installation directory
    if (-not (Test-Path $Script:Config.InstallDir)) {
        New-Item -ItemType Directory -Path $Script:Config.InstallDir -Force | Out-Null
        Write-Log "Created installation directory: $($Script:Config.InstallDir)"
    }
}

function Set-DefenderExclusions {
    Write-Log "Configuring Windows Defender exclusions"
    
    try {
        Add-MpPreference -ExclusionPath $Script:Config.InstallDir -ErrorAction Stop
        Write-Log "Windows Defender exclusions applied for: $($Script:Config.InstallDir)" "SUCCESS"
        
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
        Write-Log "Windows Defender sample submission disabled" "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure Defender exclusions: $($_.Exception.Message)" "WARNING"
        Write-Log "Malware samples may be quarantined during analysis" "WARNING"
    }
}

function Install-Prerequisites {
    Write-Log "Installing system prerequisites"
    
    # Install .NET Framework 3.5
    Write-Log "Installing .NET Framework 3.5..."
    try {
        dism /online /enable-feature /featurename:NetFx3 /all /norestart /quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log ".NET Framework 3.5 installed successfully" "SUCCESS"
        }
        else {
            Write-Log ".NET Framework 3.5 installation failed (Exit code: $LASTEXITCODE)" "WARNING"
        }
    }
    catch {
        Write-Log "Error installing .NET Framework 3.5: $($_.Exception.Message)" "WARNING"
    }
}

function Install-Chocolatey {
    Write-Log "Installing Chocolatey package manager"
    
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) 2>&1 | Out-Null
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Log "Chocolatey installed successfully" "SUCCESS"
    }
    catch {
        Write-Log "Failed to install Chocolatey: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-Dependencies {
    Write-Log "Installing core dependencies via Chocolatey"
    
    # Install core packages
    Write-Log "Installing Python, Git, and dependencies..."
    choco install -y python3 git 7zip vcredist-all --no-progress 2>&1 | Out-Null

    # Install build tools (commented sections from original)
    Write-Log "Installing Visual C++ and build tools..."
    choco install dotnetfx -y --no-progress --ignore-package-exit-codes --force 2>&1 | Out-Null
    choco install visualstudio2022buildtools -y --no-progress --force 2>&1 | Out-Null
    choco install visualstudio2022-workload-vctools -y --no-progress --force 2>&1 | Out-Null
    choco install windows-sdk-10-version-2004-all -y --no-progress --force 2>&1 | Out-Null

    # Wait for installations
    Start-Sleep -Seconds 30

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Log "Dependencies installation completed" "SUCCESS"
}

function Clone-DebloatRepo {
    Write-Log "Cloning W4RH4WK Debloat-Windows-10 repository"
    
    # Remove existing repo if present
    if (Test-Path $Script:Config.DebloatPath) {
        Remove-Item $Script:Config.DebloatPath -Recurse -Force
        Write-Log "Removed existing debloat repository"
    }
    
    Set-Location C:\
    try {
        git clone $Script:Config.DebloatRepoUrl 2>&1 | Out-Null
        Write-Log "Debloat repository cloned successfully" "SUCCESS"
        return $Script:Config.DebloatPath
    }
    catch {
        Write-Log "Failed to clone debloat repository: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Run-DebloatScripts {
    param([string]$RepoPath, [int]$Round)
    
    Write-Log "Running debloat scripts - Round $Round"
    
    $ScriptsPath = "$RepoPath\scripts"
    Set-Location $ScriptsPath
    
    # Unblock all PowerShell scripts
    Get-ChildItem -Recurse *.ps*1 | Unblock-File
    Write-Log "PowerShell scripts unblocked"
    
    $Scripts = @(
        "block-telemetry.ps1",
        "disable-services.ps1", 
        "fix-privacy-settings.ps1",
        "optimize-user-interface.ps1",
        "remove-default-apps.ps1"
        #"remove-onedrive.ps1"
    )
    
    foreach ($Script in $Scripts) {
        if (Test-Path $Script) {
            Write-Log "Executing $Script..."
            try {
                Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy", "Bypass", "-File", ".\$Script" -Wait -WindowStyle Hidden | Out-Null
                Write-Log "$Script completed successfully" "SUCCESS"
            }
            catch {
                Write-Log "Error in $Script`: $($_.Exception.Message)" "WARNING"
            }
        }
        else {
            Write-Log "$Script not found" "WARNING"
        }
    }
    
    Write-Log "Debloat round $Round completed" "SUCCESS"
}

function Prep-SandBox {
    $RepoPath = Clone-DebloatRepo

    # Round 1
    Run-DebloatScripts -RepoPath $RepoPath -Round 1

    Write-Log "Waiting 10 seconds before Round 2..."
    Start-Sleep -Seconds 10

    # Round 2
    Run-DebloatScripts -RepoPath $RepoPath -Round 2

    Write-Log "Windows debloating completed!" "SUCCESS"
    Write-Log "Reboot required to complete all changes" "WARNING"
    
    # Cleanup - Remove debloat repository
    Write-Log "Cleaning up debloat repository..."
    Set-Location C:\
    Start-Sleep -Seconds 5
    try {
        Remove-Item $RepoPath -Recurse -Force -ErrorAction Stop
        Write-Log "Debloat repository removed successfully" "SUCCESS"
    }
    catch {
        Write-Log "Repository cleanup will be attempted after reboot" "WARNING"
        # Schedule cleanup for next boot
        $CleanupScript = "Remove-Item '$RepoPath' -Recurse -Force -ErrorAction SilentlyContinue"
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'LitterBoxCleanup' -Value "powershell -Command `"$CleanupScript`"" -PropertyType String -Force | Out-Null
    }
}

function Install-LitterBox {
    Write-Log "Cloning and configuring LitterBox repository"
    
    # Clone repository
    Write-Log "Cloning LitterBox repository..."
    Set-Location C:\
    try {
        git clone $Script:Config.RepoUrl 2>&1 | Out-Null
        Set-Location $Script:Config.InstallDir
        Write-Log "LitterBox repository cloned successfully" "SUCCESS"
    }
    catch {
        Write-Log "Failed to clone LitterBox repository: $($_.Exception.Message)" "ERROR"
        throw
    }
    
    # Create virtual environment
    Write-Log "Creating Python virtual environment..."
    try {
        python -m venv venv 2>&1 | Out-Null
        Write-Log "Python virtual environment created" "SUCCESS"
    }
    catch {
        Write-Log "Failed to create virtual environment: $($_.Exception.Message)" "ERROR"
        throw
    }

    # Install Python dependencies
    Write-Log "Installing Python dependencies..."
    try {
        & ".\venv\Scripts\Activate.ps1"
        .\venv\Scripts\pip.exe install --upgrade pip --quiet 2>&1 | Out-Null
        .\venv\Scripts\pip.exe install -r requirements.txt --quiet 2>&1 | Out-Null
        Write-Log "Python dependencies installed successfully" "SUCCESS"
    }
    catch {
        Write-Log "Failed to install Python dependencies: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Configure-Firewall {
    Write-Log "Configuring Windows Firewall rules"
    try {
        New-NetFirewallRule -DisplayName "LitterBox Web" -Direction Inbound -Protocol TCP -LocalPort $Script:Config.WebPort -Action Allow -ErrorAction Stop | Out-Null
        New-NetFirewallRule -DisplayName "LitterBox MCP" -Direction Inbound -Protocol TCP -LocalPort $Script:Config.MCPPort -Action Allow -ErrorAction Stop | Out-Null
        Write-Log "Firewall rules configured for ports $($Script:Config.WebPort) and $($Script:Config.MCPPort)" "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure firewall rules: $($_.Exception.Message)" "WARNING"
    }
}

function Create-StartupFiles {
    Write-Log "Creating startup scripts and shortcuts"
    
    # Create startup batch file
    $StartupScript = @"
@echo off
echo Starting LitterBox Malware Analysis Platform...
cd $($Script:Config.InstallDir)
call .\venv\Scripts\activate.bat
python litterbox.py --debug --ip 0.0.0.0
"@
    
    try {
        $StartupScript | Out-File -FilePath "$($Script:Config.InstallDir)\litterox.bat" -Encoding ASCII
        Write-Log "Startup script created successfully"
    }
    catch {
        Write-Log "Failed to create startup script: $($_.Exception.Message)" "ERROR"
        throw
    }

    # Create desktop shortcut
    Write-Log "Creating desktop shortcut..."
    try {
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\LitterBox.lnk")
        $Shortcut.TargetPath = "$($Script:Config.InstallDir)\litterox.bat"
        $Shortcut.WorkingDirectory = $Script:Config.InstallDir
        $Shortcut.IconLocation = "$($Script:Config.InstallDir)\app\static\favicon.ico"
        $Shortcut.Description = "LitterBox Malware Analysis Platform"
        $Shortcut.Save()

        # Set shortcut to run as administrator
        $bytes = [System.IO.File]::ReadAllBytes('C:\Users\Public\Desktop\LitterBox.lnk')
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes('C:\Users\Public\Desktop\LitterBox.lnk', $bytes)
        
        Write-Log "Desktop shortcut created with admin privileges" "SUCCESS"
    }
    catch {
        Write-Log "Failed to create desktop shortcut: $($_.Exception.Message)" "WARNING"
    }
}

function Setup-AutoStart {
    Write-Log "Configuring LitterBox auto-start with admin privileges"
    
    try {
        # Remove any existing registry entry
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LitterBox' -ErrorAction SilentlyContinue
        
        # Create scheduled task for startup with admin privileges
        $Action = New-ScheduledTaskAction -Execute "$($Script:Config.InstallDir)\litterox.bat"
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName "LitterBox" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Force | Out-Null
        Write-Log "Scheduled task configured with admin privileges" "SUCCESS"
    }
    catch {
        Write-Log "Failed to configure auto-start task: $($_.Exception.Message)" "WARNING"
        Write-Log "Falling back to registry method without admin privileges" "WARNING"
        try {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'LitterBox' -Value "$($Script:Config.InstallDir)\litterox.bat" -PropertyType String -Force | Out-Null
            Write-Log "Registry auto-start entry created (requires manual admin)" "SUCCESS"
        }
        catch {
            Write-Log "Failed to create registry auto-start entry: $($_.Exception.Message)" "ERROR"
        }
    }
}

function Start-LitterBox {
    Write-Log "Starting LitterBox platform..." "SUCCESS"
    
    Set-Location $Script:Config.InstallDir
    try {
        Start-Process -FilePath "$($Script:Config.InstallDir)\litterox.bat" -WindowStyle Normal
        
        Write-Log "LitterBox setup completed successfully!" "SUCCESS"
        Write-Log "Installation directory: $($Script:Config.InstallDir)" "SUCCESS"
        Write-Log "Web interface: http://localhost:$($Script:Config.WebPort)" "SUCCESS"
        Write-Log "MCP interface: http://localhost:$($Script:Config.MCPPort)" "SUCCESS"
        Write-Log "Desktop shortcut created" "SUCCESS"
        Write-Log "Windows Defender exclusions applied" "SUCCESS"
        Write-Log "LitterBox is now running!" "SUCCESS"
    }
    catch {
        Write-Log "Failed to start LitterBox: $($_.Exception.Message)" "ERROR"
    }
}


# Main execution flow
try {
    Write-Log "=== LitterBox Malware Analysis Platform Setup Started ===" "SUCCESS"
    Initialize-Environment
    Set-DefenderExclusions
    Install-Prerequisites
    Install-Chocolatey
    Install-Dependencies
    Prep-SandBox
    Install-LitterBox
    Configure-Firewall
    Create-StartupFiles
    Setup-AutoStart
    Start-LitterBox
    Write-Log "=== LitterBox Setup Completed Successfully ===" "SUCCESS"
}
catch {
    Write-Log "Setup failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Check log file: $($Script:Config.LogFile)" "ERROR"
    exit 1
}
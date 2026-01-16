#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NetWatcher Agent Installation Script for Windows

.DESCRIPTION
    Downloads, installs, and configures the NetWatcher Agent as a Windows Service.
    Supports both installation and uninstallation operations.

.PARAMETER Workspace
    Workspace ID

.PARAMETER Id
    Agent ID

.PARAMETER Pin
    Agent PIN (numeric value)

.PARAMETER ControllerHost
    Controller host without protocol (default: api.netwatcher.io)

.PARAMETER SSL
    Use SSL/HTTPS (default: true)

.PARAMETER InstallDir
    Installation directory (default: C:\Program Files\NetWatcher-Agent)

.PARAMETER Version
    Specific version to install (default: latest)

.PARAMETER Force
    Force reinstallation even if already installed

.PARAMETER NoStart
    Don't start the service after installation

.PARAMETER Uninstall
    Uninstall the agent instead of installing

.PARAMETER Update
    Update only the binary (keeps config and service)

.EXAMPLE
    .\install.ps1 -Workspace 1 -Id 42 -Pin "123456789"

.EXAMPLE
    .\install.ps1 -Workspace 1 -Id 42 -Pin "123456789" -ControllerHost "myserver.com" -SSL $true

.EXAMPLE
    .\install.ps1 -Update

.EXAMPLE
    .\install.ps1 -Update -Version "v20260114-abc123"

.EXAMPLE
    .\install.ps1 -Uninstall

.EXAMPLE
    .\install.ps1 -Uninstall -Force
#>

[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string]$Workspace,

    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [string]$Id,

    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [ValidatePattern('^[0-9]+$')]
    [string]$Pin,

    [Parameter(ParameterSetName = 'Install')]
    [string]$ControllerHost = "api.netwatcher.io",

    [Parameter(ParameterSetName = 'Install')]
    [bool]$SSL = $true,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Uninstall')]
    [string]$InstallDir = "C:\Program Files\NetWatcher-Agent",

    [Parameter(ParameterSetName = 'Install')]
    [string]$Version,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$NoStart,

    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = 'Update', Mandatory = $true)]
    [switch]$Update,

    [Parameter(ParameterSetName = 'Update')]
    [string]$UpdateVersion
)

# ============================================================================
# Configuration
# ============================================================================

$Script:GitHubRepo = "netwatcherio/agent"
$Script:ServiceName = "NetWatcherAgent"
$Script:ServiceDisplayName = "NetWatcher Agent"
$Script:BinaryName = "netwatcher-agent.exe"
$Script:ConfigFile = "config.conf"

# ============================================================================
# Logging Functions
# ============================================================================

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-SystemArchitecture {
    # Debug: Show what we're detecting
    $runtimeArch = $null
    try {
        $runtimeArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    }
    catch { }
    
    $envArch = $env:PROCESSOR_ARCHITECTURE
    Write-Info "Debug: RuntimeInfo=$runtimeArch, PROCESSOR_ARCHITECTURE=$envArch"
    
    # Try RuntimeInformation first
    if ($runtimeArch -eq "X64") { return "amd64" }
    if ($runtimeArch -eq "Arm64") { return "arm64" }
    if ($runtimeArch -eq "X86") { return "386" }
    
    # Fallback to environment variable (case-insensitive)
    if ($envArch -ieq "AMD64") { return "amd64" }
    if ($envArch -ieq "ARM64") { return "arm64" }
    if ($envArch -ieq "x86") { return "386" }
    if ($envArch -ieq "IA64") { return "amd64" }
    
    # Final fallback - check pointer size
    if ([IntPtr]::Size -eq 8) {
        if ($envArch -imatch "ARM") {
            return "arm64"
        }
        return "amd64"
    }
    elseif ([IntPtr]::Size -eq 4) {
        return "386"
    }
    
    Write-Error "Unsupported architecture: RuntimeInfo=$runtimeArch, ENV=$envArch"
    exit 1
}

function Get-LatestVersion {
    param([string]$Repo)
    
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "NetWatcher-Installer" }
        return $response.tag_name
    }
    catch {
        Write-Error "Failed to fetch latest version from GitHub: $_"
        exit 1
    }
}

function Get-ReleaseAssets {
    param(
        [string]$Repo,
        [string]$Version
    )
    
    $apiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Version"
    
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "NetWatcher-Installer" }
        return $response.assets
    }
    catch {
        Write-Error "Failed to fetch release assets for version $Version"
        exit 1
    }
}

function Find-MatchingAsset {
    param(
        [array]$Assets,
        [string]$Architecture
    )
    
    # Look for Windows assets matching our architecture
    $patterns = @(
        "windows.*$Architecture.*\.zip$",
        "windows.*$Architecture.*\.exe$",
        "win.*$Architecture.*\.zip$"
    )
    
    foreach ($pattern in $patterns) {
        $match = $Assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if ($match) {
            return $match
        }
    }
    
    # Fallback: look for any Windows asset
    $fallback = $Assets | Where-Object { $_.name -match "windows|win" -and $_.name -match $Architecture } | Select-Object -First 1
    if ($fallback) {
        return $fallback
    }
    
    return $null
}

function Test-ServiceExists {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Stop-AgentService {
    if (Test-ServiceExists -Name $Script:ServiceName) {
        $service = Get-Service -Name $Script:ServiceName
        if ($service.Status -eq 'Running') {
            Write-Info "Stopping $($Script:ServiceDisplayName) service..."
            Stop-Service -Name $Script:ServiceName -Force
            
            # Wait for service to stop
            $timeout = 30
            $elapsed = 0
            while ((Get-Service -Name $Script:ServiceName).Status -ne 'Stopped' -and $elapsed -lt $timeout) {
                Start-Sleep -Seconds 1
                $elapsed++
            }
            
            if ((Get-Service -Name $Script:ServiceName).Status -eq 'Stopped') {
                Write-Success "Service stopped"
            }
            else {
                Write-Warning "Service did not stop within $timeout seconds"
            }
        }
    }
}

# ============================================================================
# Firewall Configuration
# ============================================================================

function Configure-Firewall {
    param(
        [string]$AgentPath
    )
    
    Write-Info "Configuring Windows Firewall rules..."
    
    # Remove any existing rules first (to avoid duplicates)
    Remove-FirewallRules
    
    try {
        # Agent - allow all connections (program-based rule)
        New-NetFirewallRule -DisplayName "NetWatcher Agent" `
            -Program $AgentPath `
            -Action Allow `
            -Profile Any `
            -Description "Allows all network connections for NetWatcher Agent" `
            -ErrorAction Stop | Out-Null
        
        Write-Success "Firewall rule created for NetWatcher Agent"
    }
    catch {
        Write-Warning "Failed to create firewall rule for agent: $_"
    }
    
    # Add explicit ICMP rules for MTR/traceroute/ping functionality
    try {
        # ICMP Echo Request - Outbound (for ping/traceroute probes)
        New-NetFirewallRule -DisplayName "NetWatcher ICMP Echo Request Out" `
            -Protocol ICMPv4 `
            -IcmpType 8 `
            -Direction Outbound `
            -Action Allow `
            -Profile Any `
            -Description "Allows outbound ICMP Echo Request for MTR/traceroute" `
            -ErrorAction Stop | Out-Null
        
        Write-Success "Firewall rule created for ICMP Echo Request (outbound)"
    }
    catch {
        Write-Warning "Failed to create ICMP outbound rule: $_"
    }
    
    try {
        # ICMP Echo Reply - Inbound (for receiving ping responses)
        New-NetFirewallRule -DisplayName "NetWatcher ICMP Echo Reply In" `
            -Protocol ICMPv4 `
            -IcmpType 0 `
            -Direction Inbound `
            -Action Allow `
            -Profile Any `
            -Description "Allows inbound ICMP Echo Reply for MTR/traceroute" `
            -ErrorAction Stop | Out-Null
        
        Write-Success "Firewall rule created for ICMP Echo Reply (inbound)"
    }
    catch {
        Write-Warning "Failed to create ICMP inbound rule: $_"
    }
    
    try {
        # ICMP Time Exceeded - Inbound (for traceroute TTL responses)
        New-NetFirewallRule -DisplayName "NetWatcher ICMP Time Exceeded In" `
            -Protocol ICMPv4 `
            -IcmpType 11 `
            -Direction Inbound `
            -Action Allow `
            -Profile Any `
            -Description "Allows inbound ICMP Time Exceeded for traceroute" `
            -ErrorAction Stop | Out-Null
        
        Write-Success "Firewall rule created for ICMP Time Exceeded (inbound)"
    }
    catch {
        Write-Warning "Failed to create ICMP Time Exceeded rule: $_"
    }
    
    try {
        # ICMP Destination Unreachable - Inbound (for traceroute endpoint detection)
        New-NetFirewallRule -DisplayName "NetWatcher ICMP Dest Unreachable In" `
            -Protocol ICMPv4 `
            -IcmpType 3 `
            -Direction Inbound `
            -Action Allow `
            -Profile Any `
            -Description "Allows inbound ICMP Destination Unreachable for traceroute" `
            -ErrorAction Stop | Out-Null
        
        Write-Success "Firewall rule created for ICMP Destination Unreachable (inbound)"
    }
    catch {
        Write-Warning "Failed to create ICMP Dest Unreachable rule: $_"
    }
}

function Remove-FirewallRules {
    Write-Info "Removing NetWatcher firewall rules..."
    $existingRules = Get-NetFirewallRule -DisplayName "NetWatcher*" -ErrorAction SilentlyContinue
    if ($existingRules) {
        $existingRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Success "Firewall rules removed"
    }
}

# ============================================================================
# Installation Functions
# ============================================================================

function Install-Agent {
    Write-Host ""
    Write-Host "NetWatcher Agent Installation Script" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""

    # Check existing installation
    $binaryPath = Join-Path $InstallDir $Script:BinaryName
    if ((Test-Path $binaryPath) -and -not $Force) {
        Write-Warning "NetWatcher Agent is already installed at $InstallDir"
        Write-Info "Use -Force to reinstall"
        
        if (Test-ServiceExists -Name $Script:ServiceName) {
            $service = Get-Service -Name $Script:ServiceName
            Write-Info "Service status: $($service.Status)"
        }
        return
    }

    # Stop existing service if running
    Stop-AgentService

    # Detect architecture
    $arch = Get-SystemArchitecture
    Write-Info "Detected architecture: windows-$arch"

    # Get version
    if (-not $Version) {
        Write-Info "Fetching latest release information..."
        $Version = Get-LatestVersion -Repo $Script:GitHubRepo
    }
    Write-Info "Version: $Version"

    # Get release assets
    Write-Info "Fetching release assets..."
    $assets = Get-ReleaseAssets -Repo $Script:GitHubRepo -Version $Version
    
    if ($assets.Count -eq 0) {
        Write-Error "No assets found for version $Version"
        exit 1
    }

    # Find matching asset
    $asset = Find-MatchingAsset -Assets $assets -Architecture $arch
    
    if (-not $asset) {
        Write-Error "No suitable asset found for windows-$arch"
        Write-Info "Available assets:"
        $assets | ForEach-Object { Write-Host "  - $($_.name)" }
        exit 1
    }

    Write-Info "Selected asset: $($asset.name)"

    # Create installation directory
    Write-Info "Creating installation directory: $InstallDir"
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download the release (use .zip extension for Expand-Archive compatibility)
    $tempFile = Join-Path $env:TEMP "netwatcher-download.zip"
    $downloadUrl = $asset.browser_download_url
    
    Write-Info "Downloading from: $downloadUrl"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
    }
    catch {
        Write-Error "Failed to download: $_"
        exit 1
    }

    # Extract or copy based on file type
    if ($asset.name -match '\.zip$') {
        Write-Info "Extracting zip archive..."
        Expand-Archive -Path $tempFile -DestinationPath $InstallDir -Force
        
        # Find and rename the binary if needed
        $extractedExe = Get-ChildItem -Path $InstallDir -Filter "*.exe" -Recurse | Select-Object -First 1
        if ($extractedExe -and $extractedExe.Name -ne $Script:BinaryName) {
            $targetPath = Join-Path $InstallDir $Script:BinaryName
            Move-Item -Path $extractedExe.FullName -Destination $targetPath -Force
        }
    }
    else {
        Write-Info "Installing binary..."
        Copy-Item -Path $tempFile -Destination $binaryPath -Force
    }

    # Clean up temp file
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

    # Verify binary exists
    if (-not (Test-Path $binaryPath)) {
        Write-Error "Binary not found after installation: $binaryPath"
        Write-Info "Contents of $InstallDir :"
        Get-ChildItem -Path $InstallDir | ForEach-Object { Write-Host "  - $($_.Name)" }
        exit 1
    }

    Write-Success "Binary installed to: $binaryPath"

    # Remove stale auth file to force re-authentication with new PIN
    $authFile = Join-Path $InstallDir "agent_auth.json"
    if (Test-Path $authFile) {
        Write-Info "Removing stale auth file to force re-authentication..."
        Remove-Item -Path $authFile -Force -ErrorAction SilentlyContinue
    }

    # Create configuration file
    $configPath = Join-Path $InstallDir $Script:ConfigFile
    Write-Info "Creating configuration file: $configPath"

    $sslValue = if ($SSL) { "true" } else { "false" }
    $configContent = @"
# NetWatcher Agent Configuration
CONTROLLER_HOST=$ControllerHost
CONTROLLER_SSL=$sslValue
WORKSPACE_ID=$Workspace
AGENT_ID=$Id
AGENT_PIN=$Pin
"@

    Set-Content -Path $configPath -Value $configContent -Force
    Write-Success "Configuration file created"

    # Create Windows Service
    Write-Info "Creating Windows Service: $($Script:ServiceDisplayName)"
    
    # Remove existing service if present
    if (Test-ServiceExists -Name $Script:ServiceName) {
        Write-Info "Removing existing service..."
        Stop-Service -Name $Script:ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        sc.exe delete $Script:ServiceName | Out-Null
        
        # Wait for service to be fully removed (can take time if handles are open)
        $maxWait = 30
        $waited = 0
        while ((Test-ServiceExists -Name $Script:ServiceName) -and $waited -lt $maxWait) {
            Start-Sleep -Seconds 1
            $waited++
        }
        if ($waited -ge $maxWait) {
            Write-Warning "Service removal is taking longer than expected. You may need to close the Services panel or reboot."
        }
    }

    # Create the service using PowerShell's New-Service cmdlet (avoids sc.exe quoting issues)
    $serviceBinPath = "`"$binaryPath`" --config `"$configPath`""
    
    Write-Info "Creating service with binPath: $serviceBinPath"
    
    # Retry loop to handle "marked for deletion" race condition
    $maxRetries = 5
    $retryDelay = 2
    $created = $false
    
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            New-Service -Name $Script:ServiceName `
                -BinaryPathName $serviceBinPath `
                -DisplayName $Script:ServiceDisplayName `
                -StartupType Automatic `
                -Description "NetWatcher Agent monitors network and voice quality" `
                -ErrorAction Stop
            Write-Success "Windows Service created"
            $created = $true
            break
        }
        catch {
            if ($_.Exception.Message -match "marked for deletion" -and $i -lt $maxRetries) {
                Write-Warning "Service still pending deletion, retrying in $retryDelay seconds... (attempt $i/$maxRetries)"
                Start-Sleep -Seconds $retryDelay
                $retryDelay = $retryDelay * 2  # Exponential backoff
            }
            else {
                Write-Error "Failed to create service: $_"
                exit 1
            }
        }
    }
    
    if (-not $created) {
        Write-Error "Failed to create service after $maxRetries attempts. Try closing the Services panel and running again, or reboot."
        exit 1
    }

    # Configure service recovery options (restart on failure)
    sc.exe failure $Script:ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    # Configure Windows Firewall rules
    Configure-Firewall -AgentPath $binaryPath

    # Start the service
    if (-not $NoStart) {
        Write-Info "Starting $($Script:ServiceDisplayName) service..."
        
        try {
            Start-Service -Name $Script:ServiceName
            Start-Sleep -Seconds 2
            
            $service = Get-Service -Name $Script:ServiceName
            if ($service.Status -eq 'Running') {
                Write-Success "Service is running"
            }
            else {
                Write-Warning "Service status: $($service.Status)"
                Write-Info "Check logs with: Get-EventLog -LogName Application -Source $Script:ServiceName"
            }
        }
        catch {
            Write-Error "Failed to start service: $_"
            Write-Info "You can start it manually with: Start-Service -Name $Script:ServiceName"
        }
    }
    else {
        Write-Info "Skipping service startup (--NoStart specified)"
    }

    # Show summary
    Show-InstallSummary
}

function Show-InstallSummary {
    Write-Host ""
    Write-Success "NetWatcher Agent installation completed!"
    Write-Host ""
    Write-Info "Installation Details:"
    Write-Host "  - Binary: $(Join-Path $InstallDir $Script:BinaryName)"
    Write-Host "  - Config: $(Join-Path $InstallDir $Script:ConfigFile)"
    Write-Host "  - Service: $Script:ServiceName"
    Write-Host ""
    Write-Info "Useful Commands:"
    Write-Host "  - Check status: Get-Service -Name $Script:ServiceName"
    Write-Host "  - View logs: Get-EventLog -LogName Application -Source $Script:ServiceName -Newest 20"
    Write-Host "  - Restart: Restart-Service -Name $Script:ServiceName"
    Write-Host "  - Stop: Stop-Service -Name $Script:ServiceName"
    Write-Host ""
    Write-Info "The NetWatcher Agent is now running and will start automatically on boot."
}

# ============================================================================
# Uninstallation Functions
# ============================================================================

function Uninstall-Agent {
    Write-Host ""
    Write-Host "NetWatcher Agent Uninstallation" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""

    $hasService = Test-ServiceExists -Name $Script:ServiceName
    $hasFiles = Test-Path $InstallDir

    if (-not $hasService -and -not $hasFiles) {
        Write-Warning "NetWatcher Agent does not appear to be installed"
        return
    }

    # Confirm uninstallation
    if (-not $Force) {
        Write-Host ""
        Write-Warning "This will completely remove NetWatcher Agent from your system."
        Write-Host "The following will be removed:" -ForegroundColor Yellow
        if ($hasService) {
            Write-Host "  - Windows Service: $Script:ServiceName"
        }
        if ($hasFiles) {
            Write-Host "  - Installation directory: $InstallDir"
        }
        Write-Host ""
        
        $confirm = Read-Host "Are you sure you want to continue? (y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Info "Uninstallation cancelled"
            return
        }
    }

    # Stop the service
    if ($hasService) {
        Stop-AgentService
        
        # Remove the service
        Write-Info "Removing Windows Service..."
        sc.exe delete $Script:ServiceName | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Windows Service removed"
        }
        else {
            Write-Warning "Could not remove service (it may require a reboot)"
        }
    }

    # Remove firewall rules
    Remove-FirewallRules

    # Remove installation directory
    if ($hasFiles) {
        Write-Info "Removing installation directory: $InstallDir"
        
        try {
            Remove-Item -Path $InstallDir -Recurse -Force
            Write-Success "Installation directory removed"
        }
        catch {
            Write-Error "Failed to remove installation directory: $_"
            Write-Info "You may need to remove it manually after a reboot"
        }
    }

    Write-Host ""
    Write-Success "NetWatcher Agent has been uninstalled"
}

# ============================================================================
# Update Function
# ============================================================================

function Update-Agent {
    Write-Host ""
    Write-Host "NetWatcher Agent Binary Update" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""

    $binaryPath = Join-Path $InstallDir $Script:BinaryName

    # Check if agent is installed
    if (-not (Test-Path $InstallDir)) {
        Write-Error "NetWatcher Agent is not installed at $InstallDir"
        Write-Info "Use the full installation command to install first."
        exit 1
    }

    if (-not (Test-Path $binaryPath)) {
        Write-Error "Binary not found at $binaryPath"
        Write-Info "Use the full installation command to install first."
        exit 1
    }

    # Get current version
    $currentVersion = "unknown"
    try {
        $currentVersion = & $binaryPath --version 2>$null
    }
    catch { }
    Write-Info "Current version: $currentVersion"

    # Detect architecture
    $arch = Get-SystemArchitecture
    Write-Info "Detected architecture: windows-$arch"

    # Get version to install
    $versionToInstall = $UpdateVersion
    if (-not $versionToInstall) {
        Write-Info "Fetching latest release information..."
        $versionToInstall = Get-LatestVersion -Repo $Script:GitHubRepo
    }
    Write-Info "Updating to version: $versionToInstall"

    # Stop service if running
    Stop-AgentService

    # Backup current binary
    $backupPath = "$binaryPath.backup"
    Write-Info "Backing up current binary to: $backupPath"
    Copy-Item -Path $binaryPath -Destination $backupPath -Force

    # Get release assets
    Write-Info "Fetching release assets..."
    $assets = Get-ReleaseAssets -Repo $Script:GitHubRepo -Version $versionToInstall
    
    if ($assets.Count -eq 0) {
        Write-Error "No assets found for version $versionToInstall"
        exit 1
    }

    # Find matching asset
    $asset = Find-MatchingAsset -Assets $assets -Architecture $arch
    
    if (-not $asset) {
        Write-Error "No suitable asset found for windows-$arch"
        exit 1
    }

    Write-Info "Selected asset: $($asset.name)"

    # Download the release
    $tempFile = Join-Path $env:TEMP "netwatcher-update.zip"
    $downloadUrl = $asset.browser_download_url
    
    Write-Info "Downloading from: $downloadUrl"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
    }
    catch {
        Write-Error "Failed to download: $_"
        Write-Info "Rolling back..."
        Move-Item -Path $backupPath -Destination $binaryPath -Force
        exit 1
    }

    # Extract or copy based on file type
    if ($asset.name -match '\.zip$') {
        Write-Info "Extracting zip archive..."
        $tempExtract = Join-Path $env:TEMP "netwatcher-extract"
        if (Test-Path $tempExtract) { Remove-Item -Path $tempExtract -Recurse -Force }
        Expand-Archive -Path $tempFile -DestinationPath $tempExtract -Force
        
        # Find the binary
        $extractedExe = Get-ChildItem -Path $tempExtract -Filter "*.exe" -Recurse | Select-Object -First 1
        if ($extractedExe) {
            Copy-Item -Path $extractedExe.FullName -Destination $binaryPath -Force
        }
        Remove-Item -Path $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Copy-Item -Path $tempFile -Destination $binaryPath -Force
    }

    # Clean up temp file
    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue

    # Verify new binary works
    $newVersion = "unknown"
    try {
        $newVersion = & $binaryPath --version 2>$null
        Write-Success "New version installed: $newVersion"
        
        # Remove backup
        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "New binary is not working. Rolling back..."
        Move-Item -Path $backupPath -Destination $binaryPath -Force
        exit 1
    }

    # Ensure firewall rules are configured
    Configure-Firewall -AgentPath $binaryPath

    # Start service (or create if missing)
    if (Test-ServiceExists -Name $Script:ServiceName) {
        Write-Info "Starting $($Script:ServiceDisplayName) service..."
        Start-Service -Name $Script:ServiceName
        Start-Sleep -Seconds 2
        
        $service = Get-Service -Name $Script:ServiceName
        if ($service.Status -eq 'Running') {
            Write-Success "Service restarted successfully"
        }
        else {
            Write-Warning "Service status: $($service.Status)"
            Write-Info "Check logs with: Get-EventLog -LogName Application -Source $Script:ServiceName"
        }
    }
    else {
        # Service doesn't exist - create it
        Write-Warning "Service not found, creating it..."
        try {
            New-Service -Name $Script:ServiceName `
                -BinaryPathName "`"$binaryPath`" --config `"$(Join-Path $InstallDir 'config.conf')`"" `
                -DisplayName $Script:ServiceDisplayName `
                -Description "NetWatcher monitoring agent" `
                -StartupType Automatic `
                -ErrorAction Stop
            
            Write-Success "Service created"
            
            # Configure restart on failure
            sc.exe failure $Script:ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
            
            # Start the service
            Start-Service -Name $Script:ServiceName
            Start-Sleep -Seconds 2
            
            $service = Get-Service -Name $Script:ServiceName
            if ($service.Status -eq 'Running') {
                Write-Success "Service started successfully"
            }
            else {
                Write-Warning "Service status: $($service.Status)"
            }
        }
        catch {
            Write-Error "Failed to create service: $_"
            Write-Info "You can run the agent manually or reinstall with: .\install.ps1 -Force ..."
        }
    }

    Write-Host ""
    Write-Success "NetWatcher Agent binary updated successfully!"
    Write-Host "  Old version: $currentVersion"
    Write-Host "  New version: $newVersion"
}

# ============================================================================
# Main Execution
# ============================================================================

# Ensure we're running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    Write-Info "Please right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

# Execute based on parameter set
if ($Uninstall) {
    Uninstall-Agent
}
elseif ($Update) {
    Update-Agent
}
else {
    Install-Agent
}

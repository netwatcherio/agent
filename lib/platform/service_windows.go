//go:build windows

// Package platform provides Windows service integration.
package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

// Windows process creation flags for detaching child processes
const (
	CREATE_NEW_PROCESS_GROUP = 0x00000200
	DETACHED_PROCESS         = 0x00000008
	CREATE_NO_WINDOW         = 0x08000000
)

// Package-level restart signaling
var (
	restartMu        sync.Mutex
	restartRequested bool
	restartChan      = make(chan struct{}, 1)
)

// AgentRunner is the function signature for the main agent logic.
type AgentRunner func(ctx context.Context) error

// windowsService wraps the agent runner to implement svc.Handler.
type windowsService struct {
	runner AgentRunner
}

// Execute implements svc.Handler and is called by the Windows SCM.
func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	// Notify SCM that we're starting
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Create context for the agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the agent in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.runner(ctx)
	}()

	// Report running IMMEDIATELY - don't wait for agent initialization
	// The agent will continue initializing in the background
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}

	// Main service loop - handle SCM commands and restart requests
	for {
		select {
		case err := <-errCh:
			// Agent exited on its own
			changes <- svc.Status{State: svc.StopPending}
			if err != nil {
				return true, 1
			}
			return false, 0

		case <-restartChan:
			// Restart requested (e.g., from auto-updater)
			log.Info("Service restart requested, initiating graceful restart...")
			changes <- svc.Status{State: svc.StopPending}

			// Spawn a detached process to restart the service after we exit
			if err := spawnRestartProcess(); err != nil {
				log.WithError(err).Error("Failed to spawn restart process")
			}

			// Cancel context to stop the agent
			cancel()

			// Wait for agent to finish
			<-errCh
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// SCM wants our status - respond with current status
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// Graceful shutdown requested
				changes <- svc.Status{State: svc.StopPending}
				cancel()

				// Wait for agent to finish
				<-errCh
				return false, 0

			default:
				// Ignore unknown commands
			}
		}
	}
}

// IsRunningAsService detects if the process was started by the Windows SCM.
func IsRunningAsService() bool {
	// Primary detection: use the official Windows API
	isService, err := svc.IsWindowsService()
	if err == nil {
		return isService
	}

	// Fallback: check if we have an interactive session
	// Services typically don't have a console attached
	return !isInteractiveSession()
}

// RunService runs the agent as a Windows service.
// This function blocks until the service is stopped.
func RunService(name string, runner AgentRunner) error {
	// Use debug.Run for better error messages during development
	// In production, this behaves the same as svc.Run
	return svc.Run(name, &windowsService{runner: runner})
}

// DebugRunService runs the service in debug mode (for testing in console)
func DebugRunService(name string, runner AgentRunner) error {
	return debug.Run(name, &windowsService{runner: runner})
}

// isInteractiveSession checks if stdin is attached to a terminal.
func isInteractiveSession() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ServiceError creates a formatted service error for logging
func ServiceError(format string, args ...interface{}) error {
	return fmt.Errorf("service: "+format, args...)
}

// IsDebugMode checks if running in debug/development mode
func IsDebugMode() bool {
	// Check for common debug indicators
	for _, arg := range os.Args {
		if strings.ToLower(arg) == "--debug" || strings.ToLower(arg) == "-debug" {
			return true
		}
	}
	return os.Getenv("NETWATCHER_DEBUG") != ""
}

// RequestServiceRestart signals the service handler to initiate a restart.
// This is used by the auto-updater to trigger a proper Windows service restart.
// Returns true if a restart was successfully requested, false if not running as a service.
func RequestServiceRestart() bool {
	restartMu.Lock()
	defer restartMu.Unlock()

	if restartRequested {
		// Already requested
		return true
	}

	// Check if we're running as a service
	if !IsRunningAsService() {
		log.Info("Not running as service, cannot request service restart")
		return false
	}

	restartRequested = true

	// Non-blocking send to restart channel
	select {
	case restartChan <- struct{}{}:
		log.Info("Service restart request sent")
	default:
		// Channel already has a pending restart request
		log.Debug("Service restart already pending")
	}

	return true
}

// spawnRestartProcess creates a detached process that will restart the service
// after the current process exits. This ensures the SCM sees a clean shutdown
// before the service is restarted.
func spawnRestartProcess() error {
	// Get the path to the executable directory for the restart script
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Ensure .tmp directory exists
	tmpDir := filepath.Join(filepath.Dir(exePath), ".tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create tmp directory: %w", err)
	}

	// Create a PowerShell script for more reliable restart with retries and logging
	scriptPath := filepath.Join(tmpDir, "restart_service.ps1")
	logPath := filepath.Join(tmpDir, "restart_service.log")

	// PowerShell script content:
	// - Logs all actions for debugging
	// - Waits for service to fully stop
	// - Retries start up to 5 times with increasing delays
	// - Cleans up the script after successful start
	scriptContent := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
$ServiceName = 'NetWatcherAgent'
$LogFile = '%s'
$ExePath = '%s'
$MaxRetries = 5
$BaseDelay = 3

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

function Test-FileLocked {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $file = [System.IO.File]::Open($Path, 'Open', 'Read', 'None')
        $file.Close()
        return $false
    } catch {
        return $true
    }
}

Write-Log "Restart script started"
Write-Log "Executable path: $ExePath"

# Wait for service to fully stop
$timeout = 30
$elapsed = 0
while ($elapsed -lt $timeout) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Log "Service not found, may have been uninstalled"
        exit 0
    }
    if ($svc.Status -eq 'Stopped') {
        Write-Log "Service is stopped"
        break
    }
    Write-Log "Waiting for service to stop... (Status: $($svc.Status))"
    Start-Sleep -Seconds 1
    $elapsed++
}

if ($elapsed -ge $timeout) {
    Write-Log "WARNING: Timeout waiting for service to stop"
    Write-Log "Attempting to force stop service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

# Wait for file handles to be released
Write-Log "Waiting for executable file lock to be released..."
$lockTimeout = 30
$lockElapsed = 0
while ($lockElapsed -lt $lockTimeout) {
    if (-not (Test-FileLocked -Path $ExePath)) {
        Write-Log "Executable is no longer locked"
        break
    }
    Write-Log "Executable still locked, waiting... ($lockElapsed sec)"
    Start-Sleep -Seconds 1
    $lockElapsed++
}

if ($lockElapsed -ge $lockTimeout) {
    Write-Log "WARNING: Executable may still be locked after $lockTimeout seconds"
}

# Additional buffer to ensure clean state
Start-Sleep -Seconds 2

# Retry loop to start the service
for ($i = 1; $i -le $MaxRetries; $i++) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Log "Attempt $i of $MaxRetries to start service (current status: $($svc.Status))"
    
    # If stuck in StartPending, wait for it
    if ($svc.Status -eq 'StartPending') {
        Write-Log "Service is in StartPending, waiting..."
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') {
            Write-Log "SUCCESS: Service is now running"
            Remove-Item -Path $PSCommandPath -Force -ErrorAction SilentlyContinue
            exit 0
        }
    }
    
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') {
            Write-Log "SUCCESS: Service is now running"
            Remove-Item -Path $PSCommandPath -Force -ErrorAction SilentlyContinue
            exit 0
        } else {
            Write-Log "Service status after start attempt: $($svc.Status)"
        }
    }
    catch {
        Write-Log "ERROR on attempt $i - $_"
    }
    
    if ($i -lt $MaxRetries) {
        $delay = $BaseDelay * $i
        Write-Log "Waiting $delay seconds before retry..."
        Start-Sleep -Seconds $delay
    }
}

Write-Log "FAILED: Could not start service after $MaxRetries attempts"
Write-Log "Manual intervention required: Start-Service -Name $ServiceName"
exit 1
`, strings.ReplaceAll(logPath, `\`, `\\`), strings.ReplaceAll(exePath, `\`, `\\`))

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write restart script: %w", err)
	}

	log.WithField("script", scriptPath).Info("Spawning restart process")

	// Run PowerShell in a completely detached process
	// -WindowStyle Hidden prevents any visible window
	// -ExecutionPolicy Bypass ensures the script runs even with restricted policies
	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath)

	// CRITICAL: Use Windows process creation flags to fully detach the child process
	// Without these flags, the PowerShell process is killed when the parent service stops
	// - CREATE_NEW_PROCESS_GROUP: Makes the child independent from parent's console group
	// - DETACHED_PROCESS: The child has no console and is detached from the parent
	// - CREATE_NO_WINDOW: Prevents any window from appearing (redundant with -WindowStyle Hidden but safer)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW,
	}

	// Ensure no handle inheritance
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		// Clean up script if we failed to start
		os.Remove(scriptPath)
		return fmt.Errorf("failed to start restart process: %w", err)
	}

	// Don't wait for the process - it will run after we exit
	log.Info("Restart process spawned successfully")
	return nil
}

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

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
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

	// Create a temporary batch script that waits briefly, then restarts the service
	// The script deletes itself after execution
	scriptPath := filepath.Join(filepath.Dir(exePath), ".tmp", "restart_service.bat")

	// Ensure .tmp directory exists
	tmpDir := filepath.Dir(scriptPath)
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create tmp directory: %w", err)
	}

	// Batch script content:
	// - Wait 3 seconds (using ping as a delay mechanism)
	// - Start the service
	// - Delete the script file
	scriptContent := `@echo off
ping -n 4 127.0.0.1 > nul
net start NetWatcherAgent
del "%~f0"
`

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write restart script: %w", err)
	}

	log.WithField("script", scriptPath).Info("Spawning restart process")

	// Run the script in a completely detached process
	// Using cmd.exe /c start /b to run in background without a window
	cmd := exec.Command("cmd.exe", "/c", "start", "/b", "", scriptPath)

	// Detach from parent process
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

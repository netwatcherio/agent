//go:build windows

// Package platform provides Windows service integration.
package platform

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
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

	// Main service loop - handle SCM commands
	for {
		select {
		case err := <-errCh:
			// Agent exited on its own
			changes <- svc.Status{State: svc.StopPending}
			if err != nil {
				return true, 1
			}
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

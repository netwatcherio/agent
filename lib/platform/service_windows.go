//go:build windows

// Package platform provides Windows service integration.
package platform

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

// Windows service name
const serviceName = "NetWatcherAgent"

// AgentRunner is the function signature for the main agent logic.
type AgentRunner func(ctx context.Context) error

// windowsService wraps the agent runner to implement svc.Handler.
type windowsService struct {
	runner AgentRunner
	ctx    context.Context
	cancel context.CancelFunc
}

// Execute implements svc.Handler and is called by the Windows SCM.
func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	// Notify SCM that we're starting
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Create context for the agent
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Start the agent in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.runner(s.ctx)
	}()

	// Small delay to let the agent initialize
	time.Sleep(100 * time.Millisecond)

	// We're now running
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}

	// Main service loop
	for {
		select {
		case err := <-errCh:
			// Agent exited
			if err != nil {
				// Return non-zero exit code on error
				changes <- svc.Status{State: svc.StopPending}
				return true, 1
			}
			changes <- svc.Status{State: svc.StopPending}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// SCM wants our status
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// Graceful shutdown
				changes <- svc.Status{State: svc.StopPending}
				s.cancel()

				// Wait for agent to finish (with timeout)
				select {
				case <-errCh:
				case <-time.After(30 * time.Second):
				}

				return false, 0

			default:
				// Ignore unknown commands
			}
		}
	}
}

// IsRunningAsService detects if the process was started by the Windows SCM.
func IsRunningAsService() bool {
	// The recommended way: check if we're running interactively
	isInteractive, err := svc.IsWindowsService()
	if err != nil {
		// If detection fails, assume interactive
		return false
	}
	return isInteractive
}

// RunService runs the agent as a Windows service.
// This blocks until the service is stopped.
func RunService(name string, runner AgentRunner) error {
	return svc.Run(name, &windowsService{runner: runner})
}

// isInteractiveSession checks if stdin is attached to a terminal.
// Fallback detection method.
func isInteractiveSession() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

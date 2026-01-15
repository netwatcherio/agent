//go:build !windows

// Package platform provides Unix stubs for service functions.
package platform

import (
	"context"
)

// AgentRunner is the function signature for the main agent logic.
type AgentRunner func(ctx context.Context) error

// IsRunningAsService always returns false on non-Windows platforms.
// Unix systems use systemd, launchd, etc. which don't require special handling.
func IsRunningAsService() bool {
	return false
}

// RunService on Unix simply runs the agent directly.
// Unix init systems (systemd, launchd) work with normal processes.
func RunService(name string, runner AgentRunner) error {
	// On Unix, we don't need special service handling.
	// Just run the agent directly with a background context.
	return runner(context.Background())
}

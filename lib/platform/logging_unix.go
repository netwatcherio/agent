//go:build !windows

// Package platform provides platform-specific integrations.
package platform

// SetupServiceLogging is a no-op on non-Windows platforms.
// Unix systems typically use syslog or systemd journal which work with stdout.
func SetupServiceLogging() (cleanup func(), err error) {
	// No-op: Unix platforms use stdout which is captured by syslog/journal
	return func() {}, nil
}

// LogEvent is a no-op on non-Windows platforms.
func LogEvent(eventType uint32, message string) {
	// No-op: Use standard logging on non-Windows
}

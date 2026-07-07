//go:build windows

// Package platform provides Windows-specific platform integrations.
package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Windows-specific constants
var (
	// EventLogSource is the Windows Event Log source name
	EventLogSource = "NetWatcherAgent"
)

// eventLogWriter wraps the Windows event log for use with logrus. Routes each
// log line to the appropriate event severity based on logrus level so anything
// visible in the log file is also visible in Event Viewer.
type eventLogWriter struct {
	elog *eventlog.Log
}

func (w *eventLogWriter) Write(p []byte) (n int, err error) {
	if w.elog == nil {
		return len(p), nil
	}
	msg := strings.TrimRight(string(p), "\r\n")
	// Route by level — check the structured fields first (logrus prefixes the
	// entry with `level=error` etc.), fall back to Error for unknown levels.
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "level=fatal") || strings.Contains(lower, "level=panic"):
		w.elog.Error(1, msg)
	case strings.Contains(lower, "level=error"):
		w.elog.Error(1, msg)
	case strings.Contains(lower, "level=warning") || strings.Contains(lower, "level=warn"):
		w.elog.Warning(1, msg)
	default:
		w.elog.Info(1, msg)
	}
	return len(p), nil
}

// SetupServiceLogging configures logging for Windows service mode.
// It sets up:
// 1. Rotating file logging beside the executable
// 2. Windows Event Log integration (optional, for critical errors)
//
// Configuration via environment variables:
//   - LOG_MAX_SIZE_MB: Maximum log file size in megabytes (default: 10)
//   - LOG_MAX_BACKUPS: Number of backup files to keep (default: 1)
//
// Returns a cleanup function that should be called on shutdown.
func SetupServiceLogging() (cleanup func(), err error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Log directly beside the executable for easy visibility
	logDir := filepath.Dir(exePath)
	cfg := GetLogConfig()

	// Set up rotating file writer
	fileWriter, err := NewRotatingFileWriter(logDir, LogFileName, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup file logging: %w", err)
	}

	// Try to set up Windows Event Log (non-fatal if it fails).
	// If we can open it, also route logrus output to it — this is the
	// single source of truth operators have when the log file is empty,
	// rotated, or inaccessible. Severity is mapped from logrus level.
	var elog *eventlog.Log
	elog, err = eventlog.Open(EventLogSource)
	if err != nil {
		err = eventlog.InstallAsEventCreate(EventLogSource, eventlog.Error|eventlog.Warning|eventlog.Info)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to install event log source (requires admin): %v\n", err)
		} else {
			elog, _ = eventlog.Open(EventLogSource)
		}
	}
	var elogWriter *eventLogWriter
	if elog != nil {
		elogWriter = &eventLogWriter{elog: elog}
	}

	// Configure logrus
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	// Multi-writer: file + event log. Stdout is intentionally NOT included on
	// Windows because services have no console and writing to stdout can fail
	// or hang; the file + event log is the canonical pair for headless servers.
	writerList := []io.Writer{fileWriter}
	if elogWriter != nil {
		writerList = append(writerList, elogWriter)
	}
	log.SetOutput(io.MultiWriter(writerList...))
	log.SetLevel(log.InfoLevel)

	log.Infof("Logging initialized - dir: %s, max_size: %dMB, backups: %d, eventlog=%v",
		logDir, cfg.MaxSize/(1024*1024), cfg.MaxBackups, elogWriter != nil)
	if elog != nil {
		elog.Info(1, "NetWatcher Agent service started")
	}

	cleanup = func() {
		fileWriter.Close()
		if elog != nil {
			elog.Close()
		}
	}

	return cleanup, nil
}

// SetupEventLogSource ensures the NetWatcherAgent Event Log source is
// registered and writes an immediate "service starting" event. Safe to call
// BEFORE logrus is configured — this is the only logging path guaranteed to
// work even if logrus setup fails or the agent panics during init.
//
// Tries to open the existing source first; if that fails, attempts to
// install it (requires admin — LocalSystem has this). On success, an
// immediate "service starting" event is written so operators can see in
// Event Viewer that the new binary reached main() at all.
//
// Returns true if the source is installed and the heartbeat was written.
// Subsequent LogEvent calls will reopen the source on demand.
func SetupEventLogSource() bool {
	elog, err := eventlog.Open(EventLogSource)
	if err != nil {
		if installErr := eventlog.InstallAsEventCreate(EventLogSource, eventlog.Error|eventlog.Warning|eventlog.Info); installErr != nil {
			fmt.Fprintf(os.Stderr, "SetupEventLogSource: InstallAsEventCreate failed: %v (open err: %v)\n", installErr, err)
			return false
		}
		elog, err = eventlog.Open(EventLogSource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SetupEventLogSource: re-open after install failed: %v\n", err)
			return false
		}
	}
	// Write a heartbeat event so operators can confirm the new binary is
	// reaching main() at all. If they see THIS in Event Viewer, the binary
	// launched successfully even if subsequent setup fails.
	_ = elog.Info(1, fmt.Sprintf("NetWatcher Agent service starting (pid=%d, version=%s)", os.Getpid(), versionString))
	_ = elog.Close()
	return true
}

// versionString is set via SetVersionString from main() so the heartbeat
// event reflects the actual build version. Default is "unknown" if main()
// never sets it (defensive — keeps logging_windows.go from depending on the
// main package).
var versionString = "unknown"

// SetVersionString allows main() to inject the build-time VERSION before
// any event-log writes happen.
func SetVersionString(v string) {
	if v != "" {
		versionString = v
	}
}

// LogEvent writes a message to the Windows Event Log.
// LogEvent writes a message to the Windows Event Log.
func LogEvent(eventType uint32, message string) {
	elog, err := eventlog.Open(EventLogSource)
	if err != nil {
		return
	}
	defer elog.Close()

	switch eventType {
	case eventlog.Error:
		elog.Error(1, message)
	case eventlog.Warning:
		elog.Warning(1, message)
	default:
		elog.Info(1, message)
	}
}

//go:build windows

// Package platform provides Windows-specific platform integrations.
package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Windows-specific constants
var (
	// EventLogSource is the Windows Event Log source name
	EventLogSource = "NetWatcherAgent"
)

// eventLogWriter wraps the Windows event log for use with logrus
type eventLogWriter struct {
	elog *eventlog.Log
}

func (w *eventLogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	err = w.elog.Info(1, msg)
	return len(p), err
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

	// Create multi-writer with file and stdout
	var writers []io.Writer
	writers = append(writers, fileWriter)
	writers = append(writers, os.Stdout)

	// Try to set up Windows Event Log (non-fatal if it fails)
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

	// Configure logrus
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	log.SetOutput(io.MultiWriter(writers...))
	log.SetLevel(log.InfoLevel)

	log.Infof("Logging initialized - dir: %s, max_size: %dMB, backups: %d",
		logDir, cfg.MaxSize/(1024*1024), cfg.MaxBackups)
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

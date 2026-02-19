//go:build !windows

// Package platform provides Unix/Linux/macOS platform integrations.
package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// SetupServiceLogging configures file logging on Unix platforms.
// Writes a rotating log file beside the executable, matching the Windows behavior.
// stdout is also kept so systemd journal / launchd still captures output.
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

	// Multi-writer: file + stdout (stdout is captured by systemd journal / launchd)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	log.SetOutput(io.MultiWriter(fileWriter, os.Stdout))
	log.SetLevel(log.InfoLevel)

	log.Infof("Logging initialized - dir: %s, max_size: %dMB, backups: %d",
		logDir, cfg.MaxSize/(1024*1024), cfg.MaxBackups)

	cleanup = func() {
		fileWriter.Close()
	}

	return cleanup, nil
}

// LogEvent is a no-op on non-Windows platforms.
func LogEvent(eventType uint32, message string) {
	// No-op: Use standard logging on non-Windows
}

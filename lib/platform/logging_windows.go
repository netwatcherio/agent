//go:build windows

// Package platform provides Windows-specific platform integrations.
package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Default logging configuration (can be overridden via environment variables)
var (
	// LogFileName is the base name for log files
	LogFileName = "netwatcher-agent.log"
	// DefaultMaxLogSize is the maximum size of a log file before rotation (10MB)
	DefaultMaxLogSize int64 = 10 * 1024 * 1024
	// DefaultMaxLogBackups is the number of rotated logs to keep (1 = keep only .log.1)
	DefaultMaxLogBackups = 1
	// EventLogSource is the Windows Event Log source name
	EventLogSource = "NetWatcherAgent"
)

// LogConfig holds the logging configuration
type LogConfig struct {
	MaxSize    int64 // Max size in bytes before rotation
	MaxBackups int   // Number of backup files to keep
}

// getLogConfig reads logging configuration from environment variables
// Environment variables:
//   - LOG_MAX_SIZE_MB: Maximum log file size in megabytes (default: 10)
//   - LOG_MAX_BACKUPS: Number of backup files to keep (default: 1)
func getLogConfig() LogConfig {
	cfg := LogConfig{
		MaxSize:    DefaultMaxLogSize,
		MaxBackups: DefaultMaxLogBackups,
	}

	// Parse LOG_MAX_SIZE_MB
	if sizeStr := strings.TrimSpace(os.Getenv("LOG_MAX_SIZE_MB")); sizeStr != "" {
		if sizeMB, err := strconv.ParseInt(sizeStr, 10, 64); err == nil && sizeMB > 0 {
			cfg.MaxSize = sizeMB * 1024 * 1024
		}
	}

	// Parse LOG_MAX_BACKUPS
	if backupsStr := strings.TrimSpace(os.Getenv("LOG_MAX_BACKUPS")); backupsStr != "" {
		if backups, err := strconv.Atoi(backupsStr); err == nil && backups >= 0 {
			cfg.MaxBackups = backups
		}
	}

	return cfg
}

// eventLogWriter wraps the Windows event log for use with logrus
type eventLogWriter struct {
	elog *eventlog.Log
}

func (w *eventLogWriter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Default to Info level for event log
	err = w.elog.Info(1, msg)
	return len(p), err
}

// rotatingFileWriter implements a simple rotating file logger
type rotatingFileWriter struct {
	mu         sync.Mutex
	logDir     string
	filename   string
	file       *os.File
	size       int64
	maxSize    int64
	maxBackups int
}

// newRotatingFileWriter creates a new rotating file writer
func newRotatingFileWriter(logDir, filename string, cfg LogConfig) (*rotatingFileWriter, error) {
	w := &rotatingFileWriter{
		logDir:     logDir,
		filename:   filename,
		maxSize:    cfg.MaxSize,
		maxBackups: cfg.MaxBackups,
	}

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *rotatingFileWriter) openFile() error {
	logPath := filepath.Join(w.logDir, w.filename)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	w.file = f
	w.size = info.Size()
	return nil
}

func (w *rotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n, err = w.file.Write(p)
	if err != nil {
		return n, err
	}

	w.size += int64(n)

	if w.size >= w.maxSize {
		if err := w.rotate(); err != nil {
			// Log rotation failed, but we don't want to lose the log entry
			// Just continue writing to the current file
			// Note: Can't use log.Warnf here as it would cause recursion
			fmt.Fprintf(os.Stderr, "Log rotation failed: %v\n", err)
		}
	}

	return n, nil
}

func (w *rotatingFileWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	basePath := filepath.Join(w.logDir, w.filename)

	// Remove oldest backup if it exists (beyond maxBackups limit)
	oldestBackup := fmt.Sprintf("%s.%d", basePath, w.maxBackups)
	os.Remove(oldestBackup)

	// Rotate existing backups (shift .1 -> .2, etc.)
	for i := w.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", basePath, i)
		dst := fmt.Sprintf("%s.%d", basePath, i+1)
		os.Rename(src, dst)
	}

	// Rotate current log to .1
	if err := os.Rename(basePath, basePath+".1"); err != nil {
		// If rename fails, just truncate the file
		return w.openFile()
	}

	// Open new log file
	return w.openFile()
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// SetupServiceLogging configures logging for Windows service mode.
// It sets up:
// 1. Rotating file logging in the executable directory
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

	logDir := filepath.Join(filepath.Dir(exePath), "logs")
	cfg := getLogConfig()

	// Set up rotating file writer
	fileWriter, err := newRotatingFileWriter(logDir, LogFileName, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup file logging: %w", err)
	}

	// Create multi-writer with file and stdout (stdout for debugging/console mode)
	var writers []io.Writer
	writers = append(writers, fileWriter)

	// Also keep stdout for compatibility (useful when running interactively)
	writers = append(writers, os.Stdout)

	// Try to set up Windows Event Log (non-fatal if it fails)
	var elog *eventlog.Log
	elog, err = eventlog.Open(EventLogSource)
	if err != nil {
		// Event log not registered - install the source first time
		err = eventlog.InstallAsEventCreate(EventLogSource, eventlog.Error|eventlog.Warning|eventlog.Info)
		if err != nil {
			// Not critical - file logging will work
			// Note: Can't use log.Warnf here as logging isn't configured yet
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

	// Log startup message with config info
	log.Infof("Logging initialized - dir: %s, max_size: %dMB, backups: %d",
		logDir, cfg.MaxSize/(1024*1024), cfg.MaxBackups)
	if elog != nil {
		elog.Info(1, "NetWatcher Agent service started")
	}

	// Return cleanup function
	cleanup = func() {
		fileWriter.Close()
		if elog != nil {
			elog.Close()
		}
	}

	return cleanup, nil
}

// LogEvent writes a message to the Windows Event Log.
// This is useful for critical events that administrators should see in Event Viewer.
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

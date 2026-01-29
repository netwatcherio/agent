//go:build windows

// Package platform provides Windows-specific platform integrations.
package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	// LogFileName is the base name for log files
	LogFileName = "netwatcher-agent.log"
	// MaxLogSize is the maximum size of a log file before rotation (5MB)
	MaxLogSize = 5 * 1024 * 1024
	// MaxLogBackups is the number of rotated logs to keep
	MaxLogBackups = 3
	// EventLogSource is the Windows Event Log source name
	EventLogSource = "NetWatcherAgent"
)

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
	mu       sync.Mutex
	logDir   string
	filename string
	file     *os.File
	size     int64
}

// newRotatingFileWriter creates a new rotating file writer
func newRotatingFileWriter(logDir, filename string) (*rotatingFileWriter, error) {
	w := &rotatingFileWriter{
		logDir:   logDir,
		filename: filename,
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

	if w.size >= MaxLogSize {
		if err := w.rotate(); err != nil {
			// Log rotation failed, but we don't want to lose the log entry
			// Just continue writing to the current file
			log.Warnf("Log rotation failed: %v", err)
		}
	}

	return n, nil
}

func (w *rotatingFileWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	basePath := filepath.Join(w.logDir, w.filename)

	// Remove oldest backup if it exists
	oldestBackup := fmt.Sprintf("%s.%d", basePath, MaxLogBackups)
	os.Remove(oldestBackup)

	// Rotate existing backups
	for i := MaxLogBackups - 1; i >= 1; i-- {
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
// Returns a cleanup function that should be called on shutdown.
func SetupServiceLogging() (cleanup func(), err error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	logDir := filepath.Join(filepath.Dir(exePath), "logs")

	// Set up rotating file writer
	fileWriter, err := newRotatingFileWriter(logDir, LogFileName)
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
			log.Warnf("Failed to install event log source (requires admin): %v", err)
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

	// Log startup message
	log.Infof("Logging initialized - log directory: %s", logDir)
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

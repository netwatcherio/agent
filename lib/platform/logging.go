// Package platform provides cross-platform logging utilities.
package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Default logging configuration (can be overridden via environment variables)
var (
	// LogFileName is the base name for log files
	LogFileName = "netwatcher-agent.log"
	// DefaultMaxLogSize is the maximum size of a log file before rotation (10MB)
	DefaultMaxLogSize int64 = 10 * 1024 * 1024
	// DefaultMaxLogBackups is the number of rotated logs to keep (1 = keep only .log.1)
	DefaultMaxLogBackups = 1
)

// LogConfig holds the logging configuration
type LogConfig struct {
	MaxSize    int64 // Max size in bytes before rotation
	MaxBackups int   // Number of backup files to keep
}

// GetLogConfig reads logging configuration from environment variables.
// Environment variables:
//   - LOG_MAX_SIZE_MB: Maximum log file size in megabytes (default: 10)
//   - LOG_MAX_BACKUPS: Number of backup files to keep (default: 1)
func GetLogConfig() LogConfig {
	cfg := LogConfig{
		MaxSize:    DefaultMaxLogSize,
		MaxBackups: DefaultMaxLogBackups,
	}

	if sizeStr := strings.TrimSpace(os.Getenv("LOG_MAX_SIZE_MB")); sizeStr != "" {
		if sizeMB, err := strconv.ParseInt(sizeStr, 10, 64); err == nil && sizeMB > 0 {
			cfg.MaxSize = sizeMB * 1024 * 1024
		}
	}

	if backupsStr := strings.TrimSpace(os.Getenv("LOG_MAX_BACKUPS")); backupsStr != "" {
		if backups, err := strconv.Atoi(backupsStr); err == nil && backups >= 0 {
			cfg.MaxBackups = backups
		}
	}

	return cfg
}

// RotatingFileWriter implements a simple rotating file logger.
// It is used on all platforms to write logs beside the executable.
type RotatingFileWriter struct {
	mu         sync.Mutex
	logDir     string
	filename   string
	file       *os.File
	size       int64
	maxSize    int64
	maxBackups int
}

// NewRotatingFileWriter creates a new rotating file writer.
func NewRotatingFileWriter(logDir, filename string, cfg LogConfig) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{
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

func (w *RotatingFileWriter) openFile() error {
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

// Write implements io.Writer.
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n, err = w.file.Write(p)
	if err != nil {
		return n, err
	}

	w.size += int64(n)

	if w.size >= w.maxSize {
		if err := w.rotate(); err != nil {
			fmt.Fprintf(os.Stderr, "Log rotation failed: %v\n", err)
		}
	}

	return n, nil
}

func (w *RotatingFileWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	basePath := filepath.Join(w.logDir, w.filename)

	// Remove oldest backup if it exists
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
		return w.openFile()
	}

	return w.openFile()
}

// Close closes the underlying file.
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

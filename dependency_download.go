package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// PlatformInfo represents platform-specific information
type PlatformInfo struct {
	OS   string
	Arch string
}

// DependencyConfig represents configuration for a dependency
type DependencyConfig struct {
	Name         string
	Version      string
	BaseURL      string
	Patterns     map[string]PlatformPattern // Key: "os-arch" or "os"
	DestDir      string
	TempDir      string // Directory for temporary files (defaults to "./temp")
	Executable   string // Name of the executable file
	MaxRetries   int
	Timeout      time.Duration
	ForceUpdate  bool
	VerifyHash   bool
	ExpectedHash string // Optional expected SHA256 hash
}

// PlatformPattern defines how to construct download URLs and extract files for a platform
type PlatformPattern struct {
	URLTemplate    string // Template with placeholders like {version}, {os}, {arch}
	ArchiveFormat  string // "zip", "tar.gz", or "binary"
	ExecutableName string // Name of executable inside archive
}

// DependencyDownloader handles downloading and managing dependencies
type DependencyDownloader struct {
	config *DependencyConfig
	client *http.Client
}

// NewDependencyDownloader creates a new dependency downloader
func NewDependencyDownloader(config *DependencyConfig) *DependencyDownloader {
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.TempDir == "" {
		config.TempDir = "./temp"
	}

	return &DependencyDownloader{
		config: config,
		client: &http.Client{Timeout: config.Timeout},
	}
}

// Download downloads and installs the dependency
func (d *DependencyDownloader) Download() error {
	platform := d.getCurrentPlatform()
	pattern, err := d.getPatternForPlatform(platform)
	if err != nil {
		return fmt.Errorf("unsupported platform %s-%s: %w", platform.OS, platform.Arch, err)
	}

	// Create destination directory
	if err := os.MkdirAll(d.config.DestDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Create temp directory
	if err := os.MkdirAll(d.config.TempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	executablePath := filepath.Join(d.config.DestDir, d.config.Executable)

	// Check if update is needed
	if !d.config.ForceUpdate && !d.isUpdateNeeded(executablePath) {
		log.WithFields(log.Fields{
			"dependency": d.config.Name,
			"path":       executablePath,
		}).Debug("Dependency already exists and is up to date")
		return nil
	}

	// Construct download URL
	downloadURL := d.buildDownloadURL(pattern, platform)

	log.WithFields(log.Fields{
		"dependency": d.config.Name,
		"version":    d.config.Version,
		"url":        downloadURL,
		"platform":   fmt.Sprintf("%s-%s", platform.OS, platform.Arch),
	}).Info("Downloading dependency")

	// Download with retry logic
	tempFile, err := d.downloadWithRetry(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", d.config.Name, err)
	}
	defer os.Remove(tempFile)

	// Extract and install
	hash, err := d.extractAndInstall(tempFile, pattern, executablePath)
	if err != nil {
		return fmt.Errorf("failed to extract and install %s: %w", d.config.Name, err)
	}

	// Verify hash if expected hash is provided
	if d.config.VerifyHash && d.config.ExpectedHash != "" {
		if hash != d.config.ExpectedHash {
			return fmt.Errorf("hash verification failed for %s: expected %s, got %s",
				d.config.Name, d.config.ExpectedHash, hash)
		}
		log.WithField("dependency", d.config.Name).Debug("Hash verification passed")
	}

	// Store hash for future comparisons
	if err := d.storeHash(executablePath, hash); err != nil {
		log.WithError(err).Warn("Failed to store hash file")
	}

	// Clean up temp directory (optional - remove old temp files)
	d.cleanupTempDir()

	log.WithFields(log.Fields{
		"dependency": d.config.Name,
		"path":       executablePath,
		"hash":       hash[:8] + "...", // Show first 8 chars of hash
	}).Info("Successfully downloaded and installed dependency")

	return nil
}

// getCurrentPlatform returns the current platform information
func (d *DependencyDownloader) getCurrentPlatform() PlatformInfo {
	return PlatformInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
}

// getPatternForPlatform gets the appropriate pattern for the current platform
func (d *DependencyDownloader) getPatternForPlatform(platform PlatformInfo) (PlatformPattern, error) {
	// Try exact match first (os-arch)
	key := fmt.Sprintf("%s-%s", platform.OS, platform.Arch)
	if pattern, exists := d.config.Patterns[key]; exists {
		return pattern, nil
	}

	// Try OS-only match
	if pattern, exists := d.config.Patterns[platform.OS]; exists {
		return pattern, nil
	}

	// Try common aliases
	aliases := d.getPlatformAliases(platform)
	for _, alias := range aliases {
		if pattern, exists := d.config.Patterns[alias]; exists {
			return pattern, nil
		}
	}

	return PlatformPattern{}, fmt.Errorf("no pattern found for platform %s-%s", platform.OS, platform.Arch)
}

// getPlatformAliases returns common aliases for a platform
func (d *DependencyDownloader) getPlatformAliases(platform PlatformInfo) []string {
	var aliases []string

	// OS aliases
	switch platform.OS {
	case "darwin":
		aliases = append(aliases, "macos", "mac", "osx")
	case "windows":
		aliases = append(aliases, "win")
	}

	// Architecture aliases
	switch platform.Arch {
	case "amd64":
		aliases = append(aliases, "x86_64", "x64")
	case "arm64":
		aliases = append(aliases, "aarch64")
	case "386":
		aliases = append(aliases, "i386", "x86")
	}

	return aliases
}

// buildDownloadURL constructs the download URL using the pattern template
func (d *DependencyDownloader) buildDownloadURL(pattern PlatformPattern, platform PlatformInfo) string {
	url := d.config.BaseURL + pattern.URLTemplate

	// Replace placeholders
	replacements := map[string]string{
		"{version}": d.config.Version,
		"{os}":      platform.OS,
		"{arch}":    platform.Arch,
		"{name}":    d.config.Name,
	}

	// Add architecture aliases for common patterns
	if platform.Arch == "amd64" {
		replacements["{x86_64}"] = "x86_64"
		replacements["{x64}"] = "x64"
	}
	if platform.Arch == "arm64" {
		replacements["{aarch64}"] = "aarch64"
	}

	for placeholder, value := range replacements {
		url = strings.ReplaceAll(url, placeholder, value)
	}

	return url
}

// downloadWithRetry downloads a file with retry logic
func (d *DependencyDownloader) downloadWithRetry(url string) (string, error) {
	var lastErr error

	for attempt := 1; attempt <= d.config.MaxRetries; attempt++ {
		if attempt > 1 {
			waitTime := time.Duration(attempt-1) * 2 * time.Second
			log.WithFields(log.Fields{
				"attempt": attempt,
				"wait":    waitTime,
			}).Warn("Retrying download after failure")
			time.Sleep(waitTime)
		}

		tempFile, err := d.downloadFile(url)
		if err == nil {
			return tempFile, nil
		}

		lastErr = err
		log.WithError(err).WithField("attempt", attempt).Warn("Download attempt failed")
	}

	return "", fmt.Errorf("failed after %d attempts: %w", d.config.MaxRetries, lastErr)
}

// downloadFile downloads a file to a temporary location within the working directory
func (d *DependencyDownloader) downloadFile(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Create temporary file in our temp directory
	tempFileName := fmt.Sprintf("%s-download-%d-%d", d.config.Name, time.Now().Unix(), os.Getpid())
	tempFilePath := filepath.Join(d.config.TempDir, tempFileName)

	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	// Copy with progress (for large files)
	written, err := io.Copy(tempFile, resp.Body)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}

	log.WithFields(log.Fields{
		"dependency": d.config.Name,
		"size":       formatBytes(written),
		"tempFile":   tempFilePath,
	}).Debug("Download completed")

	return tempFile.Name(), nil
}

// cleanupTempDir removes old temporary files from the temp directory
func (d *DependencyDownloader) cleanupTempDir() {
	// Clean up files older than 1 hour
	cutoffTime := time.Now().Add(-1 * time.Hour)

	entries, err := os.ReadDir(d.config.TempDir)
	if err != nil {
		log.WithError(err).Debug("Failed to read temp directory for cleanup")
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoffTime) && strings.Contains(entry.Name(), "-download-") {
			filePath := filepath.Join(d.config.TempDir, entry.Name())
			if err := os.Remove(filePath); err != nil {
				log.WithError(err).WithField("file", filePath).Debug("Failed to remove old temp file")
			} else {
				log.WithField("file", filePath).Debug("Removed old temp file")
			}
		}
	}
}

// extractAndInstall extracts the downloaded file and installs the executable
func (d *DependencyDownloader) extractAndInstall(archivePath string, pattern PlatformPattern, executablePath string) (string, error) {
	switch pattern.ArchiveFormat {
	case "zip":
		return d.extractZipAndInstall(archivePath, pattern.ExecutableName, executablePath)
	case "tar.gz":
		return d.extractTarGzAndInstall(archivePath, pattern.ExecutableName, executablePath)
	case "binary":
		return d.installBinary(archivePath, executablePath)
	default:
		return "", fmt.Errorf("unsupported archive format: %s", pattern.ArchiveFormat)
	}
}

// extractZipAndInstall extracts a ZIP archive and installs the executable
func (d *DependencyDownloader) extractZipAndInstall(archivePath, executableName, destPath string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		if filepath.Base(file.Name) == executableName {
			return d.extractFileFromZip(file, destPath)
		}
	}

	return "", fmt.Errorf("executable '%s' not found in ZIP archive", executableName)
}

// extractFileFromZip extracts a single file from a ZIP archive
func (d *DependencyDownloader) extractFileFromZip(file *zip.File, destPath string) (string, error) {
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)

	if _, err := io.Copy(writer, src); err != nil {
		return "", err
	}

	// Make executable
	if err := os.Chmod(destPath, 0755); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// extractTarGzAndInstall extracts a tar.gz archive and installs the executable
func (d *DependencyDownloader) extractTarGzAndInstall(archivePath, executableName, destPath string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == executableName {
			return d.extractFileFromTar(tr, destPath)
		}
	}

	return "", fmt.Errorf("executable '%s' not found in tar.gz archive", executableName)
}

// extractFileFromTar extracts a single file from a tar reader
func (d *DependencyDownloader) extractFileFromTar(tr *tar.Reader, destPath string) (string, error) {
	dst, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)

	if _, err := io.Copy(writer, tr); err != nil {
		return "", err
	}

	// Make executable
	if err := os.Chmod(destPath, 0755); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// installBinary installs a direct binary file
func (d *DependencyDownloader) installBinary(srcPath, destPath string) (string, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)

	if _, err := io.Copy(writer, src); err != nil {
		return "", err
	}

	// Make executable
	if err := os.Chmod(destPath, 0755); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// isUpdateNeeded checks if an update is needed
func (d *DependencyDownloader) isUpdateNeeded(executablePath string) bool {
	// Check if executable exists
	if _, err := os.Stat(executablePath); os.IsNotExist(err) {
		return true
	}

	// Check if hash file exists (indicates previous successful download)
	hashFile := executablePath + ".hash"
	if _, err := os.Stat(hashFile); os.IsNotExist(err) {
		return true
	}

	// If we have a specific expected hash, verify it
	if d.config.ExpectedHash != "" {
		currentHash, err := d.getFileHash(executablePath)
		if err != nil || currentHash != d.config.ExpectedHash {
			return true
		}
	}

	return false
}

// getFileHash calculates the SHA256 hash of a file
func (d *DependencyDownloader) getFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// storeHash stores the hash of the downloaded file
func (d *DependencyDownloader) storeHash(executablePath, hash string) error {
	hashFile := executablePath + ".hash"
	return os.WriteFile(hashFile, []byte(hash), 0644)
}

// formatBytes formats byte count as human readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Example usage functions

// DownloadTrippy downloads the Trippy dependency using the new flexible system
func DownloadTrippy(version string) error {
	// Use executable directory instead of working directory
	// This is critical for Windows services which run from System32
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	baseDir := filepath.Dir(exePath)

	config := &DependencyConfig{
		Name:        "trippy",
		Version:     version,
		BaseURL:     "https://github.com/fujiapple852/trippy/releases/download/" + version + "/",
		DestDir:     filepath.Join(baseDir, "lib"),
		TempDir:     filepath.Join(baseDir, "temp"),
		Executable:  getTrippyExecutableName(),
		MaxRetries:  3,
		Timeout:     60 * time.Second,
		ForceUpdate: false,
		VerifyHash:  false,
		Patterns: map[string]PlatformPattern{
			"windows-amd64": {
				URLTemplate:    "trippy-{version}-x86_64-pc-windows-msvc.zip",
				ArchiveFormat:  "zip",
				ExecutableName: "trip.exe",
			},
			"windows-arm64": {
				URLTemplate:    "trippy-{version}-aarch64-pc-windows-msvc.zip",
				ArchiveFormat:  "zip",
				ExecutableName: "trip.exe",
			},
			"darwin": {
				URLTemplate:    "trippy-{version}-x86_64-apple-darwin.tar.gz",
				ArchiveFormat:  "tar.gz",
				ExecutableName: "trip",
			},
			"linux-amd64": {
				URLTemplate:    "trippy-{version}-x86_64-unknown-linux-musl.tar.gz",
				ArchiveFormat:  "tar.gz",
				ExecutableName: "trip",
			},
			"linux-arm64": {
				URLTemplate:    "trippy-{version}-aarch64-unknown-linux-musl.tar.gz",
				ArchiveFormat:  "tar.gz",
				ExecutableName: "trip",
			},
		},
	}

	downloader := NewDependencyDownloader(config)
	return downloader.Download()
}

// getTrippyExecutableName returns the appropriate executable name for the current platform
func getTrippyExecutableName() string {
	if runtime.GOOS == "windows" {
		return "trip.exe"
	}
	return "trip"
}

// DownloadCustomTool shows how to download a different tool
func DownloadCustomTool() error {
	// Get working directory
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "."
	}

	config := &DependencyConfig{
		Name:       "mytool",
		Version:    "v1.0.0",
		BaseURL:    "https://github.com/myorg/mytool/releases/download/v1.0.0/",
		DestDir:    filepath.Join(workDir, "bin"),
		TempDir:    filepath.Join(workDir, "temp"), // Use temp folder in working directory
		Executable: "mytool" + getExecutableExt(),
		Patterns: map[string]PlatformPattern{
			"linux-amd64": {
				URLTemplate:    "mytool-{version}-linux-amd64.tar.gz",
				ArchiveFormat:  "tar.gz",
				ExecutableName: "mytool",
			},
			"windows-amd64": {
				URLTemplate:    "mytool-{version}-windows-amd64.zip",
				ArchiveFormat:  "zip",
				ExecutableName: "mytool.exe",
			},
			"darwin": {
				URLTemplate:    "mytool-{version}-darwin-universal.tar.gz",
				ArchiveFormat:  "tar.gz",
				ExecutableName: "mytool",
			},
		},
	}

	downloader := NewDependencyDownloader(config)
	return downloader.Download()
}

// getExecutableExt returns the executable extension for the current platform
func getExecutableExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Updated main dependency download function
func downloadTrippyDependency() error {
	return DownloadTrippy("0.13.0")
}

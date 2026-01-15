package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
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

// UpdaterConfig holds configuration for the auto-updater
type UpdaterConfig struct {
	Repository     string
	CurrentVersion string
	CheckInterval  time.Duration
	GitHubToken    string
	UpdateURL      string
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
	Draft      bool `json:"draft"`
	Prerelease bool `json:"prerelease"`
}

// AutoUpdater handles automatic updates
type AutoUpdater struct {
	config   *UpdaterConfig
	client   *http.Client
	shutdown context.CancelFunc
}

// NewAutoUpdater creates a new auto-updater instance
func NewAutoUpdater(config *UpdaterConfig) *AutoUpdater {
	return &AutoUpdater{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Start begins the auto-update process
func (u *AutoUpdater) Start(ctx context.Context) {
	log.WithFields(log.Fields{
		"version":  u.config.CurrentVersion,
		"interval": u.config.CheckInterval,
		"repo":     u.config.Repository,
	}).Info("Auto-updater started")

	// Check immediately on startup (after a delay to let the main app stabilize)
	time.Sleep(30 * time.Second)
	u.checkForUpdate()

	// Set up periodic checks
	ticker := time.NewTicker(u.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Auto-updater stopping...")
			return
		case <-ticker.C:
			u.checkForUpdate()
		}
	}
}

// checkForUpdate checks if a new version is available and updates if needed
func (u *AutoUpdater) checkForUpdate() {
	log.Debug("Checking for updates...")

	latestRelease, err := u.getLatestRelease()
	if err != nil {
		log.WithError(err).Error("Failed to check for updates")
		return
	}

	if latestRelease == nil {
		log.Debug("No releases found")
		return
	}

	// Skip drafts and prereleases
	if latestRelease.Draft || latestRelease.Prerelease {
		log.WithField("version", latestRelease.TagName).Debug("Skipping draft/prerelease")
		return
	}

	// Compare versions
	if !u.isNewerVersion(latestRelease.TagName, u.config.CurrentVersion) {
		log.WithFields(log.Fields{
			"latest":  latestRelease.TagName,
			"current": u.config.CurrentVersion,
		}).Debug("Already up to date")
		return
	}

	log.WithFields(log.Fields{
		"new_version":     latestRelease.TagName,
		"current_version": u.config.CurrentVersion,
	}).Info("New version available")

	// Find appropriate asset for current platform
	asset := u.findAssetForPlatform(latestRelease)
	if asset == nil {
		log.WithFields(log.Fields{
			"os":   runtime.GOOS,
			"arch": runtime.GOARCH,
		}).Warn("No suitable asset found for platform")
		return
	}

	log.WithField("asset", asset.Name).Info("Downloading update")
	if err := u.downloadAndApplyUpdate(asset.BrowserDownloadURL, asset.Name); err != nil {
		log.WithError(err).Error("Failed to apply update")
		return
	}

	log.Info("Update applied successfully. Restarting...")
	u.restart()
}

// getLatestRelease fetches the latest release from GitHub
func (u *AutoUpdater) getLatestRelease() (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", u.config.Repository)
	if u.config.UpdateURL != "" {
		url = u.config.UpdateURL
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if u.config.GitHubToken != "" {
		req.Header.Set("Authorization", "token "+u.config.GitHubToken)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

// isNewerVersion checks if the new version is newer than current
func (u *AutoUpdater) isNewerVersion(newVersion, currentVersion string) bool {
	if strings.Contains(currentVersion, "dev") {
		log.Info("Using development version, not updating.")
		return false
	}

	newVersion = strings.TrimPrefix(newVersion, "v")
	currentVersion = strings.TrimPrefix(currentVersion, "v")
	return newVersion != currentVersion
}

// findAssetForPlatform finds the appropriate release asset for current platform
func (u *AutoUpdater) findAssetForPlatform(release *GitHubRelease) *struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
} {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Look for assets that match the current platform
	patterns := []string{
		fmt.Sprintf("%s_%s", goos, goarch),
		fmt.Sprintf("%s-%s", goos, goarch),
	}

	// Add OS-specific patterns
	if goos == "windows" {
		patterns = append(patterns, "windows", "win")
	} else if goos == "darwin" {
		patterns = append(patterns, "darwin", "macos", "mac")
	} else if goos == "linux" {
		patterns = append(patterns, "linux")
	}

	// Add architecture patterns
	if goarch == "amd64" {
		patterns = append(patterns, "x86_64", "amd64")
	} else if goarch == "arm64" {
		patterns = append(patterns, "amd64", "arm64")
	}

	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)

		// Must contain netwatcher-agent in the name
		if !strings.Contains(name, "netwatcher") && !strings.Contains(name, "netwatcher-agent") {
			continue
		}

		// Check if it matches our platform patterns
		matchCount := 0
		for _, pattern := range patterns {
			if strings.Contains(name, strings.ToLower(pattern)) {
				matchCount++
			}
		}

		// If we found at least 2 pattern matches (OS + arch), this is likely our binary
		if matchCount >= 2 {
			return &asset
		}
	}

	// Fallback: look for any asset with netwatcher-agent in the name
	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.Contains(name, "netwatcher") || strings.Contains(name, "netwatcher-agent") {
			return &asset
		}
	}

	return nil
}

// downloadAndApplyUpdate downloads and applies the update
func (u *AutoUpdater) downloadAndApplyUpdate(downloadURL, filename string) error {
	resp, err := u.client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create local tmp directory next to executable (avoids read-only /tmp issues)
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	localTmpDir := filepath.Join(filepath.Dir(execPath), ".tmp")
	if err := os.MkdirAll(localTmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create local tmp directory: %w", err)
	}

	tempFile, err := os.CreateTemp(localTmpDir, "netwatcher-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		return fmt.Errorf("failed to save update: %w", err)
	}

	return u.extractAndReplace(tempFile.Name(), filename)
}

// extractAndReplace extracts the binary and replaces the current executable
func (u *AutoUpdater) extractAndReplace(archivePath, filename string) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	var newBinaryPath string

	switch {
	case strings.HasSuffix(filename, ".tar.gz"):
		newBinaryPath, err = u.extractTarGz(archivePath)
	case strings.HasSuffix(filename, ".zip"):
		newBinaryPath, err = u.extractZip(archivePath)
	case strings.HasSuffix(filename, ".exe") || !strings.Contains(filename, "."):
		newBinaryPath = archivePath
	default:
		return fmt.Errorf("unsupported archive format: %s", filename)
	}

	if err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}

	if err := os.Chmod(newBinaryPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	// Create a unique backup name with timestamp
	backupPath := fmt.Sprintf("%s.backup.%d", currentExe, time.Now().Unix())

	// Rename the current executable instead of copying
	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to rename current executable: %w", err)
	}

	// Move the new binary to the original location
	if err := os.Rename(newBinaryPath, currentExe); err != nil {
		// Try to restore the backup
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("failed to move new executable: %w", err)
	}

	// Schedule cleanup of the backup file after restart
	// The old process will continue running from the renamed file
	go func() {
		time.Sleep(5 * time.Second)
		os.Remove(backupPath)
	}()

	return nil
}

// extractTarGz extracts a tar.gz archive and returns the path to the binary
func (u *AutoUpdater) extractTarGz(archivePath string) (string, error) {
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

	// Use local tmp directory next to executable
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	localTmpDir := filepath.Join(filepath.Dir(execPath), ".tmp")
	if err := os.MkdirAll(localTmpDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create local tmp directory: %w", err)
	}

	tempDir, err := os.MkdirTemp(localTmpDir, "extract-*")
	if err != nil {
		return "", err
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		if header.Typeflag == tar.TypeReg {
			name := filepath.Base(header.Name)
			if strings.Contains(name, "netwatcher") || strings.Contains(name, "netwatcher-agent") {
				path := filepath.Join(tempDir, name)
				outFile, err := os.Create(path)
				if err != nil {
					return "", err
				}

				if _, err := io.Copy(outFile, tr); err != nil {
					outFile.Close()
					return "", err
				}
				outFile.Close()

				return path, nil
			}
		}
	}

	return "", fmt.Errorf("no netwatcher-agent executable found in archive")
}

// extractZip extracts a zip archive and returns the path to the binary
func (u *AutoUpdater) extractZip(archivePath string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	// Use local tmp directory next to executable
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	localTmpDir := filepath.Join(filepath.Dir(execPath), ".tmp")
	if err := os.MkdirAll(localTmpDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create local tmp directory: %w", err)
	}

	tempDir, err := os.MkdirTemp(localTmpDir, "extract-*")
	if err != nil {
		return "", err
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		name := filepath.Base(f.Name)
		if strings.Contains(name, "netwatcher") || strings.Contains(name, "netwatcher-agent") {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}

			path := filepath.Join(tempDir, name)
			outFile, err := os.Create(path)
			if err != nil {
				rc.Close()
				return "", err
			}

			_, err = io.Copy(outFile, rc)
			outFile.Close()
			rc.Close()

			if err != nil {
				return "", err
			}

			return path, nil
		}
	}

	return "", fmt.Errorf("no netwatcher-agent executable found in archive")
}

// copyFile copies a file from src to dst
func (u *AutoUpdater) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// restart exits the program to trigger a restart by the service manager
func (u *AutoUpdater) restart() {
	log.Info("Exiting for restart...")
	os.Exit(0)
}

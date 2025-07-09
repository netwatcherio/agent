package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/netwatcherio/netwatcher-agent/workers"
	"github.com/netwatcherio/netwatcher-agent/ws"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
		patterns = append(patterns, "aarch64", "arm64")
	}

	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)

		// Must contain netwatcher-agent in the name
		if !strings.Contains(name, "netwatcher-agent") && !strings.Contains(name, "netwatcher_agent") {
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
		if strings.Contains(name, "netwatcher-agent") || strings.Contains(name, "netwatcher_agent") {
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

	tempFile, err := os.CreateTemp("", "netwatcher-update-*")
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

	backupPath := currentExe + ".backup"

	if err := u.copyFile(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	if err := u.copyFile(newBinaryPath, currentExe); err != nil {
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	os.Remove(backupPath)

	if newBinaryPath != archivePath {
		os.Remove(newBinaryPath)
	}

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
	tempDir, err := os.MkdirTemp("", "extract-*")
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
			if strings.Contains(name, "netwatcher-agent") || strings.Contains(name, "netwatcher_agent") {
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

	tempDir, err := os.MkdirTemp("", "extract-*")
	if err != nil {
		return "", err
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		name := filepath.Base(f.Name)
		if strings.Contains(name, "netwatcher-agent") || strings.Contains(name, "netwatcher_agent") {
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

func main() {
	fmt.Printf("Starting NetWatcher Agent v%s...\n", VERSION)

	var configPath string
	var disableUpdater bool
	flag.StringVar(&configPath, "config", "./config.conf", "Path to the config file")
	flag.BoolVar(&disableUpdater, "no-update", false, "Disable auto-updater")
	flag.Parse()

	loadConfig(configPath)

	// Download trippy dependency
	err := downloadTrippyDependency()
	if err != nil {
		log.Fatalf("Failed to download dependency: %v", err)
	}

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for _ = range c {
			log.Info("Received interrupt signal, shutting down...")
			cancel() // This will stop the auto-updater gracefully
			shutdown()
			return
		}
	}()

	// Initialize auto-updater if not disabled
	if !disableUpdater {
		updateConfig := &UpdaterConfig{
			Repository:     "netwatcherio/netwatcher-agent", // Replace with your actual repo
			CurrentVersion: VERSION,
			CheckInterval:  6 * time.Hour,             // Check every 6 hours
			GitHubToken:    os.Getenv("GITHUB_TOKEN"), // Optional
		}

		updater := NewAutoUpdater(updateConfig)
		go updater.Start(ctx)
	} else {
		log.Info("Auto-updater disabled")
	}

	var probeGetCh = make(chan []probes.Probe)
	var probeDataCh = make(chan probes.ProbeData)

	wsH := &ws.WebSocketHandler{
		Host:         os.Getenv("HOST"),
		HostWS:       os.Getenv("HOST_WS"),
		Pin:          os.Getenv("PIN"),
		ID:           os.Getenv("ID"),
		AgentVersion: VERSION,
		ProbeGetCh:   probeGetCh,
	}
	wsH.InitWS()

	workers.InitProbeDataWorker(wsH, probeDataCh)

	go func(ws *ws.WebSocketHandler) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Minute * 1)
				log.Debug("Getting probes again...")
				ws.GetConnection().Emit("probe_get", []byte("please"))
			}
		}
	}(wsH)

	thisAgent, err := primitive.ObjectIDFromHex(wsH.ID)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse agent ID")
		return
	}

	workers.InitProbeWorker(probeGetCh, probeDataCh, thisAgent)

	log.Info("NetWatcher Agent started successfully")

	// Wait for context cancellation
	<-ctx.Done()
	log.Info("NetWatcher Agent stopping...")
}

func shutdown() {
	log.WithField("goroutines", runtime.NumGoroutine()).Info("Shutting down NetWatcher Agent")
	os.Exit(0)
}

func downloadTrippyDependency() error {
	var version = "0.13.0"
	baseURL := "https://github.com/fujiapple852/trippy/releases/download/" + version + "/"

	var fileName, extractedName string

	switch runtime.GOOS {
	case "windows":
		if runtime.GOARCH == "amd64" {
			fileName = "trippy-VER-x86_64-pc-windows-msvc.zip"
		} else {
			fileName = "trippy-VER-aarch64-pc-windows-msvc.zip"
		}
		extractedName = "trip.exe"
	case "darwin":
		fileName = "trippy-VER-x86_64-apple-darwin.tar.gz"
		extractedName = "trip"
	case "linux":
		if runtime.GOARCH == "amd64" {
			fileName = "trippy-VER-x86_64-unknown-linux-musl.tar.gz"
		} else if runtime.GOARCH == "arm64" {
			fileName = "trippy-VER-aarch64-unknown-linux-musl.tar.gz"
		} else {
			return fmt.Errorf("unsupported Linux architecture: %s", runtime.GOARCH)
		}
		extractedName = "trip"
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	var format = strings.Replace(fileName, "VER", version, -1)
	url := baseURL + format
	libPath := filepath.Join(".", "lib")
	os.MkdirAll(libPath, os.ModePerm)
	filePath := filepath.Join(libPath, extractedName)

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		log.WithField("path", filePath).Debug("Trippy binary already exists")
		return nil
	}

	log.WithFields(log.Fields{
		"url":  url,
		"path": filePath,
	}).Info("Downloading trippy dependency")

	// Download file
	tempFilePath := filePath + ".temp"
	err := downloadFile(url, tempFilePath)
	if err != nil {
		return fmt.Errorf("failed to download file: %v", err)
	}

	var newHash string
	if runtime.GOOS == "windows" {
		newHash, err = extractZipAndHash(tempFilePath, libPath)
		if err != nil {
			os.Remove(tempFilePath)
			return fmt.Errorf("failed to extract archive: %v", err)
		}
		os.Remove(tempFilePath)
	} else {
		newHash, err = extractTarGzAndHash(tempFilePath, libPath)
		if err != nil {
			os.Remove(tempFilePath)
			return fmt.Errorf("failed to extract archive: %v", err)
		}
		os.Remove(tempFilePath)
	}

	log.WithField("path", filePath).Info("Downloaded trippy binary")

	// Make the file executable
	err = os.Chmod(filePath, 0755)
	if err != nil {
		return fmt.Errorf("failed to make file executable: %v", err)
	}

	// Store the hash for future comparisons
	err = os.WriteFile(filePath+".hash", []byte(newHash), 0644)
	if err != nil {
		log.WithError(err).Warn("Failed to write hash file")
	}

	return nil
}

func extractTarGzAndHash(archivePath, destPath string) (string, error) {
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

		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == "trip" {
			outPath := filepath.Join(destPath, "trip")
			outFile, err := os.Create(outPath)
			if err != nil {
				return "", err
			}
			defer outFile.Close()

			hasher := sha256.New()
			writer := io.MultiWriter(outFile, hasher)

			if _, err := io.Copy(writer, tr); err != nil {
				return "", err
			}

			log.WithField("file", header.Name).Debug("Extracted trippy file")
			return hex.EncodeToString(hasher.Sum(nil)), nil
		}
	}

	return "", fmt.Errorf("'trip' binary not found in archive")
}

func extractZipAndHash(archivePath, destPath string) (string, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	for _, file := range reader.File {
		if filepath.Base(file.Name) == "trip.exe" {
			outPath := filepath.Join(destPath, "trip.exe")

			src, err := file.Open()
			if err != nil {
				return "", err
			}
			defer src.Close()

			dst, err := os.Create(outPath)
			if err != nil {
				return "", err
			}
			defer dst.Close()

			hasher := sha256.New()
			writer := io.MultiWriter(dst, hasher)

			if _, err := io.Copy(writer, src); err != nil {
				return "", err
			}

			log.WithField("file", file.Name).Debug("Extracted trippy file")
			return hex.EncodeToString(hasher.Sum(nil)), nil
		}
	}

	return "", fmt.Errorf("'trip.exe' not found in archive")
}

func getFileHash(filePath string) (string, error) {
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

func isUpdateNeeded(filePath string) bool {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return true
	}

	hashFile := filePath + ".hash"
	_, err = os.Stat(hashFile)
	if os.IsNotExist(err) {
		return true
	}

	return false
}

func downloadFile(url string, filePath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

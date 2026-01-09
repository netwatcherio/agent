package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/joho/godotenv"
)

const (
	defaultConfig = `# NetWatcher Agent Configuration
# See: https://docs.netwatcher.io/agent/configuration

# Controller URL (host:port or domain, no protocol needed)
CONTROLLER_URL=api.netwatcher.io

# Enable SSL (true = HTTPS/WSS, false = HTTP/WS)
CONTROLLER_SSL=true

# Agent credentials (provided during agent creation in the panel)
WORKSPACE_ID=
AGENT_ID=
AGENT_PIN=

# Optional: PSK is saved here after initial bootstrap
# AGENT_PSK=
`
)

var (
	// These will be set at build time using -ldflags
	VERSION   string = "dev"     // Git tag or version
	buildDate string = "unknown" // Build date
	gitCommit string = "unknown" // Git commit hash
)

// getExecutableHash returns the SHA256 hash of the running executable
// This is useful for verifying the binary integrity
func getExecutableHash() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	fileBytes, err := os.ReadFile(exePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(fileBytes)
	return hex.EncodeToString(hash[:8]), nil // First 8 bytes (16 hex chars)
}

// getVersionInfo returns formatted version information
func getVersionInfo() string {
	if VERSION == "dev" {
		// Development build - show runtime hash
		if hash, err := getExecutableHash(); err == nil {
			return fmt.Sprintf("dev-%s", hash)
		}
		return "dev-unknown"
	}

	// Release build - use build-time version
	return VERSION
}

// getBuildInfo returns detailed build information
func getBuildInfo() string {
	info := fmt.Sprintf("Version: %s\n", getVersionInfo())
	info += fmt.Sprintf("Build Date: %s\n", buildDate)
	info += fmt.Sprintf("Git Commit: %s\n", gitCommit)
	info += fmt.Sprintf("Go Version: %s\n", runtime.Version())
	info += fmt.Sprintf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Add runtime hash for verification
	if hash, err := getExecutableHash(); err == nil {
		info += fmt.Sprintf("Binary Hash: %s\n", hash)
	}

	return info
}

func loadConfig(configFile string) error {
	// Display version information
	fmt.Printf("NetWatcher %s - Copyright (c) 2024-%d Shaun Agostinho\n",
		getVersionInfo(), time.Now().Year())

	// In verbose mode or development, show full build info
	if os.Getenv("VERBOSE") == "true" || VERSION == "dev" {
		fmt.Printf("\nBuild Information:\n%s\n", getBuildInfo())
	}

	_, err := os.Stat(configFile)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Config file '%s' does not exist, creating one now.\n", configFile)
		_, err = os.Create(configFile)
		if err != nil {
			return err
		}
		err = os.WriteFile(configFile, []byte(defaultConfig), 0644)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	if os.Getenv("ENVIRONMENT") == "PRODUCTION" {
		fmt.Printf("Running in PRODUCTION mode.\n")
	} else {
		fmt.Printf("Running in DEVELOPMENT mode.\n")
	}

	err = godotenv.Load(configFile)
	if err != nil {
		return err
	}

	return nil
}

// Add a version command handler if needed
func handleVersionFlag() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Print(getBuildInfo())
		os.Exit(0)
	}
}

// lib/platform/platform.go
// Package platform provides utilities for platform-specific operations.
// Consolidates OS/architecture detection logic used across probes.
package platform

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// Info contains current platform information.
type Info struct {
	OS   string // runtime.GOOS
	Arch string // runtime.GOARCH
}

// Current returns the current platform info.
func Current() Info {
	return Info{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
}

// IsWindows returns true if running on Windows.
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsDarwin returns true if running on macOS.
func IsDarwin() bool {
	return runtime.GOOS == "darwin"
}

// IsLinux returns true if running on Linux.
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsAMD64 returns true if running on AMD64 architecture.
func IsAMD64() bool {
	return runtime.GOARCH == "amd64"
}

// IsARM64 returns true if running on ARM64 architecture.
func IsARM64() bool {
	return runtime.GOARCH == "arm64"
}

// -------------------- Binary Helpers --------------------

// BinaryName returns the platform-appropriate binary name.
// On Windows, appends ".exe" suffix.
func BinaryName(name string) string {
	if IsWindows() {
		return name + ".exe"
	}
	return name
}

// BinaryPath returns the full path to a binary in the lib directory.
func BinaryPath(name string) string {
	return filepath.Join(".", "lib", BinaryName(name))
}

// -------------------- Supported Platform Checks --------------------

// SupportedOS contains the list of supported operating systems.
var SupportedOS = []string{"windows", "darwin", "linux"}

// SupportedArch contains the list of supported architectures.
var SupportedArch = []string{"amd64", "arm64"}

// ErrUnsupportedOS is returned when the OS is not supported.
type ErrUnsupportedOS struct {
	OS string
}

func (e ErrUnsupportedOS) Error() string {
	return fmt.Sprintf("unsupported OS: %s", e.OS)
}

// ErrUnsupportedArch is returned when the architecture is not supported.
type ErrUnsupportedArch struct {
	OS   string
	Arch string
}

func (e ErrUnsupportedArch) Error() string {
	return fmt.Sprintf("unsupported %s architecture: %s", e.OS, e.Arch)
}

// CheckSupported validates that the current platform is supported.
// Returns nil if supported, or an appropriate error if not.
func CheckSupported() error {
	switch runtime.GOOS {
	case "windows", "darwin":
		return nil
	case "linux":
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			return nil
		}
		return ErrUnsupportedArch{OS: runtime.GOOS, Arch: runtime.GOARCH}
	default:
		return ErrUnsupportedOS{OS: runtime.GOOS}
	}
}

// RequireSupported panics if the platform is not supported.
// Use during initialization.
func RequireSupported() {
	if err := CheckSupported(); err != nil {
		panic(err)
	}
}

//go:build windows

// Package platform provides Windows service integration.
package platform

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

// Windows process creation flags for detaching child processes
const (
	CREATE_NEW_PROCESS_GROUP  = 0x00000200
	DETACHED_PROCESS          = 0x00000008
	CREATE_NO_WINDOW          = 0x08000000
	CREATE_BREAKAWAY_FROM_JOB = 0x01000000
)

// Package-level restart signaling
var (
	restartMu        sync.Mutex
	restartRequested bool
	restartChan      = make(chan struct{}, 1)
)

// AgentRunner is the function signature for the main agent logic.
type AgentRunner func(ctx context.Context) error

// windowsService wraps the agent runner to implement svc.Handler.
type windowsService struct {
	runner AgentRunner
}

// Execute implements svc.Handler and is called by the Windows SCM.
func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	// Notify SCM that we're starting
	const acceptedCmds = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Create context for the agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the agent in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.runner(ctx)
	}()

	// Report running IMMEDIATELY - don't wait for agent initialization
	// The agent will continue initializing in the background
	changes <- svc.Status{State: svc.Running, Accepts: acceptedCmds}

	// Main service loop - handle SCM commands and restart requests
	for {
		select {
		case err := <-errCh:
			// Agent exited on its own
			changes <- svc.Status{State: svc.StopPending}
			if err != nil {
				return true, 1
			}
			return false, 0

		case <-restartChan:
			// Restart requested (e.g., from auto-updater)
			log.Info("Service restart requested, initiating graceful restart...")
			changes <- svc.Status{State: svc.StopPending}

			// Spawn a detached process to restart the service after we exit
			if err := spawnRestartProcess(); err != nil {
				log.WithError(err).Error("Failed to spawn restart process")
			}

			// Give the spawned PowerShell process time to fully initialize before
			// we exit. Without this delay, SCM kills all child processes when the
			// service handler returns, even with CREATE_BREAKAWAY_FROM_JOB,
			// because PowerShell hasn't finished loading (~1-2s cold start).
			log.Info("Waiting for restart process to initialize...")
			time.Sleep(5 * time.Second)

			// Cancel context to stop the agent
			cancel()

			// Wait for agent to finish
			<-errCh
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// SCM wants our status - respond with current status
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// Graceful shutdown requested
				changes <- svc.Status{State: svc.StopPending}
				cancel()

				// Wait for agent to finish
				<-errCh
				return false, 0

			default:
				// Ignore unknown commands
			}
		}
	}
}

// IsRunningAsService detects if the process was started by the Windows SCM.
func IsRunningAsService() bool {
	// Primary detection: use the official Windows API
	isService, err := svc.IsWindowsService()
	if err == nil {
		return isService
	}

	// Fallback: check if we have an interactive session
	// Services typically don't have a console attached
	return !isInteractiveSession()
}

// RunService runs the agent as a Windows service.
// This function blocks until the service is stopped.
func RunService(name string, runner AgentRunner) error {
	// Use debug.Run for better error messages during development
	// In production, this behaves the same as svc.Run
	return svc.Run(name, &windowsService{runner: runner})
}

// DebugRunService runs the service in debug mode (for testing in console)
func DebugRunService(name string, runner AgentRunner) error {
	return debug.Run(name, &windowsService{runner: runner})
}

// isInteractiveSession checks if stdin is attached to a terminal.
func isInteractiveSession() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ServiceError creates a formatted service error for logging
func ServiceError(format string, args ...interface{}) error {
	return fmt.Errorf("service: "+format, args...)
}

// IsDebugMode checks if running in debug/development mode
func IsDebugMode() bool {
	// Check for common debug indicators
	for _, arg := range os.Args {
		if strings.ToLower(arg) == "--debug" || strings.ToLower(arg) == "-debug" {
			return true
		}
	}
	return os.Getenv("NETWATCHER_DEBUG") != ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// RequestServiceRestart signals the service handler to initiate a restart.
// This is used by the auto-updater to trigger a proper Windows service restart.
// Returns true if a restart was successfully requested, false if not running as a service.
func RequestServiceRestart() bool {
	restartMu.Lock()
	defer restartMu.Unlock()

	if restartRequested {
		// Already requested
		return true
	}

	// Check if we're running as a service
	if !IsRunningAsService() {
		log.Info("Not running as service, cannot request service restart")
		return false
	}

	restartRequested = true

	// Non-blocking send to restart channel
	select {
	case restartChan <- struct{}{}:
		log.Info("Service restart request sent")
	default:
		// Channel already has a pending restart request
		log.Debug("Service restart already pending")
	}

	return true
}

// WatchdogRestart triggers a graceful service restart for watchdog-forced restarts.
// Mirrors auto_updater restart pattern but uses exit code 1 (failure) instead of 0.
// This ensures the restart script has time to initialize before the process exits.
func WatchdogRestart() {
	log.Info("Watchdog: initiating graceful restart...")

	if RequestServiceRestart() {
		log.Info("Watchdog: service restart requested, waiting for graceful shutdown...")
		time.Sleep(6 * time.Second)
		log.Warn("Watchdog: service restart did not complete, falling back to exit")
	}

	log.Info("Watchdog: exiting for restart...")
	os.Exit(1)
}

// recoveryAction describes a single failure recovery action for the Windows SCM.
// delayMs is the wait before the action (in milliseconds); action is "restart" / "reboot" / "run".
type recoveryAction struct {
	action  string
	delayMs int
}

// DefaultRecoveryActions is the SCM failure policy applied on every agent startup.
//
// Format note: Windows `sc.exe failure` is famously finicky. The canonical format
// is exactly 6 slash-separated values for 3 action/delay pairs. Providing MORE
// than 6 values (which is what we did initially) silently corrupts the policy on
// some Windows versions and results in "no action" being applied — see
// https://stackoverflow.com/questions/22872510
//
// Subsequent failures use the 3rd pair with empty action (`""`), which Windows
// interprets as "take no action" — i.e. once we've restarted 3 times in quick
// succession, leave the service stopped so an operator can investigate.
//
// We DON'T try to be clever with reset periods. `reset= 60` is the documented
// minimum and matches Windows' default behaviour for failure tracking.
// `reset= 0` is rejected on some Windows versions, which caused the original
// "agent exits and never comes back" bug.
var DefaultRecoveryActions = []recoveryAction{
	{action: "restart", delayMs: 5000},  // 5s   — 1st failure
	{action: "restart", delayMs: 10000}, // 10s  — 2nd failure
	{action: "restart", delayMs: 30000}, // 30s  — 3rd failure (last restart)
	{action: "", delayMs: 60000},        // 60s  — subsequent failures: take no action
}

// DefaultResetPeriodSeconds is the failure-counter reset period.
// 60s is the documented minimum and matches the SCM's default failure-tracking
// window. We use this (not `reset= 0`) because some Windows builds reject `0`.
const DefaultResetPeriodSeconds = 60

// ServiceRecoveryTimeout is how long to wait for sc.exe to apply the policy.
// sc.exe occasionally hangs on locked-down hosts; we don't want ConfigureServiceRecovery
// to block startup indefinitely.
const ServiceRecoveryTimeout = 30 * time.Second

// ConfigureServiceRecovery re-asserts the SCM failure policy on every startup.
// This fixes existing installs that were installed before the wider policy was added.
//
// Format: `sc.exe failure <svc> reset= <secs> actions= <a1>/<d1>/<a2>/<d2>/<a3>/<d3>`
// where each pair is action/delay_ms, and the 3rd pair may use empty action
// (`""`) to mean "take no action" for subsequent failures. See:
//
//	https://serverfault.com/questions/983831
//	https://stackoverflow.com/questions/22872510
//
// After setting, we call `sc qfailure` to verify the policy was actually applied.
// Some Windows builds / GPOs silently reject `sc.exe failure`; if verification
// fails, we log the actual returned values so the operator can diagnose. The
// function never returns a fatal error — best-effort only.
func ConfigureServiceRecovery() error {
	if !IsRunningAsService() {
		// Not running as a service — nothing to configure.
		return nil
	}

	// Build the canonical 6-value actions string: a1/d1/a2/d2/a3/d3
	if len(DefaultRecoveryActions) != 4 {
		return fmt.Errorf("configure recovery: DefaultRecoveryActions has %d entries, expected 4 (3 actions + 1 subsequent-failure slot)",
			len(DefaultRecoveryActions))
	}
	parts := make([]string, 0, 6)
	for _, a := range DefaultRecoveryActions {
		// Use empty string for "no action" — the only way to specify it per the
		// SO answer. action is "" means sc.exe treats it as "take no action".
		if a.action == "" {
			parts = append(parts, "", fmt.Sprintf("%d", a.delayMs))
		} else {
			parts = append(parts, a.action, fmt.Sprintf("%d", a.delayMs))
		}
	}
	actions := strings.Join(parts, "/")

	// Run sc.exe failure with a hard timeout so a wedged sc.exe can't block startup.
	ctx, cancel := context.WithTimeout(context.Background(), ServiceRecoveryTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sc.exe", "failure", "NetWatcherAgent",
		"reset=", fmt.Sprintf("%d", DefaultResetPeriodSeconds),
		"actions=", actions,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", strings.TrimSpace(string(out))).
			Warn("ConfigureServiceRecovery: sc.exe failure returned error — agent will run with whatever policy was previously set")
		return nil
	}

	log.WithFields(log.Fields{
		"actions": actions,
		"reset_s": DefaultResetPeriodSeconds,
	}).Info("Service recovery policy set — verifying")

	// Verify it actually took effect. sc.exe returns 0 even on some GPO-locked
	// systems where the policy silently wasn't applied. `sc qfailure` tells us
	// the truth.
	verifyCmd := exec.CommandContext(ctx, "sc.exe", "qfailure", "NetWatcherAgent")
	verifyOut, verifyErr := verifyCmd.CombinedOutput()
	if verifyErr != nil {
		log.WithError(verifyErr).WithField("output", strings.TrimSpace(string(verifyOut))).
			Warn("ConfigureServiceRecovery: sc qfailure verification query failed — could not confirm policy")
		return nil
	}
	log.WithField("output", strings.TrimSpace(string(verifyOut))).
		Info("Service recovery policy verified")
	return nil
}

// WriteLastExitInfo persists diagnostic info about why the agent is exiting.
// Used by both graceful exits and the watchdog so post-mortem analysis doesn't
// require catching the live log. Always overwrites — only the most recent exit
// reason matters for diagnosing a stuck host.
func WriteLastExitInfo(reason, lastError string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	path := filepath.Join(filepath.Dir(exe), "last_exit.json")
	payload := fmt.Sprintf(`{"reason":%q,"last_error":%q,"timestamp":%q}`+"\n",
		reason, lastError, time.Now().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
		log.WithError(err).Warn("Failed to write last_exit.json")
	}
}

// spawnRestartProcess creates a detached process that will restart the service
// after the current process exits. This ensures the SCM sees a clean shutdown
// before the service is restarted.
func spawnRestartProcess() error {
	// Get the path to the executable directory for the restart script
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Ensure .update directory exists for update artifacts
	exeDir := filepath.Dir(exePath)
	updateDir := filepath.Join(exeDir, ".update")
	if err := os.MkdirAll(updateDir, 0755); err != nil {
		return fmt.Errorf("failed to create update directory: %w", err)
	}

	// Create a PowerShell script for more reliable restart with retries and logging
	// Script lives in .update/, but log sits beside the exe for easy visibility
	scriptPath := filepath.Join(updateDir, "restart_service.ps1")
	logPath := filepath.Join(exeDir, "restart_service.log")

	// PowerShell script content:
	// - Logs all actions for debugging
	// - Waits for service to fully stop
	// - Retries start up to 5 times with increasing delays
	// - Cleans up the script after successful start
	scriptContent := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
$ServiceName = 'NetWatcherAgent'
$LogFile = '%s'
$ExePath = '%s'
$MaxRetries = 5
$BaseDelay = 3

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

function Test-FileLocked {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $file = [System.IO.File]::Open($Path, 'Open', 'Read', 'None')
        $file.Close()
        return $false
    } catch {
        return $true
    }
}

Write-Log "Restart script started"
Write-Log "Executable path: $ExePath"

# Wait for service to fully stop
$timeout = 30
$elapsed = 0
while ($elapsed -lt $timeout) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Log "Service not found, may have been uninstalled"
        exit 0
    }
    if ($svc.Status -eq 'Stopped') {
        Write-Log "Service is stopped"
        break
    }
    Write-Log "Waiting for service to stop... (Status: $($svc.Status))"
    Start-Sleep -Seconds 1
    $elapsed++
}

if ($elapsed -ge $timeout) {
    Write-Log "WARNING: Timeout waiting for service to stop"
    Write-Log "Attempting to force stop service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

# Wait for file handles to be released
Write-Log "Waiting for executable file lock to be released..."
$lockTimeout = 30
$lockElapsed = 0
while ($lockElapsed -lt $lockTimeout) {
    if (-not (Test-FileLocked -Path $ExePath)) {
        Write-Log "Executable is no longer locked"
        break
    }
    Write-Log "Executable still locked, waiting... ($lockElapsed sec)"
    Start-Sleep -Seconds 1
    $lockElapsed++
}

if ($lockElapsed -ge $lockTimeout) {
    Write-Log "WARNING: Executable may still be locked after $lockTimeout seconds"
}

# Additional buffer to ensure clean state
Start-Sleep -Seconds 2

# Retry loop to start the service
for ($i = 1; $i -le $MaxRetries; $i++) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Log "Attempt $i of $MaxRetries to start service (current status: $($svc.Status))"
    
    # If stuck in StartPending, wait for it
    if ($svc.Status -eq 'StartPending') {
        Write-Log "Service is in StartPending, waiting..."
        Start-Sleep -Seconds 5
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') {
            Write-Log "SUCCESS: Service is now running"
            Remove-Item -Path $PSCommandPath -Force -ErrorAction SilentlyContinue
            exit 0
        }
    }
    
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 3
        
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') {
            Write-Log "SUCCESS: Service is now running"
            Remove-Item -Path $PSCommandPath -Force -ErrorAction SilentlyContinue
            exit 0
        } else {
            Write-Log "Service status after start attempt: $($svc.Status)"
        }
    }
    catch {
        Write-Log "ERROR on attempt $i - $_"
    }
    
    if ($i -lt $MaxRetries) {
        $delay = $BaseDelay * $i
        Write-Log "Waiting $delay seconds before retry..."
        Start-Sleep -Seconds $delay
    }
}

Write-Log "FAILED: Could not start service after $MaxRetries attempts"
Write-Log "Manual intervention required: Start-Service -Name $ServiceName"
exit 1
`, strings.ReplaceAll(logPath, `\`, `\\`), strings.ReplaceAll(exePath, `\`, `\\`))

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write restart script: %w", err)
	}

	// Pre-create the log file from Go (running as SYSTEM) so the file inherits
	// proper ACLs. Without this, PowerShell can't create new files in Program Files
	// even when spawned by a SYSTEM-level service.
	seedEntry := fmt.Sprintf("%s - [Go] Restart initiated\n"+
		"  exe_path: %s\n"+
		"  script_path: %s\n"+
		"  log_path: %s\n"+
		"  update_dir: %s\n"+
		"  pid: %d\n"+
		"  cwd: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		exePath, scriptPath, logPath, updateDir,
		os.Getpid(), exeDir)
	if err := os.WriteFile(logPath, []byte(seedEntry), 0644); err != nil {
		log.WithError(err).Warn("Failed to pre-create restart log file")
	}

	log.WithFields(log.Fields{
		"script_path":   scriptPath,
		"log_path":      logPath,
		"exe_path":      exePath,
		"script_exists": fileExists(scriptPath),
	}).Info("Spawning restart process")

	// Run PowerShell in a completely detached process
	// -WindowStyle Hidden prevents any visible window
	// -ExecutionPolicy Bypass ensures the script runs even with restricted policies
	// -NoProfile skips loading PowerShell profile for faster startup
	// Use -Command with quoted path instead of -File to handle paths with spaces correctly
	// The & call operator ensures PowerShell interprets the path as a literal string
	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-NoProfile",
		"-Command", fmt.Sprintf("& '%s'", scriptPath))

	// CRITICAL: Use Windows process creation flags to fully detach the child process.
	// Without these flags, the PowerShell process is killed when the parent service stops
	// because Windows SCM associates child processes with the service's Job Object.
	//
	// - CREATE_NEW_PROCESS_GROUP: Makes the child independent from parent's console group
	// - DETACHED_PROCESS: The child has no console and is detached from the parent
	// - CREATE_NO_WINDOW: Prevents any window from appearing
	// - CREATE_BREAKAWAY_FROM_JOB: Breaks the child out of the SCM's Job Object so it
	//   survives the service process exit. Without this, SCM kills all child processes
	//   when the service stops, regardless of DETACHED_PROCESS.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB,
	}

	// Ensure no handle inheritance
	cmd.Stdin = nil

	// Capture stdout/stderr to help diagnose why PowerShell exits immediately
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		// Direct spawn failed — likely Job Object breakaway is disallowed by Group Policy.
		// Fall back to scheduling via Windows Task Scheduler which runs outside the
		// service's Job Object entirely.
		log.WithError(err).Warn("Direct spawn failed, trying Task Scheduler fallback")
		return scheduleRestartViaTaskScheduler(scriptPath)
	}

	// Verify the spawned process is actually alive. On some Windows configurations,
	// the process can exit immediately due to missing PowerShell, execution policy
	// issues, or other system restrictions.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		// Process exited immediately — this is abnormal, PowerShell didn't initialize
		// Capture output for debugging even though process exited
		errMsg := "Restart process exited immediately"
		if stdout.Len() > 0 {
			errMsg += fmt.Sprintf(", stdout: %s", stdout.String())
		}
		if stderr.Len() > 0 {
			errMsg += fmt.Sprintf(", stderr: %s", stderr.String())
		}
		if err == nil {
			// Exit with code 0 is still an error for our purposes - PowerShell should still be running
			log.Warn(errMsg + ", trying Task Scheduler fallback")
		} else {
			log.WithError(err).Warn(errMsg + ", trying Task Scheduler fallback")
		}
		return scheduleRestartViaTaskScheduler(scriptPath)
	case <-time.After(2 * time.Second):
		// Process still running after 2s — PowerShell has initialized successfully
		log.Info("Restart process confirmed alive")
	}

	log.Info("Restart process spawned successfully")
	return nil
}

// scheduleRestartViaTaskScheduler uses schtasks.exe to schedule a one-time
// restart task. This runs outside the service's Job Object entirely, making it
// immune to SCM process cleanup.
func scheduleRestartViaTaskScheduler(scriptPath string) error {
	startTime := time.Now().Add(10 * time.Second).Format("15:04")

	// First try with /RL HIGHEST which requires admin privileges
	// If that fails (common in containers or restricted environments), retry without it
	var stderr bytes.Buffer
	taskCmd := exec.Command("schtasks.exe",
		"/Create", "/TN", "NetWatcherRestart",
		"/TR", fmt.Sprintf(`powershell.exe -ExecutionPolicy Bypass -File "%s"`, scriptPath),
		"/SC", "ONCE", "/ST", startTime,
		"/F", "/RL", "HIGHEST")
	taskCmd.Stderr = &stderr

	if taskErr := taskCmd.Run(); taskErr != nil {
		// /RL HIGHEST may fail due to insufficient privileges.
		// Retry without it - the task will still run, just not with highest privileges.
		log.WithFields(log.Fields{
			"error":  taskErr,
			"stderr": stderr.String(),
		}).Warn("Task Scheduler with HIGHEST privileges failed, retrying without")

		// Retry without /RL HIGHEST
		stderr.Reset()
		taskCmd = exec.Command("schtasks.exe",
			"/Create", "/TN", "NetWatcherRestart",
			"/TR", fmt.Sprintf(`powershell.exe -ExecutionPolicy Bypass -File "%s"`, scriptPath),
			"/SC", "ONCE", "/ST", startTime,
			"/F")
		taskCmd.Stderr = &stderr

		if taskErr2 := taskCmd.Run(); taskErr2 != nil {
			os.Remove(scriptPath)
			return fmt.Errorf("failed to schedule restart via Task Scheduler (tried HIGHEST and standard): %w (stderr: %s)", taskErr2, stderr.String())
		}
	}

	log.WithField("scheduled_time", startTime).Info("Restart scheduled via Task Scheduler as fallback")
	return nil
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/netwatcherio/netwatcher-agent/lib/platform"
	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/netwatcherio/netwatcher-agent/web"
	"github.com/netwatcherio/netwatcher-agent/workers"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// Command-line flags (parsed in main, used by runAgent)
var (
	configPath     string
	disableUpdater bool
)

// Env helpers
func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func mustParseUintEnv(name string) uint {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		log.Fatalf("%s env var is required", name)
	}
	u64, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		log.Fatalf("invalid %s: %v", name, err)
	}
	return uint(u64)
}

func main() {
	// Handle --version/-v before anything else (before flag.Parse which would reject unknown flags)
	handleVersionFlag()

	fmt.Printf("Starting NetWatcher Agent - Version: %s...\n", VERSION)

	// ---------- CLI flags ----------
	flag.StringVar(&configPath, "config", "./config.conf", "Path to the config file")
	flag.BoolVar(&disableUpdater, "no-update", false, "Disable auto-updater")
	flag.Parse()

	// ---------- File Logging ----------
	// Set up rotating file logging beside the executable (all platforms).
	// On Linux, stdout is also kept for systemd journal / launchd capture.
	// On Windows service mode, stdout doesn't work so file logging is essential.
	cleanup, err := platform.SetupServiceLogging()
	if err != nil {
		fmt.Printf("Warning: Failed to setup file logging: %v\n", err)
	} else {
		defer cleanup()
	}

	// Check if running as Windows service
	if platform.IsRunningAsService() {
		log.Info("Running as Windows service")
		if err := platform.RunService("NetWatcherAgent", runAgent); err != nil {
			log.Fatalf("Service error: %v", err)
		}
		return
	}

	// Console mode: run with signal handling
	log.Info("Running in console mode")
	ctx, cancel := context.WithCancel(context.Background())

	// Handle Ctrl+C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Infof("Received signal %v, shutting down...", sig)
		cancel()
	}()

	if err := runAgent(ctx); err != nil {
		log.Fatalf("Agent error: %v", err)
	}
}

// runAgent contains the core agent logic.
// It is called either directly (console mode) or by the Windows service handler.
func runAgent(ctx context.Context) error {
	// ---------- Deactivation Guard ----------
	// If a DEACTIVATED marker exists, the agent was previously deleted.
	// Refuse to start to prevent restart loops from service managers.
	if web.CheckDeactivatedMarker() {
		log.Warn("DEACTIVATED marker found — agent was previously removed from workspace")
		log.Warn("To reinstall this agent, delete the DEACTIVATED file and obtain a new PIN from the panel")
		os.Exit(2)
	}

	loadConfig(configPath)

	// ---------- Dependencies ----------
	if err := downloadTrippyDependency(); err != nil {
		return fmt.Errorf("failed to download dependency: %w", err)
	}

	// ---------- Updater ----------
	if !disableUpdater {
		updateConfig := &UpdaterConfig{
			Repository:     "netwatcherio/netwatcher-agent",
			CurrentVersion: VERSION,
			CheckInterval:  6 * time.Hour,
			GitHubToken:    os.Getenv("GITHUB_TOKEN"),
		}
		updater := NewAutoUpdater(updateConfig)
		go updater.Start(ctx)
	} else {
		log.Info("Auto-updater disabled")
	}

	// ---------- Wire websocket handler ----------
	probeGetCh := make(chan []probes.Probe)
	probeDataCh := make(chan probes.ProbeData, 2048)
	speedtestQueueCh := make(chan []probes.SpeedtestQueueItem)

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.InfoLevel)

	cfg := web.LoadConfigFromEnv()

	// Get auth file path relative to executable (not working directory)
	// This is critical for Windows services which run from System32
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	authFilePath := filepath.Join(filepath.Dir(exePath), web.AuthFileName)

	// 1) Login and persist exact JSON

	// Check if the auth file exists
	if _, err := os.Stat(authFilePath); os.IsNotExist(err) {
		// File does not exist → perform login
		webCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		loginResp, err := web.DoLogin(webCtx, cfg)
		cancel()
		if err != nil {
			// Check if agent was deleted - clean up and exit gracefully
			if errors.Is(err, web.ErrAgentDeleted) {
				log.Warn("Agent has been deleted from workspace — cannot authenticate")
				log.Info("Cleaning up and exiting...")
				_ = web.DeleteAuthFile()
				_ = web.WriteDeactivatedMarker("deleted_on_login")
				web.SelfUninstall()
				os.Exit(2)
			}
			return fmt.Errorf("login error: %v (server said: %s)", err, web.SafeErr(loginResp))
		}

		respJson, _ := json.Marshal(loginResp)
		if err := web.SaveRawAuthJSON(respJson); err != nil {
			return fmt.Errorf("failed to save %s: %w", authFilePath, err)
		}
		log.Infof("Saved %s (status=%s)", authFilePath, loginResp.Status)
		cfg.PSK = loginResp.PSK
	} else if err != nil {
		// Some other filesystem error (permissions, etc.)
		return fmt.Errorf("failed to stat %s: %w", authFilePath, err)
	} else {
		// File exists → load PSK from it
		authData, err := os.ReadFile(authFilePath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", authFilePath, err)
		}

		// Replace with your own unmarshal/parse logic
		var loginResp web.LoginResponse
		if err := json.Unmarshal(authData, &loginResp); err != nil {
			return fmt.Errorf("failed to parse %s: %w", authFilePath, err)
		}

		log.Infof("Loaded PSK from %s (status=%s)", authFilePath, loginResp.Status)
		// Now you can use loginResp.PSK or whatever field you need

		cfg.PSK = loginResp.PSK
	}

	// Decide PSK to use
	psk := cfg.PSK
	if cfg.PSK != "" {
		psk = cfg.PSK
	}
	if psk == "" {
		return fmt.Errorf("no PSK available after login; cannot open websocket")
	}

	// 2) WS client with gobwas + headers
	deactivateCh := make(chan string, 1) // Channel for deactivation signals

	// Create a child context for the agent that can be cancelled on deactivation
	agentCtx, agentCancel := context.WithCancel(ctx)
	defer agentCancel()

	// Watchdog: track last successful activity
	var lastSuccessfulActivity = time.Now()
	var activityMu sync.Mutex
	updateActivity := func() {
		activityMu.Lock()
		lastSuccessfulActivity = time.Now()
		activityMu.Unlock()
	}

	wsClient := &web.WSClient{
		URL:              cfg.WSURL,       // e.g. ws://host:8080/ws
		WorkspaceID:      cfg.WorkspaceID, // header: X-Workspace-ID
		AgentID:          cfg.AgentID,     // header: X-Agent-ID
		PSK:              psk,             // header: X-Agent-PSK
		ProbeGetCh:       probeGetCh,
		SpeedtestQueueCh: speedtestQueueCh,
		DeactivateCh:     deactivateCh, // For receiving deactivation signals
		CancelFunc:       agentCancel,  // Cancel agent context on deactivation
		AgentVersion:     VERSION,
	}

	// Set reconnect callback after wsClient is created (avoids closure reference issue)
	wsClient.OnReconnect = func() {
		queueSize := workers.GetRetryQueue().Size()
		log.Infof("OnReconnect: retry queue has %d items", queueSize)

		// Brief delay to ensure connection is stable before flushing
		time.Sleep(500 * time.Millisecond)

		if queueSize > 0 {
			sent := workers.FlushRetryQueue(wsClient)
			log.Infof("OnReconnect: flushed %d/%d queued items", sent, queueSize)
		}
		updateActivity()
	}

	// If your workers expect a uint agent ID now:
	workers.SetControllerConfig(cfg.ControllerHost, cfg.SSL, cfg.WorkspaceID, cfg.AgentID, psk)
	workers.FetchProbesWorker(probeGetCh, probeDataCh, primitive.NewObjectID())
	workers.ProbeDataWorker(wsClient, probeDataCh)

	go wsClient.ConnectWithRetry(agentCtx)

	// Watchdog: restart if no activity for 10 minutes
	const watchdogTimeout = 10 * time.Minute
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				activityMu.Lock()
				elapsed := time.Since(lastSuccessfulActivity)
				activityMu.Unlock()

				log.Debugf("Watchdog: last activity %v ago", elapsed.Round(time.Second))

				if elapsed > watchdogTimeout {
					log.Errorf("Watchdog: no successful activity for %v, forcing restart", elapsed.Round(time.Second))
					os.Exit(1) // systemd/SCM will restart us
				}
			}
		}
	}()

	go func(ws *web.WSClient, ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Minute * 1)
				log.Debug("Getting probes again...")
				if ws.IsConnected() {
					if ok := ws.WsConn.Emit("probe_get", []byte("please")); ok {
						updateActivity()
					}
				}
			}
		}
	}(wsClient, agentCtx)

	// Speedtest queue worker: poll and process queue
	go func(ws *web.WSClient, queueCh chan []probes.SpeedtestQueueItem, ctx context.Context) {
		// Polling ticker (30 seconds)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Poll for new speedtest queue items
				if ws.IsConnected() {
					log.Debug("Polling for speedtest queue...")
					if ok := ws.WsConn.Emit("speedtest_queue_get", []byte("{}")); ok {
						updateActivity()
					}
				}
			case items := <-queueCh:
				// Process each queue item
				for _, item := range items {
					log.Infof("Processing speedtest queue item %d (server: %s)", item.ID, item.ServerID)

					// Run the speedtest
					result := probes.RunSpeedtestForQueue(item)

					// Send result back to controller
					if ws.IsConnected() {
						data, _ := json.Marshal(result)
						if ok := ws.WsConn.Emit("speedtest_result", data); !ok {
							log.Warn("WS: emit speedtest_result returned false")
						} else {
							log.Infof("Sent speedtest result for queue item %d", item.ID)
							updateActivity()
						}
					}
				}
			}
		}
	}(wsClient, speedtestQueueCh, agentCtx)

	// Wait for context cancellation (shutdown signal) or deactivation
	select {
	case <-agentCtx.Done():
		// Check if this was due to deactivation
		if wsClient.IsDeactivated() {
			log.Warn("Agent deactivated — performing cleanup and self-uninstall")
			web.SelfUninstall()
			time.Sleep(500 * time.Millisecond)
			os.Exit(2) // Signal to service managers not to restart
		}
		log.Info("shutting down")
	case reason := <-deactivateCh:
		log.Warnf("Agent deactivated (reason: %s) — performing cleanup and self-uninstall", reason)
		// Auth file and marker already handled by markDeactivated()
		web.SelfUninstall()
		time.Sleep(500 * time.Millisecond)
		os.Exit(2) // Signal to service managers not to restart
	}

	// Give goroutines a moment to clean up
	time.Sleep(500 * time.Millisecond)

	return nil
}

func shutdown() {
	log.WithField("goroutines", runtime.NumGoroutine()).Info("Shutting down NetWatcher Agent")
	os.Exit(0)
}

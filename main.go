package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/netwatcherio/netwatcher-agent/web"
	"github.com/netwatcherio/netwatcher-agent/workers"
	"go.mongodb.org/mongo-driver/bson/primitive"

	// "github.com/netwatcherio/netwatcher-agent/workers"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
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
	fmt.Printf("Starting NetWatcher Agent - Version: %s...\n", VERSION)

	// ---------- CLI flags ----------
	var configPath string
	var disableUpdater bool
	flag.StringVar(&configPath, "config", "./config.conf", "Path to the config file")
	flag.BoolVar(&disableUpdater, "no-update", false, "Disable auto-updater")
	flag.Parse()

	loadConfig(configPath)

	// ---------- Dependencies ----------
	if err := downloadTrippyDependency(); err != nil {
		log.Fatalf("Failed to download dependency: %v", err)
	}

	// ---------- Context & signals ----------
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Info("Received interrupt signal, shutting down...")
			cancel()
			shutdown()
			return
		}
	}()

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
	probeDataCh := make(chan probes.ProbeData)
	speedtestQueueCh := make(chan []probes.SpeedtestQueueItem)

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.InfoLevel)

	cfg := web.LoadConfigFromEnv()

	// 1) Login and persist exact JSON

	// Check if the auth file exists
	if _, err := os.Stat(web.AuthFileName); os.IsNotExist(err) {
		// File does not exist → perform login
		webCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		loginResp, err := web.DoLogin(webCtx, cfg)
		cancel()
		if err != nil {
			log.Fatalf("login error: %v (server said: %s)", err, web.SafeErr(loginResp))
		}

		respJson, _ := json.Marshal(loginResp)
		if err := web.SaveRawAuthJSON(respJson); err != nil {
			log.Fatalf("failed to save %s: %v", web.AuthFileName, err)
		}
		log.Infof("Saved %s (status=%s)", web.AuthFileName, loginResp.Status)
		cfg.PSK = loginResp.PSK
	} else if err != nil {
		// Some other filesystem error (permissions, etc.)
		log.Fatalf("failed to stat %s: %v", web.AuthFileName, err)
	} else {
		// File exists → load PSK from it
		authData, err := os.ReadFile(web.AuthFileName)
		if err != nil {
			log.Fatalf("failed to read %s: %v", web.AuthFileName, err)
		}

		// Replace with your own unmarshal/parse logic
		var loginResp web.LoginResponse
		if err := json.Unmarshal(authData, &loginResp); err != nil {
			log.Fatalf("failed to parse %s: %v", web.AuthFileName, err)
		}

		log.Infof("Loaded PSK from %s (status=%s)", web.AuthFileName, loginResp.Status)
		// Now you can use loginResp.PSK or whatever field you need

		cfg.PSK = loginResp.PSK
	}

	// Decide PSK to use
	psk := cfg.PSK
	if cfg.PSK != "" {
		psk = cfg.PSK
	}
	if psk == "" {
		log.Fatalf("no PSK available after login; cannot open websocket")
	}

	// 2) WS client with gobwas + headers
	wsClient := &web.WSClient{
		URL:              cfg.WSURL,       // e.g. ws://host:8080/ws
		WorkspaceID:      cfg.WorkspaceID, // header: X-Workspace-ID
		AgentID:          cfg.AgentID,     // header: X-Agent-ID
		PSK:              psk,             // header: X-Agent-PSK
		ProbeGetCh:       probeGetCh,
		SpeedtestQueueCh: speedtestQueueCh,
		AgentVersion:     VERSION,
	}

	// If your workers expect a uint agent ID now:
	workers.FetchProbesWorker(probeGetCh, probeDataCh, primitive.NewObjectID())
	workers.ProbeDataWorker(wsClient, probeDataCh)

	// Handle Ctrl+C / SIGTERM
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go wsClient.ConnectWithRetry(parent)

	go func(ws *web.WSClient, ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Minute * 1)
				log.Debug("Getting probes again...")
				if ws.WsConn != nil {
					ws.WsConn.Emit("probe_get", []byte("please"))
				}
			}
		}
	}(wsClient, ctx)

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
				if ws.WsConn != nil {
					log.Debug("Polling for speedtest queue...")
					ws.WsConn.Emit("speedtest_queue_get", []byte("{}"))
				}
			case items := <-queueCh:
				// Process each queue item
				for _, item := range items {
					log.Infof("Processing speedtest queue item %d (server: %s)", item.ID, item.ServerID)

					// Run the speedtest
					result := probes.RunSpeedtestForQueue(item)

					// Send result back to controller
					if ws.WsConn != nil {
						data, _ := json.Marshal(result)
						if ok := ws.WsConn.Emit("speedtest_result", data); !ok {
							log.Warn("WS: emit speedtest_result returned false")
						} else {
							log.Infof("Sent speedtest result for queue item %d", item.ID)
						}
					}
				}
			}
		}
	}(wsClient, speedtestQueueCh, ctx)

	<-parent.Done()
	log.Info("shutting down")
}

func shutdown() {
	log.WithField("goroutines", runtime.NumGoroutine()).Info("Shutting down NetWatcher Agent")
	os.Exit(0)
}

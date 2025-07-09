package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/netwatcherio/netwatcher-agent/workers"
	"github.com/netwatcherio/netwatcher-agent/ws"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"os"
	"os/signal"
	"runtime"
	"time"
)

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

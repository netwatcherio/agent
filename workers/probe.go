package workers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/showwin/speedtest-go/speedtest"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/sync/syncmap"
)

type ProbeWorkerS struct {
	Probe      probes.Probe
	ToRemove   bool
	StopChan   chan struct{}
	StopOnce   *sync.Once
	WaitGroup  *sync.WaitGroup
	Ctx        context.Context
	CancelFunc context.CancelFunc
}

func makeProbeKey(probe probes.Probe) string {
	// Serialize the config to JSON
	configBytes, err := json.Marshal(probe.Config)
	if err != nil {
		// Handle error or fall back to empty hash
		return fmt.Sprintf("%s_%s_error", probe.ID, probe.Type)
	}

	// Compute SHA-256 hash of the config
	hash := sha256.Sum256(configBytes)

	// Return key in format: <ID>_<Type>_<hash>
	return fmt.Sprintf("%s_%s_%x", probe.ID, probe.Type, hash[:8]) // using first 8 bytes of hash
}

var (
	checkWorkers syncmap.Map // Key: probeID_probeType composite key

	// Track TrafficSim instances with better synchronization
	// Note: TrafficSim tracking uses just probe ID (not composite key) since
	// there can only be one TrafficSim instance per probe ID
	trafficSimServer       *probes.TrafficSim
	trafficSimServerMutex  sync.RWMutex
	trafficSimClients      = make(map[primitive.ObjectID]*probes.TrafficSim)
	trafficSimClientsMutex sync.RWMutex

	// Speed test state
	speedTestRunning    bool
	speedTestMutex      sync.Mutex
	speedTestRetryCount int
)

const (
	speedTestRetryMax     = 3
	trafficSimStopTimeout = 75 * time.Second // Slightly more than GracefulShutdownTimeout
)

func findMatchingMTRProbe(probe probes.Probe) (probes.Probe, error) {
	var foundProbe probes.Probe
	found := false

	checkWorkers.Range(func(key, value interface{}) bool {
		probeWorker, ok := value.(ProbeWorkerS)
		if !ok {
			return true
		}

		if probeWorker.Probe.Type == probes.ProbeType_MTR {
			for _, target := range probeWorker.Probe.Config.Target {
				for _, givenTarget := range probe.Config.Target {
					targetAddr := givenTarget.Target
					if strings.Contains(targetAddr, ":") {
						targetAddr = strings.Split(targetAddr, ":")[0]
					}

					if target.Target == targetAddr || target.Target == givenTarget.Target {
						foundProbe = probeWorker.Probe
						found = true
						return false
					}
				}
			}
		}
		return true
	})

	if !found {
		return probes.Probe{}, errors.New("no matching MTR probe found")
	}
	return foundProbe, nil
}

func trafficSimConfigChanged(oldProbe, newProbe probes.Probe) bool {
	// Check if target address/port changed
	if len(oldProbe.Config.Target) > 0 && len(newProbe.Config.Target) > 0 {
		if oldProbe.Config.Target[0].Target != newProbe.Config.Target[0].Target {
			return true
		}
		if oldProbe.Config.Target[0].Agent != newProbe.Config.Target[0].Agent {
			return true
		}
	}

	// Check if server flag changed
	if oldProbe.Config.Server != newProbe.Config.Server {
		return true
	}

	// Check if allowed agents changed for server
	if oldProbe.Config.Server && len(oldProbe.Config.Target) != len(newProbe.Config.Target) {
		return true
	}

	return false
}

func stopTrafficSim(probeID primitive.ObjectID, isServer bool) {
	log.Infof("Stopping TrafficSim (server=%v) for probe %s", isServer, probeID.Hex())

	if isServer {
		trafficSimServerMutex.Lock()
		defer trafficSimServerMutex.Unlock()

		if trafficSimServer != nil {
			// Use the graceful Stop method
			trafficSimServer.Stop()

			// Wait for stop with timeout
			stopCtx, cancel := context.WithTimeout(context.Background(), trafficSimStopTimeout)
			defer cancel()

			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-stopCtx.Done():
					log.Warnf("Timeout waiting for TrafficSim server to stop for probe %s", probeID.Hex())
					goto cleanupA
				case <-ticker.C:
					// Use atomic read for Running field
					if atomic.LoadInt32(&trafficSimServer.Running) == 0 {
						log.Infof("TrafficSim server stopped successfully for probe %s", probeID.Hex())
						goto cleanupA
					}
				}
			}

		cleanupA:
			trafficSimServer = nil
		}
	} else {
		trafficSimClientsMutex.Lock()
		defer trafficSimClientsMutex.Unlock()

		if client, exists := trafficSimClients[probeID]; exists {
			// Use the graceful Stop method
			client.Stop()

			// Wait for stop with timeout
			stopCtx, cancel := context.WithTimeout(context.Background(), trafficSimStopTimeout)
			defer cancel()

			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-stopCtx.Done():
					log.Warnf("Timeout waiting for TrafficSim client to stop for probe %s", probeID.Hex())
					goto cleanupB
				case <-ticker.C:
					// Use atomic read for Running field
					if atomic.LoadInt32(&client.Running) == 0 {
						log.Infof("TrafficSim client stopped successfully for probe %s", probeID.Hex())
						goto cleanupB
					}
				}
			}

		cleanupB:
			delete(trafficSimClients, probeID)
		}
	}
}

func InitProbeWorker(checkChan chan []probes.Probe, dataChan chan probes.ProbeData, thisAgent primitive.ObjectID) {
	go func(aC chan []probes.Probe, dC chan probes.ProbeData) {
		for {
			p := <-aC

			var newKeys []string

			for _, probe := range p {
				probeKey := makeProbeKey(probe)
				existingWorker, exists := checkWorkers.Load(probeKey)

				if !exists {
					// New probe - create worker
					log.Infof("Starting NEW worker for probe %s (type: %s)", probe.ID.Hex(), probe.Type)

					ctx, cancel := context.WithCancel(context.Background())
					stopChan := make(chan struct{})
					stopOnce := &sync.Once{}
					wg := &sync.WaitGroup{}

					worker := ProbeWorkerS{
						Probe:      probe,
						ToRemove:   false,
						StopChan:   stopChan,
						StopOnce:   stopOnce,
						WaitGroup:  wg,
						Ctx:        ctx,
						CancelFunc: cancel,
					}

					checkWorkers.Store(probeKey, worker)
					startCheckWorker(probe, dataChan, thisAgent)
				} else {
					// Existing probe - check for updates
					oldWorker := existingWorker.(ProbeWorkerS)

					if probe.Type == probes.ProbeType_TRAFFICSIM {
						if trafficSimConfigChanged(oldWorker.Probe, probe) {
							// Configuration changed - restart
							log.Infof("TrafficSim probe %s (type: %s) configuration changed, restarting", probe.ID.Hex(), probe.Type)

							// Stop the old worker
							stopProbeWorker(&oldWorker)

							// Stop TrafficSim instance
							stopTrafficSim(probe.ID, oldWorker.Probe.Config.Server)

							// Brief pause for cleanup
							time.Sleep(500 * time.Millisecond)

							// Create new worker
							ctx, cancel := context.WithCancel(context.Background())
							stopChan := make(chan struct{})
							stopOnce := &sync.Once{}
							wg := &sync.WaitGroup{}

							newWorker := ProbeWorkerS{
								Probe:      probe,
								ToRemove:   false,
								StopChan:   stopChan,
								StopOnce:   stopOnce,
								WaitGroup:  wg,
								Ctx:        ctx,
								CancelFunc: cancel,
							}

							checkWorkers.Store(probeKey, newWorker)
							log.Infof("Starting UPDATED worker for probe %s (type: %s)", probe.ID.Hex(), probe.Type)
							startCheckWorker(probe, dataChan, thisAgent)
						} else if probe.Config.Server {
							// Just update allowed agents for server
							updateServerAllowedAgents(probe)
							oldWorker.Probe = probe
							checkWorkers.Store(probeKey, oldWorker)
						} else {
							// Update probe data
							oldWorker.Probe = probe
							checkWorkers.Store(probeKey, oldWorker)
						}
					} else {
						// Non-TrafficSim probe - just update
						oldWorker.Probe = probe
						checkWorkers.Store(probeKey, oldWorker)
					}
				}

				newKeys = append(newKeys, probeKey)
			}

			// Remove p that are no longer in the configuration
			checkWorkers.Range(func(key any, value any) bool {
				probeKey := key.(string)
				if !containsKey(newKeys, probeKey) {
					probeWorker := value.(ProbeWorkerS)
					log.Warnf("Probe %s (type: %s) marked for removal", probeWorker.Probe.ID.Hex(), probeWorker.Probe.Type)

					// Stop the worker
					stopProbeWorker(&probeWorker)

					// Stop TrafficSim if applicable
					if probeWorker.Probe.Type == probes.ProbeType_TRAFFICSIM {
						stopTrafficSim(probeWorker.Probe.ID, probeWorker.Probe.Config.Server)
					}

					// Remove from map
					checkWorkers.Delete(key)
				}
				return true
			})
		}
	}(checkChan, dataChan)
}

func stopProbeWorker(worker *ProbeWorkerS) {
	// Cancel context
	if worker.CancelFunc != nil {
		worker.CancelFunc()
	}

	// Close stop channel
	if worker.StopChan != nil && worker.StopOnce != nil {
		worker.StopOnce.Do(func() {
			close(worker.StopChan)
		})
	}

	// Wait for worker to finish
	if worker.WaitGroup != nil {
		done := make(chan struct{})
		go func() {
			worker.WaitGroup.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Debugf("Worker for probe %s (type: %s) stopped gracefully", worker.Probe.ID.Hex(), worker.Probe.Type)
		case <-time.After(5 * time.Second):
			log.Warnf("Timeout waiting for worker %s (type: %s) to stop", worker.Probe.ID.Hex(), worker.Probe.Type)
		}
	}
}

func updateServerAllowedAgents(probe probes.Probe) {
	var allowedAgentsList []primitive.ObjectID
	for _, agent := range probe.Config.Target[1:] {
		allowedAgentsList = append(allowedAgentsList, agent.Agent)
	}

	trafficSimServerMutex.RLock()
	defer trafficSimServerMutex.RUnlock()

	if trafficSimServer != nil {
		updateAllowedAgents(trafficSimServer, allowedAgentsList)
	}
}

func containsKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func contains(ids []primitive.ObjectID, id primitive.ObjectID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func startCheckWorker(probe probes.Probe, dataChan chan probes.ProbeData, thisAgent primitive.ObjectID) {
	go func(probe probes.Probe, dC chan probes.ProbeData) {
		probeKey := makeProbeKey(probe)

		// Get the worker
		workerInterface, exists := checkWorkers.Load(probeKey)
		if !exists {
			log.Warnf("Probe %s (type: %s) not found when starting worker", probe.ID.Hex(), probe.Type)
			return
		}

		worker := workerInterface.(ProbeWorkerS)

		// Track this goroutine
		if worker.WaitGroup != nil {
			worker.WaitGroup.Add(1)
			defer worker.WaitGroup.Done()
		}

		// Main worker loop
		for {
			select {
			case <-worker.Ctx.Done():
				log.Infof("Worker for probe %s (type: %s) stopped by context", probe.ID.Hex(), probe.Type)
				return
			case <-worker.StopChan:
				log.Infof("Worker for probe %s (type: %s) stopped by StopChan", probe.ID.Hex(), probe.Type)
				return
			default:
				// Get current probe data
				workerInterface, exists := checkWorkers.Load(probeKey)
				if !exists {
					log.Warnf("Probe %s (type: %s) no longer exists", probe.ID.Hex(), probe.Type)
					return
				}

				currentWorker := workerInterface.(ProbeWorkerS)
				if currentWorker.ToRemove {
					log.Infof("Probe %s (type: %s) marked for removal", probe.ID.Hex(), probe.Type)
					return
				}

				probe := currentWorker.Probe

				// Handle different probe types
				switch probe.Type {
				case probes.ProbeType_TRAFFICSIM:
					handleTrafficSimProbe(probe, dC, thisAgent, worker.Ctx, worker.StopChan)
					return // TrafficSim runs continuously

				case probes.ProbeType_SYSTEMINFO:
					handleSystemInfoProbe(probe, dC)

				case probes.ProbeType_MTR:
					handleMTRProbe(probe, dC)

				case probes.ProbeType_SPEEDTEST:
					handleSpeedTestProbe(probe, dC)

				case probes.ProbeType_SPEEDTEST_SERVERS:
					handleSpeedTestServersProbe(probe, dC)

				case probes.ProbeType_PING:
					handlePingProbe(probe, dC)

				case probes.ProbeType_NETWORKINFO:
					handleNetworkInfoProbe(probe, dC)

				case "AGENT":
					// Agent probe type - skip for now as it's likely metadata
					log.Debugf("Skipping AGENT probe type for probe %s", probe.ID.Hex())
					time.Sleep(30 * time.Second)

				default:
					log.Warnf("Unknown probe type: %s", probe.Type)
					time.Sleep(10 * time.Second)
				}
			}
		}
	}(probe, dataChan)
}

func handleTrafficSimProbe(probe probes.Probe, dataChan chan probes.ProbeData, thisAgent primitive.ObjectID, ctx context.Context, stopChan chan struct{}) {
	checkCfg := probe.Config
	checkAddress := strings.Split(checkCfg.Target[0].Target, ":")

	portNum, err := strconv.Atoi(checkAddress[1])
	if err != nil {
		log.Errorf("Invalid port number: %v", err)
		return
	}

	mtrProbe, err := findMatchingMTRProbe(probe)
	if err != nil {
		log.Errorf("Failed to find matching MTR probe: %v", err)
	}

	if probe.Config.Server {
		handleTrafficSimServer(probe, thisAgent, checkAddress[0], portNum, stopChan)
	} else {
		handleTrafficSimClient(probe, thisAgent, checkAddress[0], portNum, dataChan, &mtrProbe, stopChan)
	}
}

func handleTrafficSimServer(probe probes.Probe, thisAgent primitive.ObjectID, ipAddress string, port int, stopChan chan struct{}) {
	var allowedAgentsList []primitive.ObjectID
	for _, agent := range probe.Config.Target[1:] {
		allowedAgentsList = append(allowedAgentsList, agent.Agent)
	}

	trafficSimServerMutex.Lock()
	// Check if server needs to be created using atomic operations
	needNewServer := trafficSimServer == nil ||
		atomic.LoadInt32(&trafficSimServer.Running) == 0 ||
		trafficSimServer.Errored

	if needNewServer {
		trafficSimServer = &probes.TrafficSim{
			Running:       0, // Start with 0, will be set to 1 by Start()
			Errored:       false,
			IsServer:      true,
			ThisAgent:     thisAgent,
			OtherAgent:    primitive.ObjectID{},
			IPAddress:     ipAddress,
			Port:          int64(port),
			AllowedAgents: allowedAgentsList,
			Probe:         &probe,
		}

		log.Infof("Starting TrafficSim server on %s:%d", ipAddress, port)
		server := trafficSimServer
		trafficSimServerMutex.Unlock()

		// Start server in goroutine (Start() will set Running to 1)
		go server.Start(nil)

		// Wait for stop signal
		<-stopChan
		log.Infof("Stopping TrafficSim server for probe %s", probe.ID.Hex())
		stopTrafficSim(probe.ID, true)
	} else {
		// Update allowed agents
		updateAllowedAgents(trafficSimServer, allowedAgentsList)
		trafficSimServerMutex.Unlock()

		// Check periodically for updates
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				// Continue checking
			}
		}
	}
}

func handleTrafficSimClient(probe probes.Probe, thisAgent primitive.ObjectID, ipAddress string, port int,
	dataChan chan probes.ProbeData, mtrProbe *probes.Probe, stopChan chan struct{}) {

	trafficSimClientsMutex.Lock()

	// Check if client already exists and is running using atomic operations
	if existingClient, exists := trafficSimClients[probe.ID]; exists && atomic.LoadInt32(&existingClient.Running) == 1 {
		trafficSimClientsMutex.Unlock()

		// Wait for stop signal
		<-stopChan
		return
	}

	// Create new client
	simClient := &probes.TrafficSim{
		Running:    0, // Start with 0, will be set to 1 by Start()
		Errored:    false,
		Conn:       nil,
		ThisAgent:  thisAgent,
		OtherAgent: probe.Config.Target[0].Agent,
		IPAddress:  ipAddress,
		Port:       int64(port),
		Probe:      &probe,
		DataChan:   dataChan,
	}

	trafficSimClients[probe.ID] = simClient
	client := simClient
	trafficSimClientsMutex.Unlock()

	log.Infof("Starting TrafficSim client for probe %s to %s:%d", probe.ID.Hex(), ipAddress, port)

	// Start client in goroutine (Start() will set Running to 1)
	go client.Start(mtrProbe)

	// Wait for stop signal
	<-stopChan
	log.Infof("Stopping TrafficSim client for probe %s", probe.ID.Hex())
	stopTrafficSim(probe.ID, false)
}

func handleSystemInfoProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	log.Info("SystemInfo: Running system hardware usage test")

	interval := probe.Config.Interval
	if interval <= 0 {
		interval = 1
	}

	data, err := probes.SystemInfo()
	if err != nil {
		log.Errorf("SystemInfo error: %v", err)
	} else {
		dataChan <- probes.ProbeData{
			ProbeID: probe.ID,
			Data:    data,
		}
	}

	time.Sleep(time.Duration(interval) * time.Minute)
}

func handleMTRProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	log.Infof("MTR: Running test for %s", probe.Config.Target[0].Target)

	data, err := probes.Mtr(&probe, false)
	if err != nil {
		log.Errorf("MTR error: %v", err)
	} else {
		reportingAgent, err := primitive.ObjectIDFromHex(os.Getenv("ID"))
		if err != nil {
			log.Printf("TrafficSim: Failed to get reporting agent ID: %v", err)
			return
		}

		dataChan <- probes.ProbeData{
			ProbeID:   probe.ID,
			Triggered: false,
			Data:      data,
			Target: probes.ProbeTarget{
				Target: string(probes.ProbeType_MTR) + "%%%" + probe.Config.Target[0].Target,
				Agent:  probe.Config.Target[0].Agent,
				Group:  reportingAgent,
			},
		}
	}

	time.Sleep(time.Duration(probe.Config.Interval) * time.Minute)
}

func handleSpeedTestProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	speedTestMutex.Lock()
	defer speedTestMutex.Unlock()

	if speedTestRunning {
		return
	}

	if probe.Config.Target[0].Target == "ok" {
		log.Info("SpeedTest: Target is ok, skipping...")
		time.Sleep(10 * time.Second)
		return
	}

	log.Infof("Running speed test for %s", probe.Config.Target[0].Target)
	speedTestRunning = true

	data, err := probes.SpeedTest(&probe)
	speedTestRunning = false

	if err != nil {
		log.Errorf("SpeedTest error: %v", err)
		speedTestRetryCount++

		if speedTestRetryCount >= speedTestRetryMax {
			probe.Config.Target[0].Target = "ok"
			log.Warn("SpeedTest: Failed after max retries, setting target to 'ok'")
		}

		time.Sleep(30 * time.Second)
		return
	}

	speedTestRetryCount = 0
	probe.Config.Target[0].Target = "ok"

	dataChan <- probes.ProbeData{
		ProbeID: probe.ID,
		Data:    data,
	}
}

func handleSpeedTestServersProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	speedtestClient := speedtest.New()
	serverList, err := speedtestClient.FetchServers()
	if err != nil {
		log.Errorf("SpeedTest servers error: %v", err)
		return
	}

	dataChan <- probes.ProbeData{
		ProbeID: probe.ID,
		Data:    serverList,
	}

	time.Sleep(12 * time.Hour)
}

func handlePingProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	log.Infof("Ping: Running test for %s", probe.Config.Target[0].Target)

	mtrProbe, err := findMatchingMTRProbe(probe)
	if err != nil {
		log.Errorf("Failed to find matching MTR probe: %v", err)
	}

	if err := probes.Ping(&probe, dataChan, mtrProbe); err != nil {
		log.Errorf("Ping error: %v", err)
	}
}

func handleNetworkInfoProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	log.Info("NetInfo: Checking networking information...")

	data, err := probes.NetworkInfo()
	if err != nil {
		log.Errorf("NetworkInfo error: %v", err)
	} else {
		dataChan <- probes.ProbeData{
			ProbeID: probe.ID,
			Data:    data,
		}
	}

	time.Sleep(10 * time.Minute)
}

func updateAllowedAgents(server *probes.TrafficSim, newAllowedAgents []primitive.ObjectID) {
	server.Mutex.Lock()
	defer server.Mutex.Unlock()

	server.AllowedAgents = newAllowedAgents
	log.Infof("Updated allowed agents for TrafficSim server: %v", newAllowedAgents)
}

package workers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netwatcherio/netwatcher-agent/probes"
	"sync"
	"time"

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
	// For TrafficSim servers, we want to treat allowed agent changes as updates, not new probes
	// So we'll exclude the allowed agents from the key for server probes
	if probe.Type == probes.ProbeType_TRAFFICSIM {
		// For server probes, only include the server address/port in the key
		// This ensures that changes to allowed agents don't create a new probe
		normalizedConfig := struct {
			Target   string `json:"target"`
			Duration int    `json:"duration"`
			Count    int    `json:"count"`
			Interval int    `json:"interval"`
			Server   bool   `json:"server"`
			Pending  int64  `json:"pending"`
		}{
			Duration: probe.DurationSec,
			Count:    probe.Count,
			Interval: probe.IntervalSec,
			Server:   probe.Server,
		}

		// Only include the server address (first target) for server probes
		/*if len(probe.Target) > 0 {
			normalizedConfig.Target = fmt.Sprintf("%s|%s|%s",
				probe.Target[0].Target,
				probe.Target[0].Agent.Hex(),
				probe.Target[0].Group.Hex())
		}*/

		configBytes, err := json.Marshal(normalizedConfig)
		if err != nil {
			return fmt.Sprintf("%s_%s_error", probe.ID, probe.Type)
		}

		hash := sha256.Sum256(configBytes)
		return fmt.Sprintf("%s_%s_%x", probe.ID, probe.Type, hash[:8])
	}

	// For all other probes (including TrafficSim clients), use the original logic
	normalizedConfig := struct {
		Target   []string `json:"target"`
		Duration int      `json:"duration"`
		Count    int      `json:"count"`
		Interval int      `json:"interval"`
		Server   bool     `json:"server"`
	}{
		Target:   make([]string, 0), // todo
		Duration: probe.DurationSec,
		Count:    probe.Count,
		Interval: probe.IntervalSec,
		Server:   probe.Server,
	}

	// Create a sorted, normalized representation of targets
	/*targetStrings := make([]string, len(probe.Target))
	for i, target := range probe.Target {
		targetStrings[i] = fmt.Sprintf("%s|%s|%s", target.Target, target.Agent.Hex(), target.Group.Hex())
	}*/

	// Sort the target strings to ensure consistent ordering
	/*sort.Strings(targetStrings)
	normalizedConfig.Target = targetStrings*/

	configBytes, err := json.Marshal(normalizedConfig)
	if err != nil {
		return fmt.Sprintf("%s_%s_error", probe.ID, probe.Type)
	}

	hash := sha256.Sum256(configBytes)
	return fmt.Sprintf("%s_%s_%x", probe.ID, probe.Type, hash[:8])
}

// Alternative approach: specialized comparison for TrafficSim probes
func trafficSimConfigChanged(oldprobe, newprobe probes.Probe) bool {
	// For server probes, we need special handling
	if oldprobe.Server && newprobe.Server {
		// Check if the server address/port changed (always at index 0)
		/*if len(oldprobe.Target) > 0 && len(newprobe.Target) > 0 {
			if oldprobe.Target[0].Target != newprobe.Target[0].Target {
				return true
			}
			if oldprobe.Target[0].Agent != newprobe.Target[0].Agent {
				return true
			}
		}*/

		// For server configs, compare allowed agents regardless of order
		/*oldAgents := extractAllowedAgents(oldprobe.Target)
		newAgents := extractAllowedAgents(newprobe.Target)

		if !sameAgentSets(oldAgents, newAgents) {
			return true
		}*/

		return false
	}

	// For client probes
	if !oldprobe.Server && !newprobe.Server {
		// Check if target address/port changed
		/*if len(oldprobe.Target) > 0 && len(newprobe.Target) > 0 {
			if oldprobe.Target[0].Target != newprobe.Target[0].Target {
				return true
			}
			if oldprobe.Target[0].Agent != newprobe.Target[0].Agent {
				return true
			}
		}*/
		return false
	}

	// Server flag changed
	return oldprobe.Server != newprobe.Server
}

// Helper function to extract allowed agents from targets (skipping index 0)
func extractAllowedAgents(targets []probes.ProbeTarget) map[primitive.ObjectID]bool {
	agents := make(map[primitive.ObjectID]bool)
	/*if len(targets) > 1 {
		for i := 1; i < len(targets); i++ {
			if targets[i].AgentID != primitive.NilObjectID {
				agents[targets[i].AgentID] = true
			}
		} todo
	}*/
	return agents
}

// Helper function to compare two agent sets
func sameAgentSets(set1, set2 map[primitive.ObjectID]bool) bool {
	if len(set1) != len(set2) {
		return false
	}

	for agent := range set1 {
		if !set2[agent] {
			return false
		}
	}

	return true
}

var (
	checkWorkers syncmap.Map // Key: probeID_probeType composite key

	// Track TrafficSim instances with better synchronization
	// Note: TrafficSim tracking uses just probe ID (not composite key) since
	// there can only be one TrafficSim instance per probe ID
	/*trafficSimServer       *probes.TrafficSim
	trafficSimServerMutex  sync.RWMutex
	trafficSimClients      = make(map[primitive.ObjectID]*probes.TrafficSim)
	trafficSimClientsMutex sync.RWMutex
	*/
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
			/*for _, target := range probeWorker.probe.Target {
				for _, givenTarget := range probe.Target {
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
			}*/
		}
		return true
	})

	if !found {
		return probes.Probe{}, errors.New("no matching MTR probe found")
	}
	return foundProbe, nil
}

/*
	func trafficSimConfigChanged(oldProbe, newProbe probes.Probe) bool {
		// Check if target address/port changed
		if len(oldprobe.Target) > 0 && len(newprobe.Target) > 0 {
			if oldprobe.Target[0].Target != newprobe.Target[0].Target {
				return true
			}
			if oldprobe.Target[0].Agent != newprobe.Target[0].Agent {
				return true
			}
		}

		// Check if server flag changed
		if oldprobe.Server != newprobe.Server {
			return true
		}

		// Check if allowed agents changed for server
		if oldprobe.Server {
			// For servers, check if the number of targets changed
			if len(oldprobe.Target) != len(newprobe.Target) {
				return true
			}

			// Check if any allowed agents changed
			if len(oldprobe.Target) > 1 && len(newprobe.Target) > 1 {
				// Create maps of allowed agents
				oldAgents := make(map[primitive.ObjectID]bool)
				newAgents := make(map[primitive.ObjectID]bool)

				for i := 1; i < len(oldprobe.Target); i++ {
					if oldprobe.Target[i].Agent != primitive.NilObjectID {
						oldAgents[oldprobe.Target[i].Agent] = true
					}
				}

				for i := 1; i < len(newprobe.Target); i++ {
					if newprobe.Target[i].Agent != primitive.NilObjectID {
						newAgents[newprobe.Target[i].Agent] = true
					}
				}

				// Compare the maps
				if len(oldAgents) != len(newAgents) {
					return true
				}

				for agent := range oldAgents {
					if !newAgents[agent] {
						return true
					}
				}
			}
		}

		return false
	}
*/
/*func stopTrafficSim(probeID primitive.ObjectID, isServer bool) {
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
*/
func FetchProbesWorker(probeGetChan chan []probes.Probe, probeDataChan chan probes.ProbeData, thisAgent primitive.ObjectID) {
	go func(aC chan []probes.Probe, dC chan probes.ProbeData) {
		for {
			p := <-aC

			var newKeys []string

			for _, probe := range p {
				probeKey := makeProbeKey(probe)
				existingWorker, exists := checkWorkers.Load(probeKey)

				if !exists {
					// New probe - create worker
					log.Infof("Starting NEW worker for probe %v (type: %s)", probe.ID, probe.Type)

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
					startCheckWorker(probe, probeDataChan, thisAgent)
				} else {
					// Existing probe - check for updates
					oldWorker := existingWorker.(ProbeWorkerS)

					if probe.Type == probes.ProbeType_TRAFFICSIM {
						if trafficSimConfigChanged(oldWorker.Probe, probe) {
							// Configuration changed - restart
							log.Infof("TrafficSim probe %v (type: %s) configuration changed, restarting", probe.ID, probe.Type)

							// Stop the old worker
							stopProbeWorker(&oldWorker)

							// Stop TrafficSim instance
							//stopTrafficSim(probe.ID, oldWorker.probe.Server)

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
							log.Infof("Starting UPDATED worker for probe %v (type: %s)", probe.ID, probe.Type)
							startCheckWorker(probe, probeDataChan, thisAgent)
						} else {
							// Update probe data without restart
							oldWorker.Probe = probe
							checkWorkers.Store(probeKey, oldWorker)

							// If it's a server, update allowed agents
							if probe.Server {
								updateServerAllowedAgents(probe)
							}
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
					log.Warnf("Probe %v (type: %s) marked for removal", probeWorker.Probe.ID, probeWorker.Probe.Type)

					// Stop the worker
					stopProbeWorker(&probeWorker)

					// Stop TrafficSim if applicable
					if probeWorker.Probe.Type == probes.ProbeType_TRAFFICSIM {
						//stopTrafficSim(probeWorker.Probe.ID, probeWorker.probe.Server)
					}

					// Remove from map
					checkWorkers.Delete(key)
				}
				return true
			})
		}
	}(probeGetChan, probeDataChan)
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
			log.Debugf("Worker for probe %v (type: %s) stopped gracefully", worker.Probe.ID, worker.Probe.Type)
		case <-time.After(5 * time.Second):
			log.Warnf("Timeout waiting for worker %v (type: %s) to stop", worker.Probe.ID, worker.Probe.Type)
		}
	}
}

func updateServerAllowedAgents(probe probes.Probe) {
	// var allowedAgentsList []primitive.ObjectID todo

	// The issue is here - we need to handle the target list properly
	// The first target (index 0) contains the server address/port
	// Subsequent targets contain allowed agent IDs

	// Check if we have allowed agents in the config
	/*if len(probe.Target) > 1 {
		// Skip the first target (server address) and collect agent IDs
		for i := 1; i < len(probe.Target); i++ {
			target := probe.Target[i]
			// Only add valid agent IDs
			if target.Agent != primitive.NilObjectID {
				allowedAgentsList = append(allowedAgentsList, target.Agent)
			}
		}
	}*/

	// If no specific agents are listed, this might mean "allow all"
	// You may want to handle this case differently based on your requirements

	/*trafficSimServerMutex.Lock()
	defer trafficSimServerMutex.Unlock()

	if trafficSimServer != nil {
		updateAllowedAgents(trafficSimServer, allowedAgentsList)
		log.Infof("Updated allowed agents for server probe %s: %v", probe.ID, allowedAgentsList)
	} else {
		log.Warnf("Attempted to update allowed agents but server is nil for probe %s", probe.ID)
	}*/
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
			log.Warnf("Probe %s (type: %s) not found when starting worker", probe.ID, probe.Type)
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
				log.Infof("Worker for probe %s (type: %s) stopped by context", probe.ID, probe.Type)
				return
			case <-worker.StopChan:
				log.Infof("Worker for probe %s (type: %s) stopped by StopChan", probe.ID, probe.Type)
				return
			default:
				// Get current probe data
				workerInterface, exists := checkWorkers.Load(probeKey)
				if !exists {
					log.Warnf("Probe %s (type: %s) no longer exists", probe.ID, probe.Type)
					return
				}

				currentWorker := workerInterface.(ProbeWorkerS)
				if currentWorker.ToRemove {
					log.Infof("Probe %s (type: %s) marked for removal", probe.ID, probe.Type)
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
					log.Debugf("Skipping AGENT probe type for probe %s", probe.ID)
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
	//checkCfg := probe.Config
	//checkAddress := strings.Split(checkCfg.Target[0].Target, ":")

	/*portNum, err := strconv.Atoi(checkAddress[1])
	if err != nil {
		log.Errorf("Invalid port number: %v", err)
		return
	}*/

	/*mtrProbe, err := findMatchingMTRProbe(probe)
	if err != nil {
		log.Errorf("Failed to find matching MTR probe: %v", err)
	}
	*/
	if probe.Server {
		//handleTrafficSimServer(probe, thisAgent, checkAddress[0], portNum, stopChan)
	} else {
		//handleTrafficSimClient(probe, thisAgent, checkAddress[0], portNum, dataChan, &mtrProbe, stopChan)
	}
}

/*func handleTrafficSimServer(probe probes.Probe, thisAgent primitive.ObjectID, ipAddress string, port int, stopChan chan struct{}) {
	var allowedAgentsList []primitive.ObjectID

	// Same fix as above - properly handle the target list
	if len(probe.Target) > 1 {
		for i := 1; i < len(probe.Target); i++ {
			target := probe.Target[i]
			if target.Agent != primitive.NilObjectID {
				allowedAgentsList = append(allowedAgentsList, target.Agent)
			}
		}
	}

	trafficSimServerMutex.Lock()
	// Check if server needs to be created using atomic operations
	needNewServer := trafficSimServer == nil ||
		atomic.LoadInt32(&trafficSimServer.Running) == 0 ||
		trafficSimServer.Errored

	if needNewServer {
		trafficSimServer = &probes.TrafficSim{
			Running:                0, // Start with 0, will be set to 1 by Start()
			Errored:                false,
			IsServer:               true,
			ThisAgent:              thisAgent,
			OtherAgent:             primitive.ObjectID{},
			IPAddress:              ipAddress,
			Port:                   int64(port),
			AllowedAgents:          allowedAgentsList,
			Probe:                  &probe,
			InterfaceCheckInterval: 30 * time.Second,
		}

		log.Infof("Starting TrafficSim server on %s:%d with allowed agents: %v", ipAddress, port, allowedAgentsList)
		server := trafficSimServer
		trafficSimServerMutex.Unlock()

		// Start server in goroutine (Start() will set Running to 1)
		go server.Start(nil)

		// Wait for stop signal
		<-stopChan
		log.Infof("Stopping TrafficSim server for probe %s", probe.ID)
		stopTrafficSim(probe.ID, true)
	} else {
		// Update allowed agents for existing server
		updateAllowedAgents(trafficSimServer, allowedAgentsList)
		trafficSimServerMutex.Unlock()

		// Monitor for updates
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				// Re-check for updates periodically
				// Get the latest probe configuration
				probeKey := makeProbeKey(probe)
				if workerInterface, exists := checkWorkers.Load(probeKey); exists {
					currentWorker := workerInterface.(ProbeWorkerS)
					currentProbe := currentWorker.Probe

					// Check if allowed agents have changed
					var currentAllowedAgents []primitive.ObjectID
					if len(currentprobe.Target) > 1 {
						for i := 1; i < len(currentprobe.Target); i++ {
							target := currentprobe.Target[i]
							if target.Agent != primitive.NilObjectID {
								currentAllowedAgents = append(currentAllowedAgents, target.Agent)
							}
						}
					}

					// Update if changed
					if !equalAgentLists(allowedAgentsList, currentAllowedAgents) {
						trafficSimServerMutex.Lock()
						if trafficSimServer != nil {
							updateAllowedAgents(trafficSimServer, currentAllowedAgents)
							allowedAgentsList = currentAllowedAgents
						}
						trafficSimServerMutex.Unlock()
					}
				}
			}
		}
	}
}
*/
// Fix 3: Add helper function to compare agent lists
func equalAgentLists(a, b []primitive.ObjectID) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison
	aMap := make(map[primitive.ObjectID]bool)
	for _, id := range a {
		aMap[id] = true
	}

	for _, id := range b {
		if !aMap[id] {
			return false
		}
	}

	return true
}

/*
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
			Running:                0, // Start with 0, will be set to 1 by Start()
			Errored:                false,
			Conn:                   nil,
			ThisAgent:              thisAgent,
			OtherAgent:             probe.Target[0].Agent,
			IPAddress:              ipAddress,
			Port:                   int64(port),
			Probe:                  &probe,
			DataChan:               dataChan,
			InterfaceCheckInterval: 30 * time.Second,
		}

		trafficSimClients[probe.ID] = simClient
		client := simClient
		trafficSimClientsMutex.Unlock()

		log.Infof("Starting TrafficSim client for probe %s to %s:%d", probe.ID, ipAddress, port)

		// Start client in goroutine (Start() will set Running to 1)
		go client.Start(mtrProbe)

		// Wait for stop signal
		<-stopChan
		log.Infof("Stopping TrafficSim client for probe %s", probe.ID)
		stopTrafficSim(probe.ID, false)
	}
*/
func handleSystemInfoProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	log.Info("SystemInfo: Running system hardware usage test")

	interval := probe.IntervalSec
	if interval <= 0 {
		interval = 1
	}

	data, err := probes.SystemInfo()
	if err != nil {
		log.Errorf("SystemInfo error: %v", err)
	} else {
		marshal, err := json.Marshal(data)
		if err != nil {
			return
		}

		dataChan <- probes.ProbeData{
			ID:           probe.ID, // todo
			Type:         probes.ProbeType_SYSTEMINFO,
			Payload:      marshal,
			ProbeID:      probe.ID,
			ProbeAgentID: probe.AgentID, // probe ownership id
			CreatedAt:    time.Now(),
		}
	}

	time.Sleep(time.Duration(interval) * time.Minute)
}

func handleMTRProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	// log.Infof("MTR: Running test for %s", probe.Target[0].Target)

	data, err := probes.Mtr(&probe, false)
	if err != nil {
		log.Errorf("MTR error: %v", err)
	} else {
		//reportingAgent, err := primitive.ObjectIDFromHex("123")

		payload, err := json.Marshal(data)

		if err != nil {
			log.Printf("TrafficSim: Failed to get reporting agent ID: %v", err)
			return
		}

		dataChan <- probes.ProbeData{
			ID:           probe.ID, // todo
			Type:         probes.ProbeType_MTR,
			Payload:      payload,
			ProbeID:      probe.ID,
			ProbeAgentID: probe.AgentID, // probe ownership id
			CreatedAt:    time.Now(),
		}
	}
	time.Sleep(time.Duration(probe.IntervalSec) * time.Second)
}

func handleSpeedTestProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	speedTestMutex.Lock()
	defer speedTestMutex.Unlock()

	if speedTestRunning {
		return
	}

	/*if probe.Target[0].Target == "ok" {
		log.Info("SpeedTest: Target is ok, skipping...")
		time.Sleep(10 * time.Second)
		return
	}*/

	//log.Infof("Running speed test for %s", probe.Target[0].Target)
	speedTestRunning = true

	/*data, err := probes.SpeedTest(&probe)
	speedTestRunning = false*/

	/*if err != nil {
		log.Errorf("SpeedTest error: %v", err)
		speedTestRetryCount++

		if speedTestRetryCount >= speedTestRetryMax {
			//probe.Target[0].Target = "ok"
			log.Warn("SpeedTest: Failed after max retries, setting target to 'ok'")
		}

		time.Sleep(30 * time.Second)
		return
	}*/

	speedTestRetryCount = 0
	//probe.Target[0].Target = "ok"

	/*dataChan <- probes.ProbeData{
		ProbeID: probe.ID,
		Data:    data,
	}*/
}

func handleSpeedTestServersProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	//speedtestClient := speedtest.New()
	/*serverList, err := speedtestClient.FetchServers()
	if err != nil {
		log.Errorf("SpeedTest servers error: %v", err)
		return
	}

	dataChan <- probes.ProbeData{
		ProbeID: probe.ID,
		Payload:    serverList,
	}

	time.Sleep(12 * time.Hour)*/
}

func handlePingProbe(probe probes.Probe, dataChan chan probes.ProbeData) {
	log.Infof("Ping: Running test for %s", probe.Targets[0].Target)

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
		marshal, err := json.Marshal(data)
		if err != nil {
			return
		}

		dataChan <- probes.ProbeData{
			ID:           probe.ID, // todo
			Type:         probes.ProbeType_NETWORKINFO,
			Payload:      marshal,
			ProbeID:      probe.ID,
			ProbeAgentID: probe.AgentID, // probe ownership id
			CreatedAt:    time.Now(),
		}
	}

	time.Sleep(10 * time.Minute)
}

/*func updateAllowedAgents(server *probes.TrafficSim, newAllowedAgents []primitive.ObjectID) {
	server.Mutex.Lock()
	defer server.Mutex.Unlock()

	server.AllowedAgents = newAllowedAgents
	log.Infof("Updated allowed agents for TrafficSim server: %v", newAllowedAgents)
}*/

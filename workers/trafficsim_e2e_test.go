package workers

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// bidirProbeList returns, in controller wire format, the probes a server agent
// (2) and a client agent (5) would receive for one bidirectional VoIP
// TrafficSim test. Both run in this process, so the lists are merged.
func bidirProbeList(t *testing.T, port int) []probes.Probe {
	raw := fmt.Sprintf(`[
	  {"id": 0, "agent_id": 2, "type": "TRAFFICSIM", "enabled": true, "server": true,
	   "metadata": {"bidirectional": true, "trafficsim": {"bidirectional_server": true, "client_probe_id": 42, "client_agent_id": 5, "voip_mode": true, "interval_ms": 20, "dscp": 46}},
	   "targets": [{"target": "0.0.0.0:%[1]d", "agent_id": 5}]},
	  {"id": 0, "agent_id": 2, "type": "TRAFFICSIM", "enabled": true, "server": true,
	   "metadata": {},
	   "targets": [{"target": "0.0.0.0:%[1]d"}, {"target": "", "agent_id": 5}]},
	  {"id": 42, "agent_id": 5, "type": "TRAFFICSIM", "enabled": true,
	   "metadata": {"bidirectional": true, "trafficsim": {"bidirectional": true, "voip_mode": true, "interval_ms": 20, "dscp": 46}},
	   "targets": [{"target": "127.0.0.1:%[1]d", "agent_id": 2}]}
	]`, port)
	var list []probes.Probe
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}
	return list
}

func activeServer() *probes.TrafficSim {
	activeTrafficSimServerMu.RLock()
	defer activeTrafficSimServerMu.RUnlock()
	return activeTrafficSimServer
}

// waitForReverseTraffic waits until the server is sending reverse packets to
// agent 5 and receiving ACKs for them, attributed to client probe 42.
func waitForReverseTraffic(t *testing.T, stage string, minNewAcks int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var base = -1
	var lastID uint
	var lastSent, lastAcked int
	var lastOK bool
	for time.Now().Before(deadline) {
		if srv := activeServer(); srv != nil {
			id, sent, acked, ok := srv.ReverseSnapshot(5)
			lastID, lastSent, lastAcked, lastOK = id, sent, acked, ok
			if ok && id == 42 {
				if base < 0 {
					base = acked
				}
				if acked-base >= minNewAcks {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: no reverse-path traffic (server=%v connected=%v clientProbeID=%d sent=%d acked=%d)",
		stage, activeServer() != nil, lastOK, lastID, lastSent, lastAcked)
}

// End-to-end through the reconciler: a TrafficSim server must run reverse-path
// tests for a connected bidirectional client, and keep doing so across the
// periodic probe_get refreshes and an unrelated probe change.
func TestTrafficSimReversePathThroughReconciler(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	t.Cleanup(func() { resetWorkers(t); time.Sleep(300 * time.Millisecond) })

	port := freeUDPPort(t)
	probeCh := make(chan []probes.Probe)
	dataCh := make(chan probes.ProbeData, 4096)
	go func() {
		for range dataCh {
		}
	}()
	FetchProbesWorker(probeCh, dataCh, primitive.NewObjectID())

	list := bidirProbeList(t, port)
	probeCh <- list
	waitForReverseTraffic(t, "initial", 25)

	// Periodic refresh with an identical list (main.go sends probe_get every minute).
	probeCh <- bidirProbeList(t, port)
	waitForReverseTraffic(t, "after identical refresh", 25)

	// Unrelated probe added alongside.
	withPing := append(bidirProbeList(t, port), probes.Probe{ID: 77, AgentID: 2, Type: probes.ProbeType_PING,
		IntervalSec: 60, Targets: []probes.ProbeTarget{{Target: "127.0.0.1"}}})
	probeCh <- withPing
	waitForReverseTraffic(t, "after unrelated change", 25)
}

// Server restart while the client keeps its flow running (what happens when a
// server agent auto-updates): reverse-path testing must resume.
func TestTrafficSimReversePathResumesAfterServerRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	t.Cleanup(func() { resetWorkers(t); time.Sleep(300 * time.Millisecond) })

	port := freeUDPPort(t)
	probeCh := make(chan []probes.Probe)
	dataCh := make(chan probes.ProbeData, 4096)
	go func() {
		for range dataCh {
		}
	}()
	FetchProbesWorker(probeCh, dataCh, primitive.NewObjectID())

	full := bidirProbeList(t, port)
	probeCh <- full
	waitForReverseTraffic(t, "initial", 25)

	// Drop the server probes only (client 42 keeps sending into the void).
	clientOnly := []probes.Probe{full[2]}
	probeCh <- clientOnly
	if !eventually(t, 5*time.Second, func() bool { return activeServer() == nil }) {
		t.Fatal("server did not stop")
	}
	time.Sleep(3 * time.Second)

	// Server comes back.
	probeCh <- bidirProbeList(t, port)
	waitForReverseTraffic(t, "after server restart", 25)
}

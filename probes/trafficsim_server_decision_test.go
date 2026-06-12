package probes

import (
	"encoding/json"
	"testing"
)

// Wire-format example data: the probe list exactly as the controller emits it to
// the SERVER agent (agent 2) for a new-format bidirectional setup where client
// agent 5 owns AGENT probe 42 targeting agent 2.
const serverAgentProbeListJSON = `[
  {
    "id": 42,
    "agent_id": 2,
    "type": "MTR",
    "enabled": true,
    "metadata": {"bidirectional": true, "trafficsim": {"bidirectional": true, "voip_mode": true, "interval_ms": 20, "dscp": 46}},
    "targets": [{"target": "10.0.0.1", "agent_id": 5}]
  },
  {
    "id": 42,
    "agent_id": 2,
    "type": "PING",
    "enabled": true,
    "metadata": {"bidirectional": true, "trafficsim": {"bidirectional": true, "voip_mode": true, "interval_ms": 20, "dscp": 46}},
    "targets": [{"target": "10.0.0.1", "agent_id": 5}]
  },
  {
    "id": 0,
    "agent_id": 2,
    "type": "TRAFFICSIM",
    "enabled": true,
    "server": true,
    "metadata": {"bidirectional": true, "trafficsim": {"bidirectional_server": true, "client_probe_id": 42, "client_agent_id": 5, "voip_mode": true, "interval_ms": 20, "dscp": 46}},
    "targets": [{"target": "0.0.0.0:5005", "agent_id": 5}]
  },
  {
    "id": 0,
    "agent_id": 2,
    "type": "TRAFFICSIM",
    "enabled": true,
    "server": true,
    "metadata": {},
    "targets": [{"target": "0.0.0.0:5005"}, {"target": "", "agent_id": 5}]
  }
]`

func parseProbeList(t *testing.T, raw string) []Probe {
	t.Helper()
	var probes []Probe
	if err := json.Unmarshal([]byte(raw), &probes); err != nil {
		t.Fatalf("unmarshal example probe list: %v", err)
	}
	return probes
}

func newServerForTest(probes []Probe) *TrafficSim {
	ts := &TrafficSim{
		IsServer:    true,
		connections: make(map[uint]*AgentConnection),
	}
	ts.SetAllProbes(probes)
	return ts
}

// When client agent 5 connects, the server must enable reverse-path testing,
// attribute it to the client's probe ID from metadata (the probe itself is
// virtual with ID 0), and mirror the client's VoIP settings.
func TestInitBidirectionalFromControllerProbeList(t *testing.T) {
	ts := newServerForTest(parseProbeList(t, serverAgentProbeListJSON))

	conn := &AgentConnection{AgentID: 5}
	ts.initBidirectional(conn)

	if conn.ClientProbeID != 42 {
		t.Errorf("ClientProbeID = %d, want 42 from metadata client_probe_id (0 disables the reverse path)", conn.ClientProbeID)
	}
	if conn.ReverseCycle == nil {
		t.Error("ReverseCycle not initialized — reverse traffic will never start")
	}
	opts := conn.ReverseTrafficOptions
	if !opts.VoIPMode || opts.IntervalMs != 20 || opts.DSCPValue != 46 {
		t.Errorf("reverse traffic options don't mirror the client's VoIP settings: %+v", opts)
	}
}

// An unknown agent (no probe references it) must stay unidirectional.
func TestInitBidirectionalUnknownAgentStaysUnidirectional(t *testing.T) {
	ts := newServerForTest(parseProbeList(t, serverAgentProbeListJSON))

	conn := &AgentConnection{AgentID: 99}
	ts.initBidirectional(conn)

	if conn.ClientProbeID != 0 || conn.ReverseCycle != nil {
		t.Errorf("unknown agent got bidirectional enabled: probeID=%d cycle=%v", conn.ClientProbeID, conn.ReverseCycle)
	}
}

// A connection established BEFORE the probe list arrived must be upgraded by
// RefreshBidirectional, and a second refresh must not reset the running cycle.
func TestRefreshBidirectionalUpgradesAndIsIdempotent(t *testing.T) {
	ts := newServerForTest(nil) // no probes yet
	conn := &AgentConnection{AgentID: 5}
	ts.connections[5] = conn

	ts.RefreshBidirectional()
	if conn.ClientProbeID != 0 {
		t.Fatal("bidirectional enabled with no probes loaded")
	}

	// Probe list arrives.
	ts.SetAllProbes(parseProbeList(t, serverAgentProbeListJSON))
	ts.RefreshBidirectional()

	if conn.ClientProbeID != 42 {
		t.Fatalf("ClientProbeID = %d after refresh, want 42", conn.ClientProbeID)
	}
	if conn.ReverseCycle == nil {
		t.Fatal("ReverseCycle not initialized by refresh")
	}

	// Second refresh must not reset in-flight reverse tracking.
	firstCycle := conn.ReverseCycle
	ts.RefreshBidirectional()
	if conn.ReverseCycle != firstCycle {
		t.Error("refresh reset an already-enabled connection's reverse cycle")
	}
}

// Legacy dual-probe wire format: the server agent has its own client probe
// targeting the connecting agent (mutual servers). Reverse stats attribute to
// that probe's real ID.
func TestInitBidirectionalLegacyMutualClientProbe(t *testing.T) {
	const legacyList = `[
	  {
	    "id": 77,
	    "agent_id": 2,
	    "type": "TRAFFICSIM",
	    "enabled": true,
	    "metadata": {"trafficsim": {"bidirectional": true}},
	    "targets": [{"target": "10.0.0.1:5000", "agent_id": 5}]
	  }
	]`
	ts := newServerForTest(parseProbeList(t, legacyList))

	conn := &AgentConnection{AgentID: 5}
	ts.initBidirectional(conn)

	if conn.ClientProbeID != 77 {
		t.Errorf("ClientProbeID = %d, want 77 (the local client probe's own ID)", conn.ClientProbeID)
	}
	if conn.ReverseCycle == nil {
		t.Error("ReverseCycle not initialized for legacy mutual setup")
	}
}

// Wire-format server probe parsing: bind address, server flag, allowed agents.
func TestNewTrafficSimParsesServerProbeFromWireFormat(t *testing.T) {
	const serverProbeJSON = `{
	  "id": 0,
	  "agent_id": 2,
	  "type": "TRAFFICSIM",
	  "enabled": true,
	  "server": true,
	  "metadata": {},
	  "targets": [{"target": "0.0.0.0:5005"}, {"target": "", "agent_id": 5}, {"target": "", "agent_id": 9}]
	}`
	var p Probe
	if err := json.Unmarshal([]byte(serverProbeJSON), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ts := NewTrafficSim(&p, nil)
	if !ts.IsServer {
		t.Error("server flag not parsed")
	}
	if ts.IPAddress != "0.0.0.0" || ts.Port != 5005 {
		t.Errorf("bind address = %s:%d, want 0.0.0.0:5005", ts.IPAddress, ts.Port)
	}
	if len(ts.AllowedAgents) != 2 || ts.AllowedAgents[0] != 5 || ts.AllowedAgents[1] != 9 {
		t.Errorf("allowed agents = %v, want [5 9]", ts.AllowedAgents)
	}
}

// Wire-format client probe parsing: target attribution and bidirectional flag.
func TestNewTrafficSimParsesBidirectionalClientFromWireFormat(t *testing.T) {
	const clientProbeJSON = `{
	  "id": 42,
	  "agent_id": 1,
	  "type": "TRAFFICSIM",
	  "enabled": true,
	  "metadata": {"bidirectional": true, "trafficsim": {"bidirectional": true, "voip_mode": true, "interval_ms": 20}},
	  "targets": [{"target": "10.0.0.2:5005", "agent_id": 2}]
	}`
	var p Probe
	if err := json.Unmarshal([]byte(clientProbeJSON), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ts := NewTrafficSim(&p, nil)
	if ts.IsServer {
		t.Error("client probe parsed as server")
	}
	if ts.IPAddress != "10.0.0.2" || ts.Port != 5005 {
		t.Errorf("target = %s:%d, want 10.0.0.2:5005", ts.IPAddress, ts.Port)
	}
	if ts.OtherAgent != 2 {
		t.Errorf("OtherAgent = %d, want 2 (stats attribution target)", ts.OtherAgent)
	}
	if !ts.Options.Bidirectional || !ts.Options.VoIPMode || ts.Options.IntervalMs != 20 {
		t.Errorf("options not parsed: %+v", ts.Options)
	}
}

package workers

import (
	"testing"

	"github.com/netwatcherio/netwatcher-agent/probes"
)

func uintPtr(v uint) *uint { return &v }

// The generic server probe and the per-client bidirectional server probes are all
// virtual (ID=0) and intentionally collapse into ONE worker key — a single server
// instance handles all clients. Bidirectional detection reads the raw probe list,
// not the workers, so the collapse is safe. This test documents that contract.
func TestMakeProbeKeyServerProbesCollapse(t *testing.T) {
	generic := probes.Probe{
		ID:          0,
		Type:        probes.ProbeType_TRAFFICSIM,
		Server:      true,
		IntervalSec: 60,
		Targets: []probes.ProbeTarget{
			{Target: "0.0.0.0:5000"},
			{AgentID: uintPtr(3)},
		},
	}
	perClient := probes.Probe{
		ID:          0,
		Type:        probes.ProbeType_TRAFFICSIM,
		Server:      true,
		IntervalSec: 60,
		Targets: []probes.ProbeTarget{
			{Target: "0.0.0.0:5000", AgentID: uintPtr(7)},
		},
	}

	if makeProbeKey(generic) != makeProbeKey(perClient) {
		t.Error("server probes should share one worker key (single server instance)")
	}
}

func TestMakeProbeKeyClientProbesStayDistinct(t *testing.T) {
	mk := func(id uint, target string) probes.Probe {
		return probes.Probe{
			ID:          id,
			Type:        probes.ProbeType_TRAFFICSIM,
			IntervalSec: 60,
			Targets:     []probes.ProbeTarget{{Target: target}},
		}
	}

	if makeProbeKey(mk(1, "1.1.1.1:5000")) == makeProbeKey(mk(2, "1.1.1.1:5000")) {
		t.Error("client probes with different IDs must have distinct keys")
	}
	if makeProbeKey(mk(1, "1.1.1.1:5000")) == makeProbeKey(mk(1, "2.2.2.2:5000")) {
		t.Error("client probes with different targets must have distinct keys")
	}
}

// Regression: per-client bidirectional server probes share the worker key with the
// generic server probe, so each reconcile cycle invoked updateServerAllowedAgents
// for them too — wiping the allowed-agents list maintained by the generic probe.
func TestUpdateServerAllowedAgentsGuard(t *testing.T) {
	server := &probes.TrafficSim{AllowedAgents: []uint{1, 2}}

	activeTrafficSimServerMu.Lock()
	prev := activeTrafficSimServer
	activeTrafficSimServer = server
	activeTrafficSimServerMu.Unlock()
	defer func() {
		activeTrafficSimServerMu.Lock()
		activeTrafficSimServer = prev
		activeTrafficSimServerMu.Unlock()
	}()

	// A per-client bidirectional server probe (Target[0] carries the client agent)
	// must NOT touch the allowed list.
	updateServerAllowedAgents(probes.Probe{
		Type:   probes.ProbeType_TRAFFICSIM,
		Server: true,
		Targets: []probes.ProbeTarget{
			{Target: "0.0.0.0:5000", AgentID: uintPtr(7)},
		},
	})
	if len(server.AllowedAgents) != 2 {
		t.Errorf("per-client bidir probe wiped allowed agents: %v", server.AllowedAgents)
	}

	// The generic server probe (Target[0] is the bind address, no AgentID)
	// owns the allowed list.
	updateServerAllowedAgents(probes.Probe{
		Type:   probes.ProbeType_TRAFFICSIM,
		Server: true,
		Targets: []probes.ProbeTarget{
			{Target: "0.0.0.0:5000"},
			{AgentID: uintPtr(3)},
			{AgentID: uintPtr(4)},
		},
	})
	if len(server.AllowedAgents) != 2 || server.AllowedAgents[0] != 3 || server.AllowedAgents[1] != 4 {
		t.Errorf("generic server probe should replace allowed agents, got %v", server.AllowedAgents)
	}
}

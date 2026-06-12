package probes

import (
	"encoding/json"
	"testing"
)

func tsMetadata(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	return b
}

func TestExtractVoIPOptionsParsesBidirectionalServerFields(t *testing.T) {
	md := tsMetadata(t, map[string]any{
		"bidirectional": true,
		"trafficsim": map[string]any{
			"bidirectional_server": true,
			"client_probe_id":      float64(42),
			"client_agent_id":      float64(7),
			"voip_mode":            true,
			"interval_ms":          float64(20),
			"dscp":                 float64(46),
		},
	})

	opts := extractVoIPOptions(md)

	if !opts.Bidirectional {
		t.Error("Bidirectional not parsed from top-level flag")
	}
	if !opts.BidirectionalServer {
		t.Error("BidirectionalServer not parsed")
	}
	if opts.ClientProbeID != 42 {
		t.Errorf("ClientProbeID = %d, want 42", opts.ClientProbeID)
	}
	if opts.ClientAgentID != 7 {
		t.Errorf("ClientAgentID = %d, want 7", opts.ClientAgentID)
	}
	if !opts.VoIPMode || opts.IntervalMs != 20 || opts.DSCPValue != 46 {
		t.Errorf("VoIP settings not parsed: %+v", opts)
	}
}

// Regression: the legacy bidirectional_receiver marker was parsed by NewTrafficSim
// but NOT by extractVoIPOptions, so GetClientProbeForAgent could never match
// legacy receiver probes.
func TestExtractVoIPOptionsParsesLegacyReceiver(t *testing.T) {
	md := tsMetadata(t, map[string]any{
		"trafficsim": map[string]any{
			"bidirectional_receiver": true,
			"client_probe_id":        float64(42),
			"client_agent_id":        float64(7),
		},
	})

	opts := extractVoIPOptions(md)
	if !opts.BidirectionalReceiver {
		t.Error("legacy bidirectional_receiver not parsed")
	}
	if opts.ClientProbeID != 42 || opts.ClientAgentID != 7 {
		t.Errorf("client ids not parsed: %+v", opts)
	}
}

// Regression: NewTrafficSim infers VoIP mode from interval_ms <= 50, but
// extractVoIPOptions didn't — the server's reverse traffic paced differently
// from the client's forward traffic.
func TestExtractVoIPOptionsInfersVoIPFromFastInterval(t *testing.T) {
	md := tsMetadata(t, map[string]any{
		"trafficsim": map[string]any{
			"interval_ms": float64(20), // fast interval, voip_mode NOT set
		},
	})

	opts := extractVoIPOptions(md)
	if !opts.VoIPMode {
		t.Error("VoIP mode not inferred from interval_ms <= 50")
	}
	if opts.PayloadSize != VoIPPayloadSize {
		t.Errorf("PayloadSize = %d, want VoIP default %d", opts.PayloadSize, VoIPPayloadSize)
	}
	if opts.PacketsPerSec != 1000/20 {
		t.Errorf("PacketsPerSec = %d, want %d", opts.PacketsPerSec, 1000/20)
	}
}

func TestExtractVoIPOptionsEmptyMetadataDefaults(t *testing.T) {
	opts := extractVoIPOptions(nil)
	if opts.VoIPMode || opts.Bidirectional || opts.BidirectionalServer || opts.BidirectionalReceiver {
		t.Errorf("unexpected flags from empty metadata: %+v", opts)
	}
	if opts.IntervalMs != TrafficSimDataInterval {
		t.Errorf("IntervalMs = %d, want default %d", opts.IntervalMs, TrafficSimDataInterval)
	}
}

// Regression: the dynamically generated bidirectional server probe is virtual
// (ID=0); the client's real probe ID rides in metadata. Using the probe's own
// ID set ClientProbeID=0, which every reverse-path gate treats as "disabled".
func TestResolveClientProbeID(t *testing.T) {
	cases := []struct {
		name  string
		probe Probe
		opts  TrafficSimOptions
		want  uint
	}{
		{
			name:  "virtual bidir server probe uses metadata client_probe_id",
			probe: Probe{ID: 0, Server: true},
			opts:  TrafficSimOptions{BidirectionalServer: true, ClientProbeID: 42},
			want:  42,
		},
		{
			name:  "legacy receiver probe uses metadata client_probe_id",
			probe: Probe{ID: 9, Server: true},
			opts:  TrafficSimOptions{BidirectionalReceiver: true, ClientProbeID: 42},
			want:  42,
		},
		{
			name:  "real client probe uses its own ID",
			probe: Probe{ID: 7},
			opts:  TrafficSimOptions{Bidirectional: true},
			want:  7,
		},
		{
			name:  "server probe without metadata id falls back to own ID",
			probe: Probe{ID: 5, Server: true},
			opts:  TrafficSimOptions{BidirectionalServer: true},
			want:  5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveClientProbeID(&tc.probe, tc.opts); got != tc.want {
				t.Errorf("resolveClientProbeID() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestShouldEnableBidirectional(t *testing.T) {
	bidirMD := tsMetadata(t, map[string]any{"bidirectional": true})

	if !shouldEnableBidirectional(&Probe{Metadata: bidirMD}) {
		t.Error("metadata bidirectional flag not honored (new format)")
	}
	if !shouldEnableBidirectional(&Probe{
		Targets: []ProbeTarget{{Target: "1.2.3.4:bidir"}},
	}) {
		t.Error(":bidir target suffix not honored (legacy format)")
	}
	if shouldEnableBidirectional(&Probe{
		Targets: []ProbeTarget{{Target: "1.2.3.4:5000"}},
	}) {
		t.Error("plain probe should not enable bidirectional")
	}
	if shouldEnableBidirectional(nil) {
		t.Error("nil probe should not enable bidirectional")
	}
}

func TestGetClientProbeForAgent(t *testing.T) {
	clientAgent := uint(5)

	bidirClientMD := tsMetadata(t, map[string]any{
		"bidirectional": true,
		"trafficsim":    map[string]any{"bidirectional": true},
	})
	bidirServerMD := tsMetadata(t, map[string]any{
		"bidirectional": true,
		"trafficsim": map[string]any{
			"bidirectional_server": true,
			"client_probe_id":      float64(42),
			"client_agent_id":      float64(clientAgent),
		},
	})

	t.Run("matches local client probe targeting the agent (mutual servers)", func(t *testing.T) {
		ts := &TrafficSim{}
		ts.SetAllProbes([]Probe{{
			ID:       7,
			Type:     ProbeType_TRAFFICSIM,
			Metadata: bidirClientMD,
			Targets:  []ProbeTarget{{Target: "1.2.3.4:5000", AgentID: &clientAgent}},
		}})
		p := ts.GetClientProbeForAgent(clientAgent)
		if p == nil || p.ID != 7 {
			t.Fatalf("got %+v, want client probe 7", p)
		}
	})

	t.Run("matches virtual bidirectional server probe by client_agent_id", func(t *testing.T) {
		ts := &TrafficSim{}
		ts.SetAllProbes([]Probe{{
			ID:       0,
			Type:     ProbeType_TRAFFICSIM,
			Server:   true,
			Metadata: bidirServerMD,
			Targets:  []ProbeTarget{{Target: "0.0.0.0:5000", AgentID: &clientAgent}},
		}})
		p := ts.GetClientProbeForAgent(clientAgent)
		if p == nil {
			t.Fatal("bidirectional server probe not matched")
		}
		if got := resolveClientProbeID(p, extractVoIPOptions(p.Metadata)); got != 42 {
			t.Errorf("resolved client probe ID = %d, want 42 from metadata", got)
		}
	})

	t.Run("no match for unrelated agent or non-bidirectional probe", func(t *testing.T) {
		ts := &TrafficSim{}
		ts.SetAllProbes([]Probe{{
			ID:      7,
			Type:    ProbeType_TRAFFICSIM,
			Targets: []ProbeTarget{{Target: "1.2.3.4:5000", AgentID: &clientAgent}},
			// no bidirectional metadata
		}})
		if p := ts.GetClientProbeForAgent(clientAgent); p != nil {
			t.Errorf("non-bidirectional client probe should not match, got %+v", p)
		}
		if p := ts.GetClientProbeForAgent(999); p != nil {
			t.Errorf("unrelated agent should not match, got %+v", p)
		}
	})
}

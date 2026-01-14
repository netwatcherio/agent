package probes

import (
	"encoding/json"
	"time"
)

type Probe struct {
	ID          uint      `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	WorkspaceId int       `json:"workspace_id"`
	AgentID     uint      `json:"agent_id"`
	Type        ProbeType `json:"type"`
	Enabled     bool      `json:"enabled"`
	IntervalSec int       `json:"interval_sec"`
	TimeoutSec  int       `json:"timeout_sec"`
	Count       int       `json:"count"`
	DurationSec int       `json:"duration_sec"`
	Server      bool      `json:"server"`
	Labels      struct {
	} `json:"labels"`
	Metadata struct {
	} `json:"metadata"`
	// For bidirectional TrafficSim: the probe ID to use when reporting reverse direction stats
	ReverseProbeID *uint         `json:"reverse_probe_id,omitempty"`
	Targets        []ProbeTarget `json:"targets"`
	ProbeProcess   int
}

type ProbeTarget struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ProbeId   int       `json:"probe_id"`
	Target    string    `gorm:"size:512" json:"target"` // ip/host[:port] (leave empty when AgentID is set)
	AgentID   *uint     `gorm:"index" json:"agent_id"`  // target agent
	GroupID   *uint     `gorm:"index" json:"group_id"`  // optional grouping/batching
}

type ProbeType string

const (
	ProbeType_RPERF             ProbeType = "RPERF"
	ProbeType_MTR               ProbeType = "MTR"
	ProbeType_PING              ProbeType = "PING"
	ProbeType_SPEEDTEST         ProbeType = "SPEEDTEST"
	ProbeType_SPEEDTEST_SERVERS ProbeType = "SPEEDTEST_SERVERS"
	ProbeType_NETWORKINFO       ProbeType = "NETINFO"
	ProbeType_SYSTEMINFO        ProbeType = "SYSINFO"
	ProbeType_TRAFFICSIM        ProbeType = "TRAFFICSIM"
	ProbeType_WEB               ProbeType = "WEB"
	ProbeType_DNS               ProbeType = "DNS"
)

// ProbeData What the agent posts (flattened main-level fields + kind + raw payload)
type ProbeData struct {
	ProbeID         uint      `json:"probe_id"`
	Triggered       bool      `json:"triggered"`
	TriggeredReason string    `json:"triggered_reason"`
	CreatedAt       time.Time `json:"created_at"` // this is the timestamp that the agent provides
	// ReceivedAt       time.Time       `json:"received_at"` // this is the timestamp the backend provides
	Type    ProbeType       `json:"type"`
	Payload json.RawMessage `json:"payload"`
	// Optional: carry target string if you still resolve AGENT types dynamically
	Target      string `json:"target,omitempty"`
	TargetAgent uint   `json:"target_agent,omitempty"`
}

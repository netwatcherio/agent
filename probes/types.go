package probes

import (
	"encoding/json"
	"time"
)

type Probe struct {
	ID          uint      `json:"id"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	WorkspaceId int       `json:"workspaceId"`
	AgentID     uint      `json:"agentID"`
	Type        ProbeType `json:"type"`
	Enabled     bool      `json:"enabled"`
	IntervalSec int       `json:"intervalSec"`
	TimeoutSec  int       `json:"timeoutSec"`
	Count       int       `json:"count"`
	DurationSec int       `json:"durationSec"`
	Server      bool      `json:"server"`
	Labels      struct {
	} `json:"labels"`
	Metadata struct {
	} `json:"metadata"`
	Targets      []ProbeTarget `json:"targets"`
	ProbeProcess int
}

type ProbeTarget struct {
	ID        int         `json:"id"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt time.Time   `json:"updatedAt"`
	ProbeId   int         `json:"probeId"`
	Target    string      `json:"target"`
	AgentId   interface{} `json:"agentId"`
	GroupId   interface{} `json:"groupId"`
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
	ID              uint      `json:"id"`
	ProbeID         uint      `json:"probe_id"`
	ProbeAgentID    uint      `json:"probe_agent_id"` // probe ID owner - used for reverse probes
	Triggered       bool      `json:"triggered"`
	TriggeredReason string    `json:"triggered_reason"`
	CreatedAt       time.Time `json:"created_at"` // this is the timestamp that the agent provides
	// ReceivedAt       time.Time       `json:"received_at"` // this is the timestamp the backend provides
	Type    ProbeType       `json:"type"`
	Payload json.RawMessage `json:"payload"`
	// Optional: carry target string if you still resolve AGENT types dynamically
	Target      string `json:"target,omitempty"`
	TargetAgent uint   `json:"targetAgent,omitempty"`
}

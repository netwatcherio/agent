package probes

import (
	"time"
)

type Probe struct {
	ID          uint      `json:"id"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	WorkspaceId int       `json:"workspaceId"`
	AgentId     int       `json:"agentId"`
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

type ProbeData struct {
	ID        uint        `json:"id"bson:"_id"`
	ProbeID   uint        `json:"probe"bson:"probe"`
	Triggered bool        `json:"triggered"bson:"triggered"`
	CreatedAt time.Time   `bson:"createdAt"json:"createdAt"`
	UpdatedAt time.Time   `bson:"updatedAt"json:"updatedAt"`
	Data      interface{} `json:"data,omitempty"bson:"data,omitempty"`
	Target    ProbeTarget `bson:"target" json:"target"`
}

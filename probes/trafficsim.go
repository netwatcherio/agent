package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// -------------------- Constants --------------------

const (
	TrafficSimReportSeq        = 60   // Packets per cycle before reporting (legacy 1-second interval mode)
	TrafficSimDataInterval     = 1000 // Milliseconds between packets (default 1 second)
	TrafficSimTimeout          = 2 * time.Second
	TrafficSimRetryInterval    = 5 * time.Second
	TrafficSimGracefulShutdown = 70 * time.Second

	// VoIP simulation constants (G.711-like) - configurable via probe options
	VoIPDataInterval = 20  // Milliseconds between packets (50 pps, matches G.711)
	VoIPPayloadSize  = 160 // Bytes (matches G.711 PCM payload)
	VoIPBitrate      = 64000
	VoIPClockRate    = 8000

	// VoIP reporting: report every 60 seconds worth of data
	// At 50 pps × 60 sec = 3000 packets per report cycle
	VoIPReportIntervalSec = 60

	// DSCP markings (for QoS simulation)
	DSCPDefault = 0  // Best effort
	DSCPEF      = 46 // Expedited Forwarding (voice traffic)
	DSCPAf41    = 34 // High priority, low loss (video)
)

// -------------------- Message Types --------------------

type TrafficSimMsgType string

const (
	MsgHello  TrafficSimMsgType = "HELLO"
	MsgAck    TrafficSimMsgType = "ACK"
	MsgData   TrafficSimMsgType = "DATA"
	MsgReport TrafficSimMsgType = "REPORT"
	MsgPing   TrafficSimMsgType = "PING"
	MsgPong   TrafficSimMsgType = "PONG"
)

// TrafficSimMsg is the UDP message structure
type TrafficSimMsg struct {
	Type      TrafficSimMsgType `json:"type"`
	Data      TrafficSimData    `json:"data"`
	SrcAgent  uint              `json:"src_agent"`
	DstAgent  uint              `json:"dst_agent"`
	Timestamp int64             `json:"timestamp"`
	Size      int               `json:"size"`
}

// TrafficSimData is the payload within each message
type TrafficSimData struct {
	Sent     int64                  `json:"sent"`
	Received int64                  `json:"received"`
	Seq      int                    `json:"seq"`
	Report   map[string]interface{} `json:"report,omitempty"`
}

// -------------------- Packet Tracking --------------------

type PacketTime struct {
	Sent     int64
	Received int64
	TimedOut bool
	Size     int
}

// CycleTracker tracks packets for a reporting cycle
type CycleTracker struct {
	StartSeq        int
	EndSeq          int
	PacketSeqs      []int
	StartTime       time.Time
	PacketTimes     map[int]PacketTime
	lastReceivedSeq int         // Last received sequence number for out-of-order detection
	outOfOrder      int         // Count of packets received out of order
	duplicates      int         // Count of duplicate packets received
	receivedSeqs    map[int]int // Track how many times each seq was received
	mu              sync.RWMutex

	// Burst loss tracking (VoIP quality assessment)
	consecutiveLoss    int // Current streak of consecutive lost packets
	maxConsecutiveLoss int // Maximum burst loss encountered
	totalBursts        int // Number of distinct burst loss events

	// RFC 3550 jitter calculation
	lastTransit     int64   // Last transit time (R - S) for RFC 3550 jitter
	lastArrivalTime int64   // Last packet arrival time (R)
	lastSentTime    int64   // Last packet sent time (S)
	rfc3550Jitter   float64 // Smoothed jitter in microseconds
}

// ClientStats tracks client-side statistics
type ClientStats struct {
	PacketTimes map[int]PacketTime
	mu          sync.RWMutex
}

// -------------------- TrafficSim Main Struct --------------------

// TrafficSimOptions holds configurable options for traffic simulation
type TrafficSimOptions struct {
	VoIPMode      bool // Enable VoIP simulation mode (20ms interval, 160-byte payload)
	PayloadSize   int  // Fixed payload size (0 = variable JSON)
	DSCPValue     int  // DSCP marking value (0-63, 46 for EF/voice)
	IntervalMs    int  // Packet interval in milliseconds
	PacketsPerSec int  // Computed from IntervalMs
	Bidirectional bool // Enable bidirectional mode (client also receives reverse traffic)

	// Bidirectional server (server side): this probe tells server to enable reverse
	BidirectionalServer   bool // True if this probe is for the server to enable bidirectional
	BidirectionalReceiver bool // True if this probe is a bidirectional receiver for the server (legacy)
	ClientProbeID         uint // The client probe ID for attribution
	ClientAgentID         uint // The client agent ID that will connect
}

// TrafficSim handles UDP traffic simulation between agents
type TrafficSim struct {
	// State management (atomic for thread safety)
	running  int32
	stopping int32

	// Identity
	ThisAgent  uint // This agent's ID
	OtherAgent uint // Target agent's ID

	// Connection
	conn   *net.UDPConn
	connMu sync.RWMutex

	// Target
	IPAddress string
	Port      int64
	IsServer  bool

	// Simulation options
	Options TrafficSimOptions

	// Server mode: allowed agents
	AllowedAgents   []uint
	allowedAgentsMu sync.RWMutex
	connections     map[uint]*AgentConnection
	connectionsMu   sync.RWMutex

	// Statistics
	clientStats  *ClientStats
	lastResponse time.Time
	sequence     int
	sequenceMu   sync.Mutex

	// Cycle tracking
	currentCycle   *CycleTracker
	cycleMu        sync.RWMutex
	packetsInCycle int

	// Control
	DataChan chan ProbeData
	Probe    *Probe
	stopChan chan struct{}
	wg       sync.WaitGroup

	// Connection validity
	connectionValid   bool
	connectionValidMu sync.RWMutex
	boundLocalIP      string // IP captured from conn.LocalAddr() after dial — used to detect stale sockets
	boundLocalIPMu    sync.RWMutex

	// Bidirectional mode: server sends test data back to connected clients
	// When a client connects, if this agent has a TRAFFICSIM client probe targeting that agent,
	// we use the existing connection to measure reverse direction and report with that probe's ID
	allProbes         []Probe // All probes for this agent to find client probes
	allProbesMu       sync.RWMutex
	GetProbesFunc     func() []Probe // Callback to dynamically get current probes
	reverseSequence   int
	reverseSequenceMu sync.Mutex
}

// AgentConnection tracks a client connection on server side
type AgentConnection struct {
	AgentID     uint
	Addr        *net.UDPAddr
	LastSeen    time.Time
	FirstSeen   time.Time
	PacketsRecv int
	PacketsSent int

	// Reverse direction tracking (for bidirectional mode)
	// ClientProbeID is the ID of the client's TrafficSim probe targeting this agent
	// When bidirectional=true, server reports reverse stats using ClientProbeID (same probe ID)
	// but with SrcAgent = this server's ID to indicate reverse direction
	ClientProbeID   uint
	ReverseCycle    *CycleTracker
	// PrevReverseCycle holds the most recently completed cycle so ACKs that
	// arrive after rotation still land in the right cycle (routed by seq).
	PrevReverseCycle *CycleTracker
	ReverseSequence  int
	LastReportTime   time.Time

	// ReverseTrafficOptions stores the client's VoIP settings for reverse traffic
	ReverseTrafficOptions TrafficSimOptions
}

// -------------------- Constructor --------------------

// NewTrafficSim creates a new TrafficSim instance
func NewTrafficSim(probe *Probe, dataChan chan ProbeData) *TrafficSim {
	ts := &TrafficSim{
		Probe:         probe,
		DataChan:      dataChan,
		AllowedAgents: make([]uint, 0),
		connections:   make(map[uint]*AgentConnection),
		clientStats:   &ClientStats{PacketTimes: make(map[int]PacketTime)},
	}

	ts.Options = TrafficSimOptions{
		VoIPMode:    false,
		PayloadSize: 0,
		DSCPValue:   DSCPDefault,
		IntervalMs:  TrafficSimDataInterval,
	}

	// Parse VoIP mode and other options from probe metadata
	// Support both nested format (trafficsim: {voip_mode, dscp, ...}) and flat format for flexibility
	if len(probe.Metadata) > 0 {
		var metadata map[string]interface{}
		if err := json.Unmarshal(probe.Metadata, &metadata); err == nil {
			// First, check for nested trafficsim config (from AGENT probe inheritance)
			var tsConfig map[string]interface{}
			if tc, ok := metadata["trafficsim"].(map[string]interface{}); ok {
				tsConfig = tc
			} else {
				// Fall back to top-level for direct TRAFFICSIM probes
				tsConfig = metadata
			}

			// Parse VoIP mode
			if voipMode, ok := tsConfig["voip_mode"]; ok {
				if b, ok := voipMode.(bool); ok {
					ts.Options.VoIPMode = b
				}
			}
			// Parse payload size
			if payloadSize, ok := tsConfig["payload_size"]; ok {
				if f, ok := payloadSize.(float64); ok {
					ts.Options.PayloadSize = int(f)
				}
			}
			// Parse DSCP value
			if dscp, ok := tsConfig["dscp"]; ok {
				if f, ok := dscp.(float64); ok {
					ts.Options.DSCPValue = int(f)
				}
			}
			// Parse interval
			if intervalMs, ok := tsConfig["interval_ms"]; ok {
				if f, ok := intervalMs.(float64); ok {
					ts.Options.IntervalMs = int(f)
				}
			}
			// Parse bidirectional flag
			if bidirectional, ok := tsConfig["bidirectional"]; ok {
				if b, ok := bidirectional.(bool); ok {
					ts.Options.Bidirectional = b
				}
			}
			// Parse bidirectional server mode (for server side)
			if bidirServer, ok := tsConfig["bidirectional_server"]; ok {
				if b, ok := bidirServer.(bool); ok {
					ts.Options.BidirectionalServer = b
				}
			}
			// Parse bidirectional receiver fields (for server side - legacy)
			if bidirRecv, ok := tsConfig["bidirectional_receiver"]; ok {
				if b, ok := bidirRecv.(bool); ok {
					ts.Options.BidirectionalReceiver = b
				}
			}
			if clientProbeID, ok := tsConfig["client_probe_id"]; ok {
				if f, ok := clientProbeID.(float64); ok {
					ts.Options.ClientProbeID = uint(f)
				}
			}
			if clientAgentID, ok := tsConfig["client_agent_id"]; ok {
				if f, ok := clientAgentID.(float64); ok {
					ts.Options.ClientAgentID = uint(f)
				}
			}
		}
	}

	// Apply VoIP defaults if enabled or inferred from interval
	// If interval is <= 50ms (50 pps or faster), treat as VoIP mode
	if ts.Options.VoIPMode || (ts.Options.IntervalMs > 0 && ts.Options.IntervalMs <= 50) {
		ts.Options.VoIPMode = true // Ensure VoIP mode is set for <= 50ms intervals
		if ts.Options.PayloadSize == 0 {
			ts.Options.PayloadSize = VoIPPayloadSize
		}
		if ts.Options.IntervalMs == TrafficSimDataInterval {
			ts.Options.IntervalMs = VoIPDataInterval
		}
	}
	ts.Options.PacketsPerSec = 1000 / ts.Options.IntervalMs

	// Parse probe configuration
	if probe.Server {
		ts.IsServer = true
	}

	// Get target from probe targets
	if len(probe.Targets) > 0 {
		target := probe.Targets[0]
		if target.AgentID != nil {
			ts.OtherAgent = *target.AgentID
		}
		if target.Target != "" {
			ts.parseTarget(target.Target)
		}
	}

	// For server mode, additional targets are allowed agents
	if ts.IsServer && len(probe.Targets) > 1 {
		for i := 1; i < len(probe.Targets); i++ {
			if probe.Targets[i].AgentID != nil {
				ts.AllowedAgents = append(ts.AllowedAgents, *probe.Targets[i].AgentID)
			}
		}
	}

	return ts
}

func (ts *TrafficSim) parseTarget(target string) {
	// Parse "IP:PORT" format
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		ts.IPAddress = target[:idx]
		if port, err := strconv.ParseInt(target[idx+1:], 10, 64); err == nil {
			ts.Port = port
		}
	} else {
		ts.IPAddress = target
		ts.Port = 5000 // Default port
	}
}

// -------------------- State Management --------------------

func (ts *TrafficSim) isRunning() bool {
	return atomic.LoadInt32(&ts.running) == 1
}

func (ts *TrafficSim) isStopping() bool {
	return atomic.LoadInt32(&ts.stopping) == 1
}

func (ts *TrafficSim) getConn() *net.UDPConn {
	ts.connMu.RLock()
	defer ts.connMu.RUnlock()
	return ts.conn
}

func (ts *TrafficSim) setConn(conn *net.UDPConn) {
	ts.connMu.Lock()
	defer ts.connMu.Unlock()
	if ts.conn != nil && ts.conn != conn {
		ts.conn.Close()
	}
	ts.conn = conn
	ts.setConnectionValid(conn != nil)
}

func (ts *TrafficSim) isConnectionValid() bool {
	ts.connectionValidMu.RLock()
	defer ts.connectionValidMu.RUnlock()
	return ts.connectionValid
}

func (ts *TrafficSim) setConnectionValid(valid bool) {
	ts.connectionValidMu.Lock()
	defer ts.connectionValidMu.Unlock()
	ts.connectionValid = valid
}

// IsRunning returns true if this TrafficSim instance is active.
// Exported for use by the interface watcher callback.
func (ts *TrafficSim) IsRunning() bool {
	return ts.isRunning()
}

// InvalidateConnection marks the current UDP socket as invalid, forcing
// reconnection on the next send cycle. Called by the interface watcher
// when a network change (gateway/interface IP change) is detected.
func (ts *TrafficSim) InvalidateConnection() {
	ts.setConnectionValid(false)
}

func (ts *TrafficSim) setBoundLocalIP(ip string) {
	ts.boundLocalIPMu.Lock()
	defer ts.boundLocalIPMu.Unlock()
	ts.boundLocalIP = ip
}

func (ts *TrafficSim) getBoundLocalIP() string {
	ts.boundLocalIPMu.RLock()
	defer ts.boundLocalIPMu.RUnlock()
	return ts.boundLocalIP
}

// isBoundIPValid checks whether the IP our socket is bound to is still
// assigned to any active network interface. If it isn't, the socket is stale
// (the interface went down, changed IP, or was removed) and must be reconnected.
//
// This is the deterministic replacement for loss-based heuristics:
// - UDP is connectionless, so writes to a dead interface "succeed" silently
// - conn.LocalAddr() tells us exactly which IP the socket is using
// - If that IP vanished from the interface list, the socket is guaranteed stale
func (ts *TrafficSim) isBoundIPValid() bool {
	boundIP := ts.getBoundLocalIP()
	if boundIP == "" {
		return true // No bound IP recorded, skip this check
	}

	return isLocalIPActive(boundIP)
}

// isLocalIPActive checks if the given IP address is currently assigned to any
// active (UP) network interface on this host. Used by probes to validate
// socket health after network changes.
func isLocalIPActive(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true // Can't check, assume valid to avoid false reconnects
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return true // Couldn't parse, assume valid
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipNet.IP.Equal(targetIP) {
			return true // IP is still assigned to an active interface
		}
	}

	return false // IP not found on any interface — socket is stale
}

// SetAllProbes stores all probes for this agent, enabling bidirectional detection
// When a client connects, the server can check if it has a client probe for that agent
func (ts *TrafficSim) SetAllProbes(probes []Probe) {
	ts.allProbesMu.Lock()
	defer ts.allProbesMu.Unlock()
	ts.allProbes = probes
	log.Infof("[trafficsim] Server loaded %d probes for bidirectional detection", len(probes))
}

// UpdateAllowedAgents replaces the allowed agents list on a running server.
// This is called when the probe reconciliation delivers updated targets.
func (ts *TrafficSim) UpdateAllowedAgents(agents []uint) {
	ts.allowedAgentsMu.Lock()
	defer ts.allowedAgentsMu.Unlock()
	old := ts.AllowedAgents
	ts.AllowedAgents = agents
	log.Infof("[trafficsim] Updated allowed agents: %v -> %v", old, agents)
}

// initBidirectional checks if this server has a TRAFFICSIM client probe for the
// connected agent and, if so, (re)initializes reverse-direction tracking.
// Must be called with ts.connectionsMu held.
func (ts *TrafficSim) initBidirectional(connection *AgentConnection) {
	clientProbe := ts.GetClientProbeForAgent(connection.AgentID)
	if clientProbe != nil {
		// Extract client's VoIP settings from metadata for reverse traffic
		connection.ReverseTrafficOptions = extractVoIPOptions(clientProbe.Metadata)

		// Enable bidirectional reverse traffic if:
		// 1. NEW: The bidirectional flag is set in metadata
		// 2. LEGACY: The target has ":bidir" suffix (dual-probe approach)
		if shouldEnableBidirectional(clientProbe) {
			connection.ClientProbeID = resolveClientProbeID(clientProbe, connection.ReverseTrafficOptions)
			connection.ReverseCycle = &CycleTracker{
				StartSeq:     1,
				StartTime:    time.Now(),
				PacketSeqs:   make([]int, 0, TrafficSimReportSeq),
				PacketTimes:  make(map[int]PacketTime),
				receivedSeqs: make(map[int]int),
			}
			log.Infof("[trafficsim] Bidirectional mode ENABLED for agent %d using client probe %d (VoIP: %v, DSCP: %d, Interval: %dms, BiDir flag: %v)",
				connection.AgentID, connection.ClientProbeID, connection.ReverseTrafficOptions.VoIPMode,
				connection.ReverseTrafficOptions.DSCPValue, connection.ReverseTrafficOptions.IntervalMs,
				connection.ReverseTrafficOptions.Bidirectional)
		} else {
			// No bidirectional flag - this is a unidirectional probe
			connection.ClientProbeID = 0
			connection.ReverseCycle = nil
			log.Infof("[trafficsim] Unidirectional probe for agent %d - reverse disabled (no bidirectional flag)",
				connection.AgentID)
		}
	} else {
		// No client probe found
		connection.ClientProbeID = 0
		connection.ReverseCycle = nil
		connection.ReverseTrafficOptions = TrafficSimOptions{}
		log.Infof("[trafficsim] Bidirectional mode DISABLED for agent %d - no client probe found", connection.AgentID)
	}
}

// extractVoIPOptions extracts VoIP/trafficsim options from probe metadata
func extractVoIPOptions(metadata json.RawMessage) TrafficSimOptions {
	opts := TrafficSimOptions{
		VoIPMode:      false,
		DSCPValue:     DSCPDefault,
		IntervalMs:    TrafficSimDataInterval,
		Bidirectional: false,
	}

	if len(metadata) == 0 {
		return opts
	}

	var metadataMap map[string]interface{}
	if err := json.Unmarshal(metadata, &metadataMap); err != nil {
		return opts
	}

	// Check for top-level bidirectional flag first (new format)
	// This is the primary flag going forward
	if bidir, ok := metadataMap["bidirectional"]; ok {
		if b, ok := bidir.(bool); ok && b {
			opts.Bidirectional = true
		}
	}

	// Check for nested trafficsim config (legacy/backward compat)
	var tsConfig map[string]interface{}
	if tc, ok := metadataMap["trafficsim"].(map[string]interface{}); ok {
		tsConfig = tc
	} else {
		tsConfig = metadataMap // Fall back to top-level for legacy
	}

	// Parse VoIP mode
	if voipMode, ok := tsConfig["voip_mode"]; ok {
		if b, ok := voipMode.(bool); ok {
			opts.VoIPMode = b
		}
	}
	// Parse DSCP value
	if dscp, ok := tsConfig["dscp"]; ok {
		if f, ok := dscp.(float64); ok {
			opts.DSCPValue = int(f)
		}
	}
	// Parse interval
	if intervalMs, ok := tsConfig["interval_ms"]; ok {
		if f, ok := intervalMs.(float64); ok {
			opts.IntervalMs = int(f)
		}
	}
	// Parse payload size
	if payloadSize, ok := tsConfig["payload_size"]; ok {
		if f, ok := payloadSize.(float64); ok {
			opts.PayloadSize = int(f)
		}
	}
	// Parse bidirectional flag (only if top-level not already set)
	if !opts.Bidirectional {
		if bidirectional, ok := tsConfig["bidirectional"]; ok {
			if b, ok := bidirectional.(bool); ok {
				opts.Bidirectional = b
			}
		}
	}
	// Parse bidirectional server fields (for GetClientProbeForAgent search)
	if bidirServer, ok := tsConfig["bidirectional_server"]; ok {
		if b, ok := bidirServer.(bool); ok {
			opts.BidirectionalServer = b
		}
	}
	// Legacy bidirectional receiver marker (dual-probe approach)
	if bidirRecv, ok := tsConfig["bidirectional_receiver"]; ok {
		if b, ok := bidirRecv.(bool); ok {
			opts.BidirectionalReceiver = b
		}
	}
	if clientProbeID, ok := tsConfig["client_probe_id"]; ok {
		if f, ok := clientProbeID.(float64); ok {
			opts.ClientProbeID = uint(f)
		}
	}
	if clientAgentID, ok := tsConfig["client_agent_id"]; ok {
		if f, ok := clientAgentID.(float64); ok {
			opts.ClientAgentID = uint(f)
		}
	}

	// Apply VoIP defaults if enabled or inferred from interval, mirroring NewTrafficSim
	// so reverse traffic paces the same as the client's forward traffic.
	if opts.VoIPMode || (opts.IntervalMs > 0 && opts.IntervalMs <= 50) {
		opts.VoIPMode = true
		if opts.PayloadSize == 0 {
			opts.PayloadSize = VoIPPayloadSize
		}
		if opts.IntervalMs == TrafficSimDataInterval {
			opts.IntervalMs = VoIPDataInterval
		}
	}
	opts.PacketsPerSec = 1000 / opts.IntervalMs

	return opts
}

// RefreshBidirectional re-checks all existing connections for bidirectional probe support.
// Called when the probe list is updated (e.g., after FetchProbesWorker delivers new probes)
// to ensure connections that were established before the probe list was populated
// get a chance to enable bidirectional mode.
func (ts *TrafficSim) RefreshBidirectional() {
	ts.connectionsMu.Lock()
	defer ts.connectionsMu.Unlock()

	refreshed := 0
	for _, connection := range ts.connections {
		// Skip if bidirectional already enabled
		if connection.ClientProbeID != 0 && connection.ReverseCycle != nil {
			continue
		}
		// Re-check if we now have a client probe for this agent
		clientProbe := ts.GetClientProbeForAgent(connection.AgentID)
		if clientProbe != nil && shouldEnableBidirectional(clientProbe) {
			// Extract VoIP options including bidirectional flag
			opts := extractVoIPOptions(clientProbe.Metadata)
			connection.ClientProbeID = resolveClientProbeID(clientProbe, opts)
			connection.ReverseCycle = &CycleTracker{
				StartSeq:     1,
				StartTime:    time.Now(),
				PacketSeqs:   make([]int, 0, TrafficSimReportSeq),
				PacketTimes:  make(map[int]PacketTime),
				receivedSeqs: make(map[int]int),
			}
			connection.ReverseTrafficOptions = opts
			log.Infof("[trafficsim] Bidirectional mode (refresh) enabled for agent %d using client probe %d (VoIP: %v, BiDir: %v)",
				connection.AgentID, connection.ClientProbeID, opts.VoIPMode, opts.Bidirectional)
			refreshed++
		}
	}
	if refreshed > 0 {
		log.Infof("[trafficsim] Bidirectional refresh complete: %d connections updated", refreshed)
	}
}

// GetClientProbeForAgent finds a TRAFFICSIM probe targeting the given agent for bidirectional testing.
// The controller creates TRAFFICSIM probes when:
// 1. Target agent has a server (client mode) - looks for client probe
// 2. Owner agent has a server (bidirectional mode with bidirectional_receiver marker)
// Returns the probe if found, nil otherwise
func (ts *TrafficSim) GetClientProbeForAgent(targetAgentID uint) *Probe {
	// First try using dynamic probe retrieval if available (preferred for freshest data)
	var probesToCheck []Probe
	if ts.GetProbesFunc != nil {
		probesToCheck = ts.GetProbesFunc()
	} else {
		// Fallback to stored probe list
		ts.allProbesMu.RLock()
		probesToCheck = ts.allProbes
		ts.allProbesMu.RUnlock()
	}

	// Look for either:
	// 1. Client probe (not server) targeting this agent
	// 2. Bidirectional receiver probe (server=true) with client_agent_id matching this agent
	for i := range probesToCheck {
		p := &probesToCheck[i]

		if p.Type == ProbeType_TRAFFICSIM {
			opts := extractVoIPOptions(p.Metadata)

			// Check for client probe targeting this agent
			if !p.Server {
				for _, t := range p.Targets {
					if t.AgentID != nil && *t.AgentID == targetAgentID {
						// Check if this probe has bidirectional enabled
						if shouldEnableBidirectional(p) {
							log.Infof("[trafficsim] GetClientProbeForAgent: FOUND client probe %d for agent %d (bidirectional)", p.ID, targetAgentID)
							return p
						}
					}
				}
			}

			// Check for bidirectional receiver/server probe (server) with matching client_agent_id
			if p.Server {
				// Check both bidirectional_server (new) and bidirectional_receiver (legacy)
				if (opts.BidirectionalServer || opts.BidirectionalReceiver) && opts.ClientAgentID == targetAgentID {
					log.Infof("[trafficsim] GetClientProbeForAgent: FOUND bidirectional probe %d for client agent %d (clientProbeID=%d, bidirectional_server=%v)",
						p.ID, targetAgentID, opts.ClientProbeID, opts.BidirectionalServer)
					return p
				}
			}
		}
	}
	log.Infof("[trafficsim] GetClientProbeForAgent: NO probe found for agent %d", targetAgentID)
	return nil
}

// resolveClientProbeID returns the probe ID to use for reverse-path attribution.
// For dynamically generated bidirectional SERVER probes the probe itself is virtual
// (ID=0) and the client's real probe ID is carried in metadata as client_probe_id —
// that ID must be used so reverse stats land on the same probe as the client's
// forward stats. For real client probes (mutual-server / legacy) the probe's own ID
// is already the correct one.
func resolveClientProbeID(probe *Probe, opts TrafficSimOptions) uint {
	if (opts.BidirectionalServer || opts.BidirectionalReceiver) && opts.ClientProbeID != 0 {
		return opts.ClientProbeID
	}
	return probe.ID
}

// shouldEnableBidirectional checks if bidirectional mode should be enabled for a probe.
// Returns true if:
// 1. The probe has bidirectional=true in metadata (NEW single-probe approach)
// 2. The probe's target contains ":bidir" suffix (LEGACY dual-probe approach)
func shouldEnableBidirectional(probe *Probe) bool {
	if probe == nil {
		return false
	}

	// Check metadata for bidirectional flag
	opts := extractVoIPOptions(probe.Metadata)
	if opts.Bidirectional {
		return true
	}

	// Check for legacy ":bidir" suffix in targets
	for _, t := range probe.Targets {
		if t.Target != "" && strings.HasSuffix(t.Target, ":bidir") {
			return true
		}
	}

	return false
}

// nextReverseSequence returns the next sequence number for reverse direction
func (ts *TrafficSim) nextReverseSequence() int {
	ts.reverseSequenceMu.Lock()
	defer ts.reverseSequenceMu.Unlock()
	ts.reverseSequence++
	return ts.reverseSequence
}

// isNetworkChangeError detects errors indicating the local IP or socket is no longer valid.
// This includes both Unix/Linux errors and Windows-specific socket errors.
func isNetworkChangeError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "can't assign requested address") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "no route to host") ||
		// Windows-specific socket errors when network state changes
		strings.Contains(errStr, "wsasend") ||
		strings.Contains(errStr, "wsarecv") ||
		strings.Contains(errStr, "An invalid argument was supplied") ||
		strings.Contains(errStr, "forcibly closed") ||
		strings.Contains(errStr, "unreachable network") // Windows variant
}

// lastReconnectLog tracks the last time we logged a network-related error to prevent spam
var lastReconnectLog time.Time
var reconnectLogMu sync.Mutex

// shouldLogNetworkError returns true if we should log a network-related error.
// Rate-limits to one message every 5 seconds to prevent spam when network is down.
func shouldLogNetworkError() bool {
	reconnectLogMu.Lock()
	defer reconnectLogMu.Unlock()
	if time.Since(lastReconnectLog) > 5*time.Second {
		lastReconnectLog = time.Now()
		return true
	}
	return false
}

// reconnectUDP closes the existing connection and establishes a new one
func (ts *TrafficSim) reconnectUDP() error {
	shouldLog := shouldLogNetworkError()

	if shouldLog {
		log.Infof("[trafficsim] Reconnecting due to network change...")
	}

	// Close old connection
	ts.connMu.Lock()
	if ts.conn != nil {
		ts.conn.Close()
		ts.conn = nil
	}
	ts.connMu.Unlock()

	// Establish new connection
	if err := ts.dialUDP(); err != nil {
		if shouldLog {
			log.Infof("[trafficsim] Reconnection failed: %v", err)
		}
		return err
	}

	log.Debugf("[trafficsim] Reconnected to %s:%d", ts.IPAddress, ts.Port)
	return nil
}

func (ts *TrafficSim) nextSequence() int {
	ts.sequenceMu.Lock()
	defer ts.sequenceMu.Unlock()
	ts.sequence++
	return ts.sequence
}

func (ts *TrafficSim) resetSequence() {
	ts.sequenceMu.Lock()
	defer ts.sequenceMu.Unlock()
	ts.sequence = 0
}

// -------------------- Message Building --------------------

func (ts *TrafficSim) buildMessage(msgType TrafficSimMsgType, data TrafficSimData) ([]byte, error) {
	msg := TrafficSimMsg{
		Type:      msgType,
		Data:      data,
		SrcAgent:  ts.ThisAgent,
		DstAgent:  ts.OtherAgent,
		Timestamp: time.Now().UnixMilli(),
	}

	// Marshal once to get size
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}
	msg.Size = len(msgBytes)

	// Re-marshal with size
	msgBytes, err = json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message with size: %w", err)
	}

	return msgBytes, nil
}

// -------------------- Client Mode --------------------

// Start begins the TrafficSim in client or server mode
func (ts *TrafficSim) Start(mtrProbe *Probe) {
	atomic.StoreInt32(&ts.running, 1)
	atomic.StoreInt32(&ts.stopping, 0)
	ts.stopChan = make(chan struct{})

	defer func() {
		log.Infof("[trafficsim] Start() exiting for probe %d", ts.Probe.ID)
		atomic.StoreInt32(&ts.running, 0)
		if ts.conn != nil {
			ts.conn.Close()
		}
	}()

	ctx := context.Background()

	for ts.isRunning() && !ts.isStopping() {
		var err error
		if ts.IsServer {
			err = ts.runServer()
		} else {
			err = ts.runClient(ctx, mtrProbe)
		}

		if err != nil {
			log.Infof("[trafficsim] Error: %v. Retrying in %v...", err, TrafficSimRetryInterval)
			select {
			case <-time.After(TrafficSimRetryInterval):
			case <-ts.stopChan:
				return
			}
		}
	}
}

func (ts *TrafficSim) runClient(ctx context.Context, mtrProbe *Probe) error {
	// Establish UDP connection
	if err := ts.dialUDP(); err != nil {
		return fmt.Errorf("dial UDP: %w", err)
	}
	// Don't capture ts.conn directly — reconnectUDP() may replace it.
	// Cleanup is handled by setConn() and Stop().
	defer func() {
		conn := ts.getConn()
		if conn != nil {
			conn.Close()
		}
	}()

	// Attempt handshake
	if !ts.handshake() {
		return fmt.Errorf("handshake failed")
	}

	log.Debugf("[trafficsim] Connected to %s:%d", ts.IPAddress, ts.Port)

	// Start receive loop
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		ts.receiveLoop(ctx)
	}()

	// Run test cycles
	ts.runTestCycles(ctx, mtrProbe)

	return nil
}

func (ts *TrafficSim) dialUDP() error {
	addr := fmt.Sprintf("%s:%d", ts.IPAddress, ts.Port)
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	// Resolve bind address from probe config.
	// If BindInterface is set, bind the socket to that specific interface's IP.
	// If empty, DialUDPWithBind passes nil laddr (OS default — current behavior).
	bindIP := ""
	if ts.Probe != nil && ts.Probe.BindInterface != "" {
		var err error
		bindIP, err = ResolveBindInterface(ts.Probe.BindInterface)
		if err != nil {
			return fmt.Errorf("trafficsim probe=%d: bind interface %q: %w", ts.Probe.ID, ts.Probe.BindInterface, err)
		}
		log.Infof("[trafficsim] probe=%d binding to interface %q (IP: %s)",
			ts.Probe.ID, ts.Probe.BindInterface, bindIP)
	}

	conn, err := DialUDPWithBind(bindIP, raddr)
	if err != nil {
		return err
	}

	// Apply DSCP marking if configured
	if ts.Options.DSCPValue > 0 {
		if err := ts.setDSCPMarking(conn, ts.Options.DSCPValue); err != nil {
			log.Warnf("[trafficsim] probe=%d: failed to set DSCP %d: %v", ts.Probe.ID, ts.Options.DSCPValue, err)
		} else {
			log.Infof("[trafficsim] probe=%d: DSCP marking set to %d (0x%02x)", ts.Probe.ID, ts.Options.DSCPValue, ts.Options.DSCPValue<<2)
		}
	}

	// Capture the local IP the OS actually bound us to.
	// We'll check this before each cycle — if this IP is no longer
	// assigned to any active interface, the socket is stale.
	if localAddr := conn.LocalAddr(); localAddr != nil {
		host, _, _ := net.SplitHostPort(localAddr.String())
		ts.setBoundLocalIP(host)
		log.Debugf("[trafficsim] probe=%d bound to local IP %s", ts.Probe.ID, host)
	}

	ts.setConn(conn)
	return nil
}

func (ts *TrafficSim) handshake() bool {
	seq := ts.nextSequence()
	sentTime := time.Now().UnixMilli()

	msg, err := ts.buildMessage(MsgHello, TrafficSimData{
		Sent: sentTime,
		Seq:  seq,
	})
	if err != nil {
		log.Infof("[trafficsim] Error building HELLO: %v", err)
		return false
	}

	conn := ts.getConn()
	if conn == nil {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(TrafficSimTimeout))
	if _, err := conn.Write(msg); err != nil {
		log.Infof("[trafficsim] Failed to send HELLO: %v", err)
		return false
	}

	// Wait for response
	buf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		log.Infof("[trafficsim] No HELLO response: %v", err)
		return false
	}

	var resp TrafficSimMsg
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		log.Infof("[trafficsim] Invalid HELLO response: %v", err)
		return false
	}

	if resp.Type == MsgAck || resp.Type == MsgHello {
		log.Debugf("[trafficsim] Handshake successful, RTT: %dms", time.Now().UnixMilli()-sentTime)
		ts.lastResponse = time.Now()
		return true
	}

	return false
}

func (ts *TrafficSim) runTestCycles(ctx context.Context, mtrProbe *Probe) {
	// Determine reporting mode based on VoIP settings
	// In VoIP mode, we report based on time (every VoIPReportIntervalSec seconds)
	// In legacy mode (1 second interval), we report every 60 packets (60 seconds)
	useTimeBasedReporting := ts.Options.VoIPMode && ts.Options.IntervalMs <= 50
	reportInterval := time.Duration(VoIPReportIntervalSec) * time.Second

	for ts.isRunning() && !ts.isStopping() {
		// Start new cycle
		cycle := ts.startCycle()
		cycleStartTime := time.Now()

		if useTimeBasedReporting {
			log.Infof("[trafficsim] Starting VoIP cycle, will report every %v", reportInterval)
		} else {
			log.Debugf("[trafficsim] Starting cycle, %d packets", TrafficSimReportSeq)
		}

		// Pre-cycle check: validate the socket's bound IP is still on a live interface.
		// This catches silent socket death (Windows rebinding to a dead interface)
		// without the overhead of calling net.InterfaceAddrs() on every packet.
		if !ts.isBoundIPValid() {
			log.Warnf("[trafficsim] probe=%d: bound IP %s no longer valid, forcing reconnect",
				ts.Probe.ID, ts.getBoundLocalIP())
			ts.setConnectionValid(false)
		}

		// Send packets in a loop, checking both packet count (legacy) and time (VoIP)
		packetsSent := 0
		for (useTimeBasedReporting && time.Since(cycleStartTime) < reportInterval) ||
			(!useTimeBasedReporting && packetsSent < TrafficSimReportSeq) {
			select {
			case <-ctx.Done():
				return
			case <-ts.stopChan:
				return
			default:
			}

			// Check if connection was invalidated (by error handler, watcher, or pre-cycle check)
			if !ts.isConnectionValid() {
				if err := ts.reconnectUDP(); err != nil {
					// Still send packet (will fail, recording loss)
					// Only log occasionally to prevent spam when network is down
					if shouldLogNetworkError() {
						log.Infof("[trafficsim] Reconnection failed, packet %d will fail", packetsSent+1)
					}
				}
			}

			ts.sendDataPacket(cycle)
			packetsSent++

			// Wait for interval (use configurable interval in milliseconds)
			select {
			case <-time.After(time.Duration(ts.Options.IntervalMs) * time.Millisecond):
			case <-ctx.Done():
				return
			case <-ts.stopChan:
				return
			}
		}

		log.Infof("[trafficsim] VoIP cycle complete: sent=%d packets over %v",
			packetsSent, time.Since(cycleStartTime).Round(time.Second))

		// Wait for responses
		ts.waitForResponses(ctx, cycle)

		// Calculate and report stats
		stats := ts.calculateStats(cycle)
		ts.reportStats(stats, mtrProbe)

		// Reset sequence for next cycle
		ts.resetSequence()

		// Check for packet loss trigger (run MTR for diagnostics)
		if loss, ok := stats["lossPercentage"].(float64); ok && loss > 5.0 {
			ts.triggerMTR(mtrProbe, loss)
		}

		log.Infof("[trafficsim] probe=%d loss=%.1f%% avgRTT=%.1fms minRTT=%vms maxRTT=%vms",
			ts.Probe.ID, stats["lossPercentage"], stats["averageRTT"], stats["minRTT"], stats["maxRTT"])
	}
}

func (ts *TrafficSim) startCycle() *CycleTracker {
	ts.cycleMu.Lock()
	defer ts.cycleMu.Unlock()

	cycle := &CycleTracker{
		StartSeq:        ts.sequence + 1,
		StartTime:       time.Now(),
		PacketSeqs:      make([]int, 0, TrafficSimReportSeq),
		PacketTimes:     make(map[int]PacketTime),
		receivedSeqs:    make(map[int]int), // Track receive count per seq
		lastReceivedSeq: 0,
		outOfOrder:      0,
		duplicates:      0,
	}
	ts.currentCycle = cycle
	ts.packetsInCycle = 0

	return cycle
}

func (ts *TrafficSim) sendDataPacket(cycle *CycleTracker) bool {
	seq := ts.nextSequence()
	sentTime := time.Now().UnixMilli()

	// Track in cycle
	cycle.mu.Lock()
	cycle.PacketSeqs = append(cycle.PacketSeqs, seq)
	cycle.PacketTimes[seq] = PacketTime{Sent: sentTime}
	log.Debugf("[trafficsim] CLIENT sent seq=%d", seq)
	cycle.mu.Unlock()

	// Also track in client stats
	ts.clientStats.mu.Lock()
	ts.clientStats.PacketTimes[seq] = PacketTime{Sent: sentTime}
	ts.clientStats.mu.Unlock()

	msg, err := ts.buildMessage(MsgData, TrafficSimData{
		Sent: sentTime,
		Seq:  seq,
	})
	if err != nil {
		log.Infof("[trafficsim] Error building DATA: %v", err)
		return false
	}

	conn := ts.getConn()
	if conn == nil {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(msg); err != nil {
		log.Infof("[trafficsim] Send error for seq %d: %v", seq, err)
		// Check if this is a network change error
		if isNetworkChangeError(err) {
			ts.setConnectionValid(false)
		}
		return false
	}

	return true
}

func (ts *TrafficSim) receiveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ts.stopChan:
			return
		default:
		}

		if !ts.isRunning() {
			return
		}

		conn := ts.getConn()
		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Check for network change errors
			if isNetworkChangeError(err) {
				if shouldLogNetworkError() {
					log.Infof("[trafficsim] Network change detected in receive loop: %v", err)
				}
				ts.setConnectionValid(false)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Only log non-network errors (closed connection during shutdown is expected)
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Infof("[trafficsim] Read error: %v", err)
			}
			continue
		}

		var msg TrafficSimMsg
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}

		switch msg.Type {
		case MsgAck:
			ts.handleAck(msg.Data)
		case MsgPong:
			ts.lastResponse = time.Now()
		case MsgData:
			// Server sent DATA (bidirectional mode) - send ACK back
			ack, err := ts.buildAckMessage(msg.Data)
			if err != nil {
				continue
			}
			conn.Write(ack)
			ts.lastResponse = time.Now()
		case MsgReport:
			// Server stats received
		}
	}
}

func (ts *TrafficSim) handleAck(data TrafficSimData) {
	seq := data.Seq
	recvTime := time.Now().UnixMilli()

	// Update cycle tracker
	ts.cycleMu.RLock()
	if ts.currentCycle != nil {
		ts.currentCycle.mu.Lock()

		// Track duplicate detection: increment receive count for this seq
		ts.currentCycle.receivedSeqs[seq]++
		receiveCount := ts.currentCycle.receivedSeqs[seq]

		if receiveCount > 1 {
			// This is a duplicate packet
			ts.currentCycle.duplicates++
			// Reset consecutive loss counter when we receive a packet (even duplicate)
			if ts.currentCycle.consecutiveLoss > 0 {
				if ts.currentCycle.consecutiveLoss > ts.currentCycle.maxConsecutiveLoss {
					ts.currentCycle.maxConsecutiveLoss = ts.currentCycle.consecutiveLoss
				}
				ts.currentCycle.totalBursts++
				ts.currentCycle.consecutiveLoss = 0
			}
		} else {
			// First time receiving this seq - check for out-of-order
			if ts.currentCycle.lastReceivedSeq > 0 && seq < ts.currentCycle.lastReceivedSeq {
				// Packet arrived out of order (lower seq after higher seq)
				ts.currentCycle.outOfOrder++
			}
			ts.currentCycle.lastReceivedSeq = seq
			// Reset consecutive loss counter on successful receipt
			if ts.currentCycle.consecutiveLoss > 0 {
				if ts.currentCycle.consecutiveLoss > ts.currentCycle.maxConsecutiveLoss {
					ts.currentCycle.maxConsecutiveLoss = ts.currentCycle.consecutiveLoss
				}
				ts.currentCycle.totalBursts++
				ts.currentCycle.consecutiveLoss = 0
			}
		}

		// Update packet timing (only first receipt)
		if pt, ok := ts.currentCycle.PacketTimes[seq]; ok && pt.Received == 0 {
			pt.Received = recvTime
			ts.currentCycle.PacketTimes[seq] = pt

			// RFC 3550 jitter calculation
			// J(i) = J(i-1) + (|D(i,i-1)| - J(i-1))/16
			// D(i,j) = (Rj - Ri) - (Sj - Si) = difference between inter-arrival and inter-transit time
			if ts.currentCycle.lastTransit > 0 {
				interArrival := float64(recvTime - ts.currentCycle.lastArrivalTime)
				interTransit := float64(pt.Sent - ts.currentCycle.lastSentTime)
				D := math.Abs(interArrival - interTransit)
				// Update smoothed jitter using RFC 3550 formula
				ts.currentCycle.rfc3550Jitter = ts.currentCycle.rfc3550Jitter + (D-ts.currentCycle.rfc3550Jitter)/16.0
			}
			// Update last transit time for next calculation
			transit := recvTime - pt.Sent
			ts.currentCycle.lastTransit = transit
			ts.currentCycle.lastArrivalTime = recvTime
			ts.currentCycle.lastSentTime = pt.Sent

			log.Debugf("[trafficsim] CLIENT handleAck seq=%d rtt=%d jitter=%.2f", seq, recvTime-pt.Sent, ts.currentCycle.rfc3550Jitter)
		} else if _, ok := ts.currentCycle.PacketTimes[seq]; ok {
			log.Debugf("[trafficsim] CLIENT handleAck seq=%d ALREADY RECEIVED", seq)
		} else {
			log.Debugf("[trafficsim] CLIENT handleAck seq=%d NOT FOUND", seq)
		}
		ts.currentCycle.mu.Unlock()
	}
	ts.cycleMu.RUnlock()

	// Update client stats
	ts.clientStats.mu.Lock()
	if pt, ok := ts.clientStats.PacketTimes[seq]; ok && pt.Received == 0 {
		pt.Received = recvTime
		ts.clientStats.PacketTimes[seq] = pt
	}
	ts.clientStats.mu.Unlock()

	ts.lastResponse = time.Now()
}

func (ts *TrafficSim) waitForResponses(ctx context.Context, cycle *CycleTracker) {
	deadline := time.Now().Add(TrafficSimTimeout + 500*time.Millisecond)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-ts.stopChan:
			return
		case <-time.After(50 * time.Millisecond):
		}

		// Check if all packets are complete
		allDone := true
		now := time.Now().UnixMilli()

		cycle.mu.Lock()
		receivedCount := 0
		timedOutCount := 0
		for _, seq := range cycle.PacketSeqs {
			if pt, ok := cycle.PacketTimes[seq]; ok {
				if pt.Received > 0 {
					receivedCount++
				} else if pt.TimedOut {
					timedOutCount++
				}
			}
		}
		if receivedCount > 0 || len(cycle.PacketSeqs) > 0 {
			log.Debugf("[trafficsim] CLIENT waitForResponses: received=%d timedOut=%d total=%d",
				receivedCount, timedOutCount, len(cycle.PacketSeqs))
		}
		for _, seq := range cycle.PacketSeqs {
			if pt, ok := cycle.PacketTimes[seq]; ok {
				if pt.Received == 0 && !pt.TimedOut {
					if now-pt.Sent > int64(TrafficSimTimeout.Milliseconds()) {
						pt.TimedOut = true
						cycle.PacketTimes[seq] = pt
						// Track burst loss
						cycle.consecutiveLoss++
					} else {
						allDone = false
					}
				}
			}
		}
		cycle.mu.Unlock()

		if allDone {
			break
		}
	}
}

func percentile(vals []float64, pct int) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := (len(sorted) * pct) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (ts *TrafficSim) calculateStats(cycle *CycleTracker) map[string]interface{} {
	cycle.mu.RLock()
	defer cycle.mu.RUnlock()

	var rtts []float64
	var totalRTT, minRTT, maxRTT int64
	lost := 0
	total := len(cycle.PacketSeqs)

	for _, seq := range cycle.PacketSeqs {
		if pt, ok := cycle.PacketTimes[seq]; ok {
			if pt.Received == 0 || pt.TimedOut {
				lost++
				continue
			}
			rtt := pt.Received - pt.Sent
			rtts = append(rtts, float64(rtt))
			totalRTT += rtt
			if minRTT == 0 || rtt < minRTT {
				minRTT = rtt
			}
			if rtt > maxRTT {
				maxRTT = rtt
			}
		}
	}

	avgRTT := float64(0)
	stdDev := float64(0)
	if len(rtts) > 0 {
		avgRTT = float64(totalRTT) / float64(len(rtts))
		for _, rtt := range rtts {
			stdDev += math.Pow(rtt-avgRTT, 2)
		}
		stdDev = math.Sqrt(stdDev / float64(len(rtts)))
	}

	lossPercent := float64(0)
	if total > 0 {
		lossPercent = (float64(lost) / float64(total)) * 100
	}

	// Calculate percentages for out-of-order and duplicates
	outOfOrderPercent := float64(0)
	duplicatePercent := float64(0)
	received := total - lost
	if received > 0 {
		outOfOrderPercent = (float64(cycle.outOfOrder) / float64(received)) * 100
		duplicatePercent = (float64(cycle.duplicates) / float64(received)) * 100
	}

	// Latency percentiles
	medianRTT := percentile(rtts, 50)
	p95RTT := percentile(rtts, 95)
	p99RTT := percentile(rtts, 99)

	log.Infof("[trafficsim] DEBUG percentile: rtts.len=%d medianRTT=%v p95RTT=%v p99RTT=%v", len(rtts), medianRTT, p95RTT, p99RTT)

	// Jitter: mean absolute deviation of inter-packet delays
	var jitterVals []float64
	for i := 1; i < len(rtts); i++ {
		jitterVals = append(jitterVals, math.Abs(rtts[i]-rtts[i-1]))
	}
	jitterAvg := float64(0)
	if len(jitterVals) > 0 {
		var sum float64
		for _, j := range jitterVals {
			sum += j
		}
		jitterAvg = sum / float64(len(jitterVals))
	}
	jitterMedian := percentile(jitterVals, 50)
	jitterP95 := percentile(jitterVals, 95)

	// Estimate one-way delay as half of RTT
	oneWayLatency := avgRTT / 2.0

	// Playout buffer recommendation based on jitter
	// RFC 3438 guidelines: buffer should be 2-3x the measured jitter
	// For G.711: minimum 20ms + jitter, typical 40-80ms
	playoutBufferMin := jitterMedian * 2
	if playoutBufferMin < 20 {
		playoutBufferMin = 20
	}
	playoutBufferMax := jitterP95 * 2
	if playoutBufferMax < playoutBufferMin {
		playoutBufferMax = playoutBufferMin * 2
	}

	// MOS calculation using simplified E-Model (G.107)
	// R = 94.2 - Id - Ie - Is
	// For G.711: Ie = 0 (best effort codec)
	// Id depends on delay: Id = 0.024 * oneWayDelay + 0.11 * oneWayDelay * (oneWayDelay/10)
	// Is is for simultaneous impairments (simplified to 0 for our test)
	// Packet loss impact: Ip = 30 * ln(1 + 0.8 * lossPercent)
	// Burst loss amplification: effectiveLoss = lossPercent * (1 + burstFactor * 0.1)
	// For burst loss, we amplify the loss impact
	burstFactor := float64(0)
	if cycle.totalBursts > 0 {
		// More bursts = higher burst factor (0-4 scale)
		burstFactor = math.Min(float64(cycle.totalBursts)/10.0, 4.0)
	}
	effectiveLossPercent := lossPercent * (1.0 + burstFactor*0.1)

	// Calculate impairment components
	Ie := float64(0)                                    // Equipment impairment for G.711
	Ip := 30.0 * math.Log(1.0+0.8*effectiveLossPercent) // Packet loss impairment
	oneWayDelayMs := oneWayLatency
	Id := 0.024*oneWayDelayMs + 0.11*oneWayDelayMs*(oneWayDelayMs/10.0) // Delay impairment

	// R-factor (0-100 scale)
	R := 94.2 - Id - Ie - Ip

	// Clamp R to valid range
	if R < 0 {
		R = 0
	}
	if R > 100 {
		R = 100
	}

	// Convert R-factor to MOS (1.0-5.0)
	// MOS = 1.0 + 0.035*R + R*(R-60)*(100-R)*7e-6
	MOS := 1.0 + 0.035*R + R*(R-60.0)*(100.0-R)*7e-6
	if MOS < 1.0 {
		MOS = 1.0
	}
	if MOS > 5.0 {
		MOS = 5.0
	}

	// MOS quality classification
	mosQuality := "unknown"
	if MOS >= 4.3 {
		mosQuality = "excellent"
	} else if MOS >= 4.0 {
		mosQuality = "good"
	} else if MOS >= 3.6 {
		mosQuality = "acceptable"
	} else if MOS >= 3.0 {
		mosQuality = "poor"
	} else {
		mosQuality = "bad"
	}

	log.Infof("[trafficsim] DEBUG jitter percentile: jitterVals.len=%d jitterMedian=%v jitterP95=%v", len(jitterVals), jitterMedian, jitterP95)
	log.Infof("[trafficsim] DEBUG MOS: R=%.1f MOS=%.2f Id=%.2f Ip=%.2f oneWayLatency=%.1fms", R, MOS, Id, Ip, oneWayLatency)

	log.Infof("[trafficsim] calculateStats: totalPacketSeqs=%d receivedRtts=%d lost=%d jitterVals=%d outOfOrder=%d duplicates=%d",
		total, len(rtts), lost, len(jitterVals), cycle.outOfOrder, cycle.duplicates)

	log.Infof("[trafficsim] DEBUG calculateStats RETURNING: medianRTT=%v p95RTT=%v p99RTT=%v jitterMedian=%v jitterP95=%v jitterAvg=%v",
		medianRTT, p95RTT, p99RTT, jitterMedian, jitterP95, jitterAvg)

	// Calculate cycle duration
	cycleDurationMs := float64(0)
	if !cycle.StartTime.IsZero() {
		cycleDurationMs = float64(time.Since(cycle.StartTime).Milliseconds())
	}

	// Calculate actual packet rate achieved
	packetsPerSecond := float64(0)
	if cycleDurationMs > 0 && total > 0 {
		packetsPerSecond = (float64(total) / cycleDurationMs) * 1000.0
	}

	// Calculate network efficiency (packets that were useful - not lost/duplicate/out-of-order)
	networkEfficiency := float64(100)
	if total > 0 {
		badPackets := lost + cycle.duplicates + cycle.outOfOrder
		networkEfficiency = float64(total-badPackets) / float64(total) * 100.0
	}

	// Latency quality classification (based on one-way latency)
	latencyQuality := "unknown"
	latencyQualityScore := float64(100)
	estOneWayLat := avgRTT / 2.0
	if estOneWayLat < 50 {
		latencyQuality = "excellent"
		latencyQualityScore = 100
	} else if estOneWayLat < 100 {
		latencyQuality = "good"
		latencyQualityScore = 80
	} else if estOneWayLat < 200 {
		latencyQuality = "acceptable"
		latencyQualityScore = 60
	} else if estOneWayLat < 300 {
		latencyQuality = "poor"
		latencyQualityScore = 40
	} else {
		latencyQuality = "bad"
		latencyQualityScore = 20
	}

	// Jitter quality score (lower jitter = higher quality)
	jitterQualityScore := float64(100)
	if jitterMedian < 10 {
		jitterQualityScore = 100
	} else if jitterMedian < 20 {
		jitterQualityScore = 80
	} else if jitterMedian < 30 {
		jitterQualityScore = 60
	} else if jitterMedian < 50 {
		jitterQualityScore = 40
	} else {
		jitterQualityScore = 20
	}

	// Loss quality score
	lossQualityScore := float64(100)
	if lossPercent < 0.1 {
		lossQualityScore = 100
	} else if lossPercent < 0.5 {
		lossQualityScore = 90
	} else if lossPercent < 1.0 {
		lossQualityScore = 80
	} else if lossPercent < 2.0 {
		lossQualityScore = 60
	} else if lossPercent < 5.0 {
		lossQualityScore = 40
	} else {
		lossQualityScore = 20
	}

	// Composite network health score (0-100)
	networkHealthScore := (latencyQualityScore*0.4 + jitterQualityScore*0.3 + lossQualityScore*0.3)

	// Build stats map with backward-compatible base metrics
	stats := map[string]interface{}{
		// Basic loss and packet metrics
		"lostPackets":       lost,
		"lossPercentage":    lossPercent,
		"totalPackets":      total,
		"receivedPackets":   received,
		"duplicates":        cycle.duplicates,
		"duplicatePercent":  duplicatePercent,
		"outOfOrder":        cycle.outOfOrder,
		"outOfOrderPercent": outOfOrderPercent,

		// Latency metrics (RTT in ms)
		"averageRTT": avgRTT,
		"medianRTT":  medianRTT,
		"p95RTT":     p95RTT,
		"p99RTT":     p99RTT,
		"minRTT":     minRTT,
		"maxRTT":     maxRTT,
		"stdDevRTT":  stdDev,

		// Jitter metrics (ms)
		"jitterAvg":    jitterAvg,
		"jitterMedian": jitterMedian,
		"jitterP95":    jitterP95,

		// Network quality metrics
		"networkEfficiency":   networkEfficiency,
		"latencyQuality":      latencyQuality,
		"latencyQualityScore": latencyQualityScore,
		"jitterQualityScore":  jitterQualityScore,
		"lossQualityScore":    lossQualityScore,
		"networkHealthScore":  networkHealthScore,

		// Timing metrics
		"cycleDurationMs":  cycleDurationMs,
		"packetsPerSecond": packetsPerSecond,

		"timestamp": time.Now(),
	}

	// Add RFC 3550 jitter (computed for all traffic, useful for network characterization)
	if cycle.rfc3550Jitter > 0 {
		stats["rfc3550Jitter"] = cycle.rfc3550Jitter
	}

	// Add VoIP-specific metrics when in VoIP mode
	if ts.Options.VoIPMode {
		// Estimated one-way latency
		stats["oneWayLatency"] = oneWayLatency

		// Playout buffer recommendations (ms)
		stats["playoutBufferMin"] = playoutBufferMin
		stats["playoutBufferMax"] = playoutBufferMax

		// Burst loss metrics
		stats["maxConsecutiveLoss"] = cycle.maxConsecutiveLoss
		stats["totalBursts"] = cycle.totalBursts

		// MOS/quality metrics
		stats["MOS"] = MOS
		stats["RFactor"] = R
		stats["mosQuality"] = mosQuality
		stats["delayImp"] = Id
		stats["lossImp"] = Ip

		// Config info
		stats["dscpValue"] = ts.Options.DSCPValue
		stats["payloadSize"] = ts.Options.PayloadSize
		stats["intervalMs"] = ts.Options.IntervalMs

		// Estimated bandwidth in kbps (payload + protocol overhead)
		// Total overhead: RTP(12) + UDP(8) + IP(20) = 40 bytes
		if ts.Options.PayloadSize > 0 && ts.Options.IntervalMs > 0 {
			packetSize := ts.Options.PayloadSize + 40
			stats["estimatedBandwidthKbps"] = float64(packetSize) * 8.0 * 1000.0 / float64(ts.Options.IntervalMs)
		}
	}

	return stats
}

func (ts *TrafficSim) reportStats(stats map[string]interface{}, mtrProbe *Probe) {
	if ts.DataChan == nil || !ts.isRunning() {
		return
	}

	log.Infof("[trafficsim] CLIENT stats map before marshal: %+v", stats)

	payload, err := json.Marshal(stats)
	if err != nil {
		log.Infof("[trafficsim] Error marshaling stats: %v", err)
		return
	}

	log.Infof("[trafficsim] CLIENT JSON payload: %s", string(payload))

	target := fmt.Sprintf("%s:%d", ts.IPAddress, ts.Port)

	select {
	case ts.DataChan <- ProbeData{
		ProbeID:     ts.Probe.ID,
		Triggered:   false,
		CreatedAt:   time.Now(),
		Type:        ProbeType_TRAFFICSIM,
		Payload:     payload,
		Target:      target,
		TargetAgent: ts.OtherAgent,
	}:
	default:
		log.Infof("[trafficsim] DataChan full, dropping stats")
	}
}

func (ts *TrafficSim) triggerMTR(mtrProbe *Probe, lossPercent float64) {
	if mtrProbe == nil {
		return
	}

	log.Infof("[trafficsim] Triggering MTR due to %.1f%% packet loss", lossPercent)

	// Run actual MTR trace for diagnostics
	go func() {
		mtrResult, err := Mtr(mtrProbe, true) // triggered=true for higher sample count
		if err != nil {
			log.Errorf("[trafficsim] Triggered MTR failed for probe %d: %v", mtrProbe.ID, err)
			return
		}

		payload, err := json.Marshal(mtrResult)
		if err != nil {
			log.Errorf("[trafficsim] Triggered MTR marshal error: %v", err)
			return
		}

		if ts.DataChan == nil || !ts.isRunning() {
			return
		}

		target := ""
		if len(mtrProbe.Targets) > 0 {
			target = mtrProbe.Targets[0].Target
		}

		select {
		case ts.DataChan <- ProbeData{
			ProbeID:   mtrProbe.ID,
			Triggered: true,
			CreatedAt: time.Now(),
			Type:      ProbeType_MTR,
			Payload:   payload,
			Target:    target,
		}:
			log.Infof("[trafficsim] Triggered MTR completed for %s (loss was %.1f%%)", target, lossPercent)
		default:
			log.Warnf("[trafficsim] DataChan full, dropping triggered MTR result")
		}
	}()
}

// -------------------- Server Mode --------------------

func (ts *TrafficSim) runServer() error {
	// Determine listen address: use BindInterface IP if configured, else 0.0.0.0 (all interfaces)
	listenIP := "0.0.0.0"
	if ts.Probe != nil && ts.Probe.BindInterface != "" {
		bindIP, err := ResolveBindInterface(ts.Probe.BindInterface)
		if err != nil {
			return fmt.Errorf("trafficsim server probe=%d: bind interface %q: %w", ts.Probe.ID, ts.Probe.BindInterface, err)
		}
		listenIP = bindIP
		log.Infof("[trafficsim] Server binding to interface %q (IP: %s)", ts.Probe.BindInterface, listenIP)
	}

	listenAddr := fmt.Sprintf("%s:%d", listenIP, ts.Port)
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	ts.setConn(conn)
	defer conn.Close()

	log.Debugf("[trafficsim] Server listening on %s", listenAddr)

	lastValidPacket := time.Now()
	const serverStaleTimeout = 2 * time.Minute

	for ts.isRunning() && !ts.isStopping() {
		select {
		case <-ts.stopChan:
			return nil
		default:
		}

		// Staleness watchdog: if no valid packets for 2 min, force rebind
		if time.Since(lastValidPacket) > serverStaleTimeout {
			if shouldLogNetworkError() {
				log.Infof("[trafficsim] Server stale for %v, forcing rebind", time.Since(lastValidPacket).Round(time.Second))
			}
			return fmt.Errorf("server stale, no packets for %v", serverStaleTimeout)
		}

		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Check for network-change errors (Windows: wsarecv, WSAEINVAL, etc.)
			if isNetworkChangeError(err) {
				if shouldLogNetworkError() {
					log.Infof("[trafficsim] Server network change detected: %v. Rebinding...", err)
				}
				return fmt.Errorf("network change: %w", err)
			}
			log.Infof("[trafficsim] Server read error: %v", err)
			continue
		}

		var msg TrafficSimMsg
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}

		// Check if agent is allowed
		if !ts.isAgentAllowed(msg.SrcAgent) {
			log.Infof("[trafficsim] Rejected packet from unauthorized agent %d", msg.SrcAgent)
			continue
		}

		lastValidPacket = time.Now()
		ts.handleServerMessage(conn, remoteAddr, msg)
	}

	return nil
}

func (ts *TrafficSim) isAgentAllowed(agentID uint) bool {
	ts.allowedAgentsMu.RLock()
	defer ts.allowedAgentsMu.RUnlock()

	// If no allowed list, allow all
	if len(ts.AllowedAgents) == 0 {
		return true
	}

	for _, allowed := range ts.AllowedAgents {
		if allowed == agentID {
			return true
		}
	}
	return false
}

func (ts *TrafficSim) handleServerMessage(conn *net.UDPConn, addr *net.UDPAddr, msg TrafficSimMsg) {
	// Update or create connection tracking
	ts.connectionsMu.Lock()

	log.Debugf("[trafficsim] handleServerMessage ENTRY: SrcAgent=%d Type=%s Seq=%d", msg.SrcAgent, msg.Type, msg.Data.Seq)
	connection, exists := ts.connections[msg.SrcAgent]
	if !exists {
		// Brand new connection
		connection = &AgentConnection{
			AgentID:        msg.SrcAgent,
			Addr:           addr,
			FirstSeen:      time.Now(),
			LastReportTime: time.Now(),
		}
		ts.connections[msg.SrcAgent] = connection
		log.Debugf("[trafficsim] New connection from agent %d at %s", msg.SrcAgent, addr.String())

		// Check if we have a client probe for this connected agent (enables bidirectional mode)
		ts.initBidirectional(connection)
	} else {
		// Existing connection — always update the address so reverse DATA goes
		// to the latest addr:port. Connection identity is the agent ID (map key),
		// not the network address. Multiple agents can share an IP behind NAT,
		// and one agent can have multiple sockets on different ports.
		connection.Addr = addr

		// Detect reconnection purely by behavioral signals:
		// 1. Stale HELLO (>30s gap + handshake) = agent restarted or reconnected
		// 2. Very long silence (>2min) on any packet = connection dropped and resumed
		staleConnection := time.Since(connection.LastSeen) > 30*time.Second
		isReconnect := (staleConnection && msg.Type == MsgHello) || time.Since(connection.LastSeen) > 2*time.Minute

		if isReconnect {
			reason := "HELLO after gap"
			if time.Since(connection.LastSeen) > 2*time.Minute {
				reason = fmt.Sprintf("silence for %v", time.Since(connection.LastSeen).Round(time.Second))
			}
			log.Infof("[trafficsim] Agent %d reconnected (%s), resetting connection state", msg.SrcAgent, reason)

			// Reset counters and reverse cycle
			connection.PacketsRecv = 0
			connection.PacketsSent = 0
			connection.ReverseSequence = 0
			connection.LastReportTime = time.Now()

			// Re-check bidirectional (probes may have changed since first connect)
			ts.initBidirectional(connection)
		}
	}
	connection.LastSeen = time.Now()
	connection.PacketsRecv++
	ts.connectionsMu.Unlock()

	// Handle different message types
	switch msg.Type {
	case MsgData, MsgHello:
		// Client sent data, send ACK back
		ack, err := ts.buildAckMessage(msg.Data)
		if err != nil {
			return
		}

		if _, err := conn.WriteToUDP(ack, addr); err != nil {
			if isNetworkChangeError(err) {
				if shouldLogNetworkError() {
					log.Infof("[trafficsim] Server network change on ACK send: %v", err)
				}
				// Close socket to force the read loop to exit and trigger rebind
				conn.Close()
				return
			}
			log.Infof("[trafficsim] Failed to send ACK: %v", err)
		}

		ts.connectionsMu.Lock()
		connection.PacketsSent++
		ts.connectionsMu.Unlock()

		// If bidirectional (has client probe for this agent), send test data back
		log.Debugf("[trafficsim] REVERSE path check: ClientProbeID=%d", connection.ClientProbeID)
		if connection.ClientProbeID != 0 && connection.ReverseCycle != nil {
			log.Debugf("[trafficsim] REVERSE calling sendReverseDataPacket for agent %d", connection.AgentID)
			ts.sendReverseDataPacket(conn, addr, connection)
		}

	case MsgAck:
		// Client ACK'd our reverse data packet - record the response time
		log.Debugf("[trafficsim] REVERSE MsgAck received: data.Seq=%d", msg.Data.Seq)
		if connection.ClientProbeID != 0 && connection.ReverseCycle != nil {
			ts.handleReverseAck(connection, msg.Data)
		} else {
			log.Debugf("[trafficsim] REVERSE MsgAck SKIPPED: ClientProbeID=%d", connection.ClientProbeID)
		}
	}
}

func (ts *TrafficSim) buildAckMessage(data TrafficSimData) ([]byte, error) {
	ack := TrafficSimMsg{
		Type: MsgAck,
		Data: TrafficSimData{
			Sent:     data.Sent,
			Received: time.Now().UnixMilli(),
			Seq:      data.Seq,
		},
		SrcAgent:  ts.ThisAgent,
		Timestamp: time.Now().UnixMilli(),
	}

	return json.Marshal(ack)
}

// sendReverseDataPacket sends a test data packet from server to client for bidirectional measurement
func (ts *TrafficSim) sendReverseDataPacket(conn *net.UDPConn, addr *net.UDPAddr, connection *AgentConnection) {
	log.Debugf("[trafficsim] REVERSE sendReverseDataPacket ENTRY: AgentID=%d ReverseSequence=%d", connection.AgentID, connection.ReverseSequence)
	connection.ReverseSequence++
	seq := connection.ReverseSequence
	sentTime := time.Now().UnixMilli()

	log.Debugf("[trafficsim] REVERSE sendReverseDataPacket: assigned seq=%d", seq)

	// Track in reverse cycle
	connection.ReverseCycle.mu.Lock()
	connection.ReverseCycle.PacketSeqs = append(connection.ReverseCycle.PacketSeqs, seq)
	connection.ReverseCycle.PacketTimes[seq] = PacketTime{Sent: sentTime}
	log.Debugf("[trafficsim] REVERSE sent seq=%d cyclePacketCount=%d", seq, len(connection.ReverseCycle.PacketSeqs))
	connection.ReverseCycle.mu.Unlock()

	// Build DATA message
	msg := TrafficSimMsg{
		Type: MsgData,
		Data: TrafficSimData{
			Sent: sentTime,
			Seq:  seq,
		},
		SrcAgent:  ts.ThisAgent,
		DstAgent:  connection.AgentID,
		Timestamp: sentTime,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Infof("[trafficsim] Error building reverse DATA: %v", err)
		return
	}

	// Log VoIP settings being used for reverse traffic (first packet of new cycle)
	if len(connection.ReverseCycle.PacketSeqs) == 1 && connection.ReverseTrafficOptions.VoIPMode {
		log.Infof("[trafficsim] REVERSE: Sending reverse with VoIP settings - VoIPMode=%v DSCP=%d Interval=%dms Payload=%d",
			connection.ReverseTrafficOptions.VoIPMode,
			connection.ReverseTrafficOptions.DSCPValue,
			connection.ReverseTrafficOptions.IntervalMs,
			connection.ReverseTrafficOptions.PayloadSize)
	}

	if _, err := conn.WriteToUDP(msgBytes, addr); err != nil {
		log.Infof("[trafficsim] Failed to send reverse DATA to agent %d: %v", connection.AgentID, err)
	}

	connection.PacketsSent++

	// Rotate the reverse cycle when complete. VoIP mode reports on a time basis
	// (mirroring the client's VoIPReportIntervalSec reporting); non-VoIP rotates
	// per TrafficSimReportSeq packets.
	var cycleDone bool
	if connection.ReverseTrafficOptions.VoIPMode {
		cycleDone = time.Since(connection.ReverseCycle.StartTime) >= time.Duration(VoIPReportIntervalSec)*time.Second
	} else {
		cycleDone = len(connection.ReverseCycle.PacketSeqs) >= TrafficSimReportSeq
	}
	if cycleDone {
		completedCycle := connection.ReverseCycle

		// Rotate immediately — NEVER block here waiting for ACKs. This code runs
		// on the server's single read-loop goroutine: blocking stalls ACK
		// processing for BOTH directions, which shows up on the client as huge
		// false loss and inflated RTT on the forward path.
		connection.PrevReverseCycle = completedCycle
		connection.ReverseCycle = &CycleTracker{
			StartSeq:     connection.ReverseSequence + 1,
			StartTime:    time.Now(),
			PacketSeqs:   make([]int, 0, TrafficSimReportSeq),
			PacketTimes:  make(map[int]PacketTime),
			receivedSeqs: make(map[int]int),
		}
		connection.LastReportTime = time.Now()

		// Late ACKs keep landing in the completed cycle via PrevReverseCycle.
		// Finalize (mark stragglers lost) and report once the ACK window passes.
		probeID := connection.ClientProbeID
		agentID := connection.AgentID
		target := connection.Addr.String()
		time.AfterFunc(TrafficSimTimeout+500*time.Millisecond, func() {
			finalizeReverseCycle(completedCycle)
			ts.reportCycleStats(completedCycle, probeID, agentID, target)
		})
	}
}

// finalizeReverseCycle marks every packet that never received an ACK as timed
// out. Called after the ACK grace window, off the read loop.
func finalizeReverseCycle(cycle *CycleTracker) {
	cycle.mu.Lock()
	defer cycle.mu.Unlock()
	for _, seq := range cycle.PacketSeqs {
		if pt, ok := cycle.PacketTimes[seq]; ok && pt.Received == 0 && !pt.TimedOut {
			pt.TimedOut = true
			cycle.PacketTimes[seq] = pt
			cycle.consecutiveLoss++
		}
	}
	if cycle.consecutiveLoss > cycle.maxConsecutiveLoss {
		cycle.maxConsecutiveLoss = cycle.consecutiveLoss
	}
}

// handleReverseAck processes ACK from client for server's reverse DATA packet
func (ts *TrafficSim) handleReverseAck(connection *AgentConnection, data TrafficSimData) {
	seq := data.Seq
	recvTime := time.Now().UnixMilli()

	// Route by sequence: ReverseSequence is monotonic across cycles, so an ACK
	// with seq below the current cycle's StartSeq belongs to the previous
	// (rotated, not yet reported) cycle.
	cycle := connection.ReverseCycle
	if cycle == nil {
		return
	}
	if prev := connection.PrevReverseCycle; prev != nil && seq < cycle.StartSeq {
		cycle = prev
	}
	cycle.mu.Lock()
	defer cycle.mu.Unlock()

	log.Debugf("[trafficsim] REVERSE handleReverseAck START: seq=%d", seq)

	// Track duplicate/out-of-order and burst loss
	cycle.receivedSeqs[seq]++
	receiveCount := cycle.receivedSeqs[seq]

	if receiveCount > 1 {
		cycle.duplicates++
		// Reset consecutive loss counter when we receive a packet (even duplicate)
		if cycle.consecutiveLoss > 0 {
			if cycle.consecutiveLoss > cycle.maxConsecutiveLoss {
				cycle.maxConsecutiveLoss = cycle.consecutiveLoss
			}
			cycle.totalBursts++
			cycle.consecutiveLoss = 0
		}
	} else if cycle.lastReceivedSeq > 0 && seq < cycle.lastReceivedSeq {
		cycle.outOfOrder++
	}
	cycle.lastReceivedSeq = seq

	// Update packet timing and RFC 3550 jitter
	if pt, ok := cycle.PacketTimes[seq]; ok && pt.Received == 0 {
		pt.Received = recvTime
		cycle.PacketTimes[seq] = pt

		// RFC 3550 jitter calculation for reverse direction
		if cycle.lastTransit > 0 {
			interArrival := float64(recvTime - cycle.lastArrivalTime)
			interTransit := float64(pt.Sent - cycle.lastSentTime)
			D := math.Abs(interArrival - interTransit)
			cycle.rfc3550Jitter = cycle.rfc3550Jitter + (D-cycle.rfc3550Jitter)/16.0
		}
		transit := recvTime - pt.Sent
		cycle.lastTransit = transit
		cycle.lastArrivalTime = recvTime
		cycle.lastSentTime = pt.Sent

		log.Debugf("[trafficsim] REVERSE handleReverseAck seq=%d rtt=%dms jitter=%.2f", seq, recvTime-pt.Sent, cycle.rfc3550Jitter)
	} else if _, ok := cycle.PacketTimes[seq]; ok {
		log.Debugf("[trafficsim] REVERSE handleReverseAck seq=%d ALREADY RECEIVED", seq)
	} else {
		log.Infof("[trafficsim] REVERSE handleReverseAck seq=%d NOT FOUND in PacketTimes (current size=%d) - may be from rotated cycle", seq, len(cycle.PacketTimes))
	}
}

// reportCycleStats calculates and reports stats for a completed reverse cycle
func (ts *TrafficSim) reportCycleStats(cycle *CycleTracker, probeID uint, agentID uint, target string) {
	if ts.DataChan == nil || !ts.isRunning() {
		log.Infof("[trafficsim] REVERSE reportCycleStats skipped: DataChan=%v running=%v", ts.DataChan, ts.isRunning())
		return
	}

	// Calculate stats using the same method as client
	stats := ts.calculateStats(cycle)

	log.Infof("[trafficsim] REVERSE reportCycleStats: probeID=%d agentID=%d target=%s statsLen=%d", probeID, agentID, target, len(stats))
	log.Infof("[trafficsim] REVERSE stats map keys: %v", mapKeys(stats))
	log.Debugf("[trafficsim] REVERSE stats map before marshal: %+v", stats)

	payload, err := json.Marshal(stats)
	if err != nil {
		log.Infof("[trafficsim] Error marshaling reverse stats: %v", err)
		return
	}

	log.Infof("[trafficsim] REVERSE JSON payload: %s", string(payload))

	// Report with the client probe ID for this connection
	select {
	case ts.DataChan <- ProbeData{
		ProbeID:     probeID,
		Triggered:   false,
		CreatedAt:   time.Now(),
		Type:        ProbeType_TRAFFICSIM,
		Payload:     payload,
		Target:      target,
		TargetAgent: agentID,
	}:
		log.Infof("[trafficsim] probe=%d (reverse) agent=%d loss=%.1f%% avgRTT=%.1fms",
			probeID, agentID, stats["lossPercentage"], stats["averageRTT"])
	default:
		log.Infof("[trafficsim] DataChan full, dropping reverse stats")
	}
}

// -------------------- Stop --------------------

// Stop gracefully stops the TrafficSim
func (ts *TrafficSim) Stop() {
	log.Infof("[trafficsim] Stop requested for probe %d", ts.Probe.ID)

	atomic.StoreInt32(&ts.stopping, 1)

	// Wait briefly for current operations
	time.Sleep(100 * time.Millisecond)

	atomic.StoreInt32(&ts.running, 0)

	if ts.stopChan != nil {
		close(ts.stopChan)
	}

	if ts.conn != nil {
		ts.conn.Close()
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Infof("[trafficsim] Stopped probe %d", ts.Probe.ID)
	case <-time.After(5 * time.Second):
		log.Infof("[trafficsim] Timeout waiting for goroutines, probe %d", ts.Probe.ID)
	}
}

// -------------------- Interface Helpers --------------------

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	// Score interfaces
	type candidate struct {
		ip    string
		score int
	}
	var candidates []candidate

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			score := 0
			if ip.IsPrivate() {
				score += 10
				if ip[0] == 192 && ip[1] == 168 {
					score += 5
				}
			}

			candidates = append(candidates, candidate{ip: ip.String(), score: score})
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("no suitable interface found")
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	return candidates[0].ip, nil
}

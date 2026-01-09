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
	TrafficSimReportSeq        = 60 // Packets per cycle before reporting
	TrafficSimDataInterval     = 1  // Seconds between packets
	TrafficSimTimeout          = 2 * time.Second
	TrafficSimRetryInterval    = 5 * time.Second
	TrafficSimGracefulShutdown = 70 * time.Second
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
}

// ClientStats tracks client-side statistics
type ClientStats struct {
	PacketTimes map[int]PacketTime
	mu          sync.RWMutex
}

// -------------------- TrafficSim Main Struct --------------------

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

	// Server mode: allowed agents
	AllowedAgents []uint
	connections   map[uint]*AgentConnection
	connectionsMu sync.RWMutex

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
}

// AgentConnection tracks a client connection on server side
type AgentConnection struct {
	AgentID     uint
	Addr        *net.UDPAddr
	LastSeen    time.Time
	FirstSeen   time.Time
	PacketsRecv int
	PacketsSent int
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
		log.Printf("[trafficsim] Start() exiting for probe %d", ts.Probe.ID)
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
			log.Printf("[trafficsim] Error: %v. Retrying in %v...", err, TrafficSimRetryInterval)
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
	defer ts.conn.Close()

	// Attempt handshake
	if !ts.handshake() {
		return fmt.Errorf("handshake failed")
	}

	log.Printf("[trafficsim] Connected to %s:%d", ts.IPAddress, ts.Port)

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

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
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
		log.Printf("[trafficsim] Error building HELLO: %v", err)
		return false
	}

	conn := ts.getConn()
	if conn == nil {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(TrafficSimTimeout))
	if _, err := conn.Write(msg); err != nil {
		log.Printf("[trafficsim] Failed to send HELLO: %v", err)
		return false
	}

	// Wait for response
	buf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[trafficsim] No HELLO response: %v", err)
		return false
	}

	var resp TrafficSimMsg
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		log.Printf("[trafficsim] Invalid HELLO response: %v", err)
		return false
	}

	if resp.Type == MsgAck || resp.Type == MsgHello {
		log.Printf("[trafficsim] Handshake successful, RTT: %dms", time.Now().UnixMilli()-sentTime)
		ts.lastResponse = time.Now()
		return true
	}

	return false
}

func (ts *TrafficSim) runTestCycles(ctx context.Context, mtrProbe *Probe) {
	for ts.isRunning() && !ts.isStopping() {
		// Start new cycle
		cycle := ts.startCycle()

		log.Printf("[trafficsim] Starting cycle, %d packets", TrafficSimReportSeq)

		// Send packets
		for i := 0; i < TrafficSimReportSeq && ts.isRunning() && !ts.isStopping(); i++ {
			select {
			case <-ctx.Done():
				return
			case <-ts.stopChan:
				return
			default:
			}

			ts.sendDataPacket(cycle)

			// Wait for interval
			select {
			case <-time.After(time.Duration(TrafficSimDataInterval) * time.Second):
			case <-ctx.Done():
				return
			case <-ts.stopChan:
				return
			}
		}

		// Wait for responses
		ts.waitForResponses(ctx, cycle)

		// Calculate and report stats
		stats := ts.calculateStats(cycle)
		ts.reportStats(stats, mtrProbe)

		// Reset sequence for next cycle
		ts.resetSequence()

		// Check for packet loss trigger
		if loss, ok := stats["lossPercentage"].(float64); ok && loss > 5.0 {
			ts.triggerMTR(mtrProbe, loss)
		}

		log.Printf("[trafficsim] Cycle complete: loss=%.1f%%, avgRTT=%.1fms",
			stats["lossPercentage"], stats["averageRTT"])
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
		log.Printf("[trafficsim] Error building DATA: %v", err)
		return false
	}

	conn := ts.getConn()
	if conn == nil {
		return false
	}

	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(msg); err != nil {
		log.Printf("[trafficsim] Send error for seq %d: %v", seq, err)
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
			log.Printf("[trafficsim] Read error: %v", err)
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
		} else {
			// First time receiving this seq - check for out-of-order
			if ts.currentCycle.lastReceivedSeq > 0 && seq < ts.currentCycle.lastReceivedSeq {
				// Packet arrived out of order (lower seq after higher seq)
				ts.currentCycle.outOfOrder++
			}
			ts.currentCycle.lastReceivedSeq = seq
		}

		// Update packet timing (only first receipt)
		if pt, ok := ts.currentCycle.PacketTimes[seq]; ok && pt.Received == 0 {
			pt.Received = recvTime
			ts.currentCycle.PacketTimes[seq] = pt
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
		for _, seq := range cycle.PacketSeqs {
			if pt, ok := cycle.PacketTimes[seq]; ok {
				if pt.Received == 0 && !pt.TimedOut {
					if now-pt.Sent > int64(TrafficSimTimeout.Milliseconds()) {
						pt.TimedOut = true
						cycle.PacketTimes[seq] = pt
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

	return map[string]interface{}{
		"lostPackets":       lost,
		"lossPercentage":    lossPercent,
		"totalPackets":      total,
		"averageRTT":        avgRTT,
		"minRTT":            minRTT,
		"maxRTT":            maxRTT,
		"stdDevRTT":         stdDev,
		"outOfOrder":        cycle.outOfOrder,
		"outOfOrderPercent": outOfOrderPercent,
		"duplicates":        cycle.duplicates,
		"duplicatePercent":  duplicatePercent,
		"timestamp":         time.Now(),
	}
}

func (ts *TrafficSim) reportStats(stats map[string]interface{}, mtrProbe *Probe) {
	if ts.DataChan == nil || !ts.isRunning() {
		return
	}

	payload, err := json.Marshal(stats)
	if err != nil {
		log.Printf("[trafficsim] Error marshaling stats: %v", err)
		return
	}

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
		log.Printf("[trafficsim] DataChan full, dropping stats")
	}
}

func (ts *TrafficSim) triggerMTR(mtrProbe *Probe, lossPercent float64) {
	if mtrProbe == nil {
		return
	}

	log.Printf("[trafficsim] Triggering MTR due to %.1f%% packet loss", lossPercent)
	// The actual MTR execution would be handled by the probe worker
	// This just logs the trigger for now
}

// -------------------- Server Mode --------------------

func (ts *TrafficSim) runServer() error {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", ts.Port)
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

	log.Printf("[trafficsim] Server listening on %s", listenAddr)

	for ts.isRunning() && !ts.isStopping() {
		select {
		case <-ts.stopChan:
			return nil
		default:
		}

		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[trafficsim] Server read error: %v", err)
			continue
		}

		var msg TrafficSimMsg
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}

		// Check if agent is allowed
		if !ts.isAgentAllowed(msg.SrcAgent) {
			log.Printf("[trafficsim] Rejected packet from unauthorized agent %d", msg.SrcAgent)
			continue
		}

		ts.handleServerMessage(conn, remoteAddr, msg)
	}

	return nil
}

func (ts *TrafficSim) isAgentAllowed(agentID uint) bool {
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
	connection, exists := ts.connections[msg.SrcAgent]
	if !exists {
		connection = &AgentConnection{
			AgentID:   msg.SrcAgent,
			Addr:      addr,
			FirstSeen: time.Now(),
		}
		ts.connections[msg.SrcAgent] = connection
		log.Printf("[trafficsim] New connection from agent %d at %s", msg.SrcAgent, addr.String())
	}
	connection.LastSeen = time.Now()
	connection.PacketsRecv++
	ts.connectionsMu.Unlock()

	// Build ACK
	ack, err := ts.buildAckMessage(msg.Data)
	if err != nil {
		return
	}

	if _, err := conn.WriteToUDP(ack, addr); err != nil {
		log.Printf("[trafficsim] Failed to send ACK: %v", err)
	}

	ts.connectionsMu.Lock()
	connection.PacketsSent++
	ts.connectionsMu.Unlock()
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

// -------------------- Stop --------------------

// Stop gracefully stops the TrafficSim
func (ts *TrafficSim) Stop() {
	log.Printf("[trafficsim] Stop requested for probe %d", ts.Probe.ID)

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
		log.Printf("[trafficsim] Stopped probe %d", ts.Probe.ID)
	case <-time.After(5 * time.Second):
		log.Printf("[trafficsim] Timeout waiting for goroutines, probe %d", ts.Probe.ID)
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

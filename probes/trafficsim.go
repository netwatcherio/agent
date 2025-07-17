package probes

import (
	"context"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	TrafficSim_ReportSeq    = 60
	TrafficSim_DataInterval = 1
	RetryInterval           = 5 * time.Second
	PacketTimeout           = 2 * time.Second
	GracefulShutdownTimeout = 70 * time.Second
	ServerReportInterval    = 15 * time.Second
)

type TrafficSim struct {
	// Use atomic for thread-safe access
	Running       int32 // 0 = stopped, 1 = Running
	stopping      int32 // 0 = not stopping, 1 = stopping
	Errored       bool
	ThisAgent     primitive.ObjectID
	OtherAgent    primitive.ObjectID
	Conn          *net.UDPConn
	IPAddress     string
	Port          int64
	IsServer      bool
	LastResponse  time.Time
	AllowedAgents []primitive.ObjectID
	Connections   map[primitive.ObjectID]*Connection
	ConnectionsMu sync.RWMutex
	ClientStats   *ClientStats
	Sequence      int
	DataChan      chan ProbeData
	Probe         *Probe
	localIP       string
	testComplete  chan bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
	currentTestMu sync.RWMutex
	inTestCycle   bool

	// Enhanced tracking
	flowStats        map[string]*FlowStats // key: "src-dst"
	flowStatsMu      sync.RWMutex
	serverStats      *ServerStats
	lastServerReport time.Time
	sync.Mutex
}

type Connection struct {
	Addr         *net.UDPAddr
	LastResponse time.Time
	ExpectedSeq  int
	AgentID      primitive.ObjectID
	ClientStats  *ClientStats
	FlowKey      string // "src-dst" identifier
}

type ClientStats struct {
	DuplicatePackets int                `json:"duplicatePackets"`
	OutOfSequence    int                `json:"outOfSequence"`
	PacketTimes      map[int]PacketTime `json:"-"`
	LastReportTime   time.Time          `json:"lastReportTime"`
	ReportInterval   time.Duration      `json:"reportInterval"`
	ConnectionLost   bool               `json:"connectionLost"`
	mu               sync.RWMutex
}

type ServerStats struct {
	ConnectionCount  int                         `json:"connectionCount"`
	TotalPacketsRecv int64                       `json:"totalPacketsReceived"`
	TotalPacketsSent int64                       `json:"totalPacketsSent"`
	ActiveFlows      map[string]*FlowServerStats `json:"activeFlows"`
	LastCleanup      time.Time                   `json:"lastCleanup"`
	mu               sync.RWMutex
}

type FlowServerStats struct {
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	PacketsRecv  int64     `json:"packetsReceived"`
	PacketsSent  int64     `json:"packetsSent"`
	BytesRecv    int64     `json:"bytesReceived"`
	BytesSent    int64     `json:"bytesSent"`
	LastSequence int       `json:"lastSequence"`
	ExpectedSeq  int       `json:"expectedSequence"`
	OutOfOrder   int       `json:"outOfOrder"`
	Duplicates   int       `json:"duplicates"`
}

type FlowStats struct {
	Direction     string                `json:"direction"` // "client-server" or "server-client"
	StartTime     time.Time             `json:"startTime"`
	EndTime       time.Time             `json:"endTime"`
	PacketsSent   int                   `json:"packetsSent"`
	PacketsRecv   int                   `json:"packetsReceived"`
	PacketsLost   int                   `json:"packetsLost"`
	BytesSent     int64                 `json:"bytesSent"`
	BytesRecv     int64                 `json:"bytesReceived"`
	RTTStats      RTTStatistics         `json:"rttStats"`
	JitterStats   JitterStatistics      `json:"jitterStats"`
	PacketDetails map[int]*PacketDetail `json:"-"`
	mu            sync.RWMutex
}

type PacketDetail struct {
	Sequence   int           `json:"sequence"`
	SentTime   time.Time     `json:"sentTime"`
	RecvTime   time.Time     `json:"recvTime,omitempty"`
	RTT        time.Duration `json:"rtt,omitempty"`
	Size       int           `json:"size"`
	TimedOut   bool          `json:"timedOut"`
	Duplicate  bool          `json:"duplicate"`
	OutOfOrder bool          `json:"outOfOrder"`
	SendFailed bool          `json:"sendFailed"` // New field to track send failures
}

type RTTStatistics struct {
	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	Avg    time.Duration `json:"avg"`
	StdDev time.Duration `json:"stdDev"`
	P50    time.Duration `json:"p50"`
	P95    time.Duration `json:"p95"`
	P99    time.Duration `json:"p99"`
}

type JitterStatistics struct {
	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	Avg    time.Duration `json:"avg"`
	StdDev time.Duration `json:"stdDev"`
}

type PacketTime struct {
	Sent       int64
	Received   int64
	TimedOut   bool
	SendFailed bool // New field to track send failures
	Size       int
}

const (
	TrafficSim_HELLO  TrafficSimMsgType = "HELLO"
	TrafficSim_ACK    TrafficSimMsgType = "ACK"
	TrafficSim_DATA   TrafficSimMsgType = "DATA"
	TrafficSim_REPORT TrafficSimMsgType = "REPORT" // Server reports to client
	TrafficSim_PING   TrafficSimMsgType = "PING"   // Bidirectional keepalive
	TrafficSim_PONG   TrafficSimMsgType = "PONG"
)

type TrafficSimMsgType string

type TrafficSimMsg struct {
	Type      TrafficSimMsgType  `json:"type"`
	Data      TrafficSimData     `json:"data"`
	Src       primitive.ObjectID `json:"src"`
	Dst       primitive.ObjectID `json:"dst"`
	Timestamp int64              `json:"timestamp"`
	Size      int                `json:"size"`
}

type TrafficSimData struct {
	Sent     int64                  `json:"sent"`
	Received int64                  `json:"received"`
	Seq      int                    `json:"seq"`
	Report   map[string]interface{} `json:"report,omitempty"`
}

// Initialize flow tracking
func (ts *TrafficSim) initFlowTracking() {
	ts.flowStats = make(map[string]*FlowStats)
	if ts.IsServer {
		ts.serverStats = &ServerStats{
			ActiveFlows: make(map[string]*FlowServerStats),
			LastCleanup: time.Now(),
		}
	}
}

// Get or create flow stats
func (ts *TrafficSim) getOrCreateFlow(src, dst primitive.ObjectID, direction string) *FlowStats {
	flowKey := fmt.Sprintf("%s-%s", src.Hex(), dst.Hex())

	ts.flowStatsMu.Lock()
	defer ts.flowStatsMu.Unlock()

	if flow, exists := ts.flowStats[flowKey]; exists {
		return flow
	}

	flow := &FlowStats{
		Direction:     direction,
		StartTime:     time.Now(),
		PacketDetails: make(map[int]*PacketDetail),
	}
	ts.flowStats[flowKey] = flow
	return flow
}

// Record packet sent (updated to handle send failures)
func (ts *TrafficSim) recordPacketSent(flow *FlowStats, seq int, size int, sendFailed bool) {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	flow.PacketsSent++
	if !sendFailed {
		flow.BytesSent += int64(size)
	}

	detail := &PacketDetail{
		Sequence:   seq,
		SentTime:   time.Now(),
		Size:       size,
		SendFailed: sendFailed,
	}

	// If send failed, immediately mark as timed out
	if sendFailed {
		detail.TimedOut = true
		flow.PacketsLost++
	}

	flow.PacketDetails[seq] = detail
}

// Record packet received
func (ts *TrafficSim) recordPacketReceived(flow *FlowStats, seq int, sentTime int64) {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	now := time.Now()
	flow.PacketsRecv++
	flow.EndTime = now

	if detail, exists := flow.PacketDetails[seq]; exists {
		detail.RecvTime = now
		detail.RTT = now.Sub(detail.SentTime)
		flow.BytesRecv += int64(detail.Size)
	}
}

// Calculate comprehensive flow statistics
func (ts *TrafficSim) calculateFlowStats(flow *FlowStats) map[string]interface{} {
	flow.mu.RLock()
	defer flow.mu.RUnlock()

	var rtts []time.Duration
	var jitters []time.Duration
	var lastRTT time.Duration

	// Sort packets by sequence
	var sequences []int
	for seq := range flow.PacketDetails {
		sequences = append(sequences, seq)
	}
	sort.Ints(sequences)

	// Collect RTT data and calculate jitter
	for _, seq := range sequences {
		detail := flow.PacketDetails[seq]
		if !detail.RecvTime.IsZero() && detail.RTT > 0 && !detail.SendFailed {
			rtts = append(rtts, detail.RTT)
			if lastRTT > 0 {
				jitter := detail.RTT - lastRTT
				if jitter < 0 {
					jitter = -jitter
				}
				jitters = append(jitters, jitter)
			}
			lastRTT = detail.RTT
		} else if detail.TimedOut || detail.SendFailed {
			// Already counted in PacketsLost during recordPacketSent or waitForResponses
		}
	}

	// Calculate RTT statistics
	rttStats := calculateRTTStats(rtts)
	jitterStats := calculateJitterStats(jitters)

	// Update flow stats
	flow.RTTStats = rttStats
	flow.JitterStats = jitterStats

	// Calculate loss percentage
	totalPackets := flow.PacketsSent
	lossPercentage := float64(0)
	if totalPackets > 0 {
		lossPercentage = (float64(flow.PacketsLost) / float64(totalPackets)) * 100
	}

	// Calculate throughput
	duration := flow.EndTime.Sub(flow.StartTime).Seconds()
	throughputSend := float64(0)
	throughputRecv := float64(0)
	if duration > 0 {
		throughputSend = float64(flow.BytesSent*8) / duration / 1e6 // Mbps
		throughputRecv = float64(flow.BytesRecv*8) / duration / 1e6 // Mbps
	}

	return map[string]interface{}{
		"direction":       flow.Direction,
		"duration":        flow.EndTime.Sub(flow.StartTime).Seconds(),
		"packetsSent":     flow.PacketsSent,
		"packetsReceived": flow.PacketsRecv,
		"packetsLost":     flow.PacketsLost,
		"lossPercentage":  lossPercentage,
		"bytesSent":       flow.BytesSent,
		"bytesReceived":   flow.BytesRecv,
		"throughputSend":  throughputSend,
		"throughputRecv":  throughputRecv,
		"rttStats":        rttStats,
		"jitterStats":     jitterStats,
	}
}

func calculateRTTStats(rtts []time.Duration) RTTStatistics {
	if len(rtts) == 0 {
		return RTTStatistics{}
	}

	// Sort RTTs for percentile calculations
	sort.Slice(rtts, func(i, j int) bool {
		return rtts[i] < rtts[j]
	})

	// Calculate basic stats
	var sum time.Duration
	min := rtts[0]
	max := rtts[len(rtts)-1]

	for _, rtt := range rtts {
		sum += rtt
	}
	avg := sum / time.Duration(len(rtts))

	// Calculate standard deviation
	var variance float64
	avgFloat := float64(avg)
	for _, rtt := range rtts {
		diff := float64(rtt) - avgFloat
		variance += diff * diff
	}
	stdDev := time.Duration(math.Sqrt(variance / float64(len(rtts))))

	// Calculate percentiles
	p50 := rtts[len(rtts)*50/100]
	p95 := rtts[len(rtts)*95/100]
	p99 := rtts[len(rtts)*99/100]

	return RTTStatistics{
		Min:    min,
		Max:    max,
		Avg:    avg,
		StdDev: stdDev,
		P50:    p50,
		P95:    p95,
		P99:    p99,
	}
}

func calculateJitterStats(jitters []time.Duration) JitterStatistics {
	if len(jitters) == 0 {
		return JitterStatistics{}
	}

	var sum time.Duration
	min := jitters[0]
	max := jitters[0]

	for _, jitter := range jitters {
		sum += jitter
		if jitter < min {
			min = jitter
		}
		if jitter > max {
			max = jitter
		}
	}
	avg := sum / time.Duration(len(jitters))

	// Calculate standard deviation
	var variance float64
	avgFloat := float64(avg)
	for _, jitter := range jitters {
		diff := float64(jitter) - avgFloat
		variance += diff * diff
	}
	stdDev := time.Duration(math.Sqrt(variance / float64(len(jitters))))

	return JitterStatistics{
		Min:    min,
		Max:    max,
		Avg:    avg,
		StdDev: stdDev,
	}
}

// Server-side flow tracking
func (ts *TrafficSim) updateServerFlowStats(agentID primitive.ObjectID, msgType TrafficSimMsgType, size int, seq int) {
	if ts.serverStats == nil {
		return
	}

	flowKey := agentID.Hex()

	ts.serverStats.mu.Lock()
	defer ts.serverStats.mu.Unlock()

	flow, exists := ts.serverStats.ActiveFlows[flowKey]
	if !exists {
		flow = &FlowServerStats{
			FirstSeen:   time.Now(),
			ExpectedSeq: 1,
		}
		ts.serverStats.ActiveFlows[flowKey] = flow
	}

	flow.LastSeen = time.Now()

	switch msgType {
	case TrafficSim_DATA:
		flow.PacketsRecv++
		flow.BytesRecv += int64(size)
		ts.serverStats.TotalPacketsRecv++

		// Check sequence ordering
		if seq < flow.LastSequence {
			flow.OutOfOrder++
		} else if seq == flow.LastSequence {
			flow.Duplicates++
		}
		flow.LastSequence = seq

	case TrafficSim_ACK, TrafficSim_PONG, TrafficSim_REPORT:
		flow.PacketsSent++
		flow.BytesSent += int64(size)
		ts.serverStats.TotalPacketsSent++
	}

	// Cleanup old flows periodically
	if time.Since(ts.serverStats.LastCleanup) > 5*time.Minute {
		ts.cleanupOldFlows()
		ts.serverStats.LastCleanup = time.Now()
	}
}

func (ts *TrafficSim) cleanupOldFlows() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for key, flow := range ts.serverStats.ActiveFlows {
		if flow.LastSeen.Before(cutoff) {
			delete(ts.serverStats.ActiveFlows, key)
		}
	}
}

// Generate server report for client
// BIDIRECTIONAL REPORTING EXPLANATION:
// The server generates periodic reports about each connected client flow.
// These reports include:
// - Server->Client statistics (packets/bytes sent from server to client)
// - Client->Server statistics (packets/bytes received from client to server)
// - Flow health metrics (out of order packets, duplicates, etc.)
//
// The client receives these reports and can use them to understand:
// 1. How well its packets are reaching the server (client->server flow)
// 2. How well it's receiving server responses (server->client flow)
// 3. Any asymmetric network issues between the two directions
//
// This enables true bidirectional monitoring where both endpoints have
// visibility into the full duplex communication channel.
func (ts *TrafficSim) generateServerReport() map[string]interface{} {
	if ts.serverStats == nil {
		return nil
	}

	ts.serverStats.mu.RLock()
	defer ts.serverStats.mu.RUnlock()

	flows := make(map[string]interface{})
	for agentID, flow := range ts.serverStats.ActiveFlows {
		// Each flow report contains bidirectional statistics:
		// - packetsReceived: Client->Server direction
		// - packetsSent: Server->Client direction
		// This allows the client to see both directions of traffic
		flows[agentID] = map[string]interface{}{
			"packetsReceived": flow.PacketsRecv, // Client->Server packets
			"packetsSent":     flow.PacketsSent, // Server->Client packets
			"bytesReceived":   flow.BytesRecv,   // Client->Server bytes
			"bytesSent":       flow.BytesSent,   // Server->Client bytes
			"outOfOrder":      flow.OutOfOrder,  // Client->Server sequencing issues
			"duplicates":      flow.Duplicates,  // Client->Server duplicate packets
			"lastSeen":        flow.LastSeen,
			"uptime":          time.Since(flow.FirstSeen).Seconds(),
		}
	}

	return map[string]interface{}{
		"totalConnections": len(ts.serverStats.ActiveFlows),
		"totalPacketsRecv": ts.serverStats.TotalPacketsRecv,
		"totalPacketsSent": ts.serverStats.TotalPacketsSent,
		"activeFlows":      flows,
		"reportTime":       time.Now(),
	}
}

// isRunning returns true if the TrafficSim is Running
func (ts *TrafficSim) isRunning() bool {
	return atomic.LoadInt32(&ts.Running) == 1
}

// isStopping returns true if the TrafficSim is in the process of stopping
func (ts *TrafficSim) isStopping() bool {
	return atomic.LoadInt32(&ts.stopping) == 1
}

// setInTestCycle safely sets the test cycle state
func (ts *TrafficSim) setInTestCycle(state bool) {
	ts.currentTestMu.Lock()
	ts.inTestCycle = state
	ts.currentTestMu.Unlock()
}

// isInTestCycle safely checks if we're in a test cycle
func (ts *TrafficSim) isInTestCycle() bool {
	ts.currentTestMu.RLock()
	defer ts.currentTestMu.RUnlock()
	return ts.inTestCycle
}

func (ts *TrafficSim) buildMessage(msgType TrafficSimMsgType, data TrafficSimData) (string, error) {
	msg := TrafficSimMsg{
		Type:      msgType,
		Data:      data,
		Src:       ts.ThisAgent,
		Dst:       ts.OtherAgent,
		Timestamp: time.Now().UnixMilli(),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message: %w", err)
	}
	msg.Size = len(msgBytes)

	// Re-marshal with size included
	msgBytes, err = json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message with size: %w", err)
	}

	return string(msgBytes), nil
}

func (ts *TrafficSim) runClient(ctx context.Context, mtrProbe *Probe) error {
	ts.Probe = mtrProbe
	ts.initFlowTracking()

	for ts.isRunning() && !ts.isStopping() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentIP, err := getLocalIP()
		if err != nil {
			log.Printf("TrafficSim: Failed to get local IP: %v", err)
			if !ts.waitOrStop(RetryInterval) {
				return nil
			}
			continue
		}

		if ts.localIP != currentIP {
			ts.localIP = currentIP
			log.Printf("TrafficSim: Local IP updated to %s", ts.localIP)
		}

		if err := ts.establishConnection(); err != nil {
			log.Printf("TrafficSim: Connection failed: %v", err)
			// Mark connection as lost for stats purposes
			if ts.ClientStats != nil {
				ts.ClientStats.mu.Lock()
				ts.ClientStats.ConnectionLost = true
				ts.ClientStats.mu.Unlock()
			}
			if !ts.waitOrStop(RetryInterval) {
				return nil
			}
			continue
		}

		// Run the client session
		if err := ts.runClientSession(ctx, mtrProbe); err != nil {
			log.Printf("TrafficSim: Client session error: %v", err)
			if ts.Conn != nil {
				ts.Conn.Close()
			}
			if !ts.waitOrStop(RetryInterval) {
				return nil
			}
			continue
		}
	}

	log.Print("TrafficSim: Client stopped")
	return nil
}

func (ts *TrafficSim) waitOrStop(duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-timer.C:
		return ts.isRunning() && !ts.isStopping()
	case <-ts.stopChan:
		return false
	}
}

func (ts *TrafficSim) establishConnection() error {
	toAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", ts.IPAddress, ts.Port))
	if err != nil {
		return fmt.Errorf("could not resolve %s:%d: %w", ts.IPAddress, ts.Port, err)
	}

	localAddr, err := net.ResolveUDPAddr("udp4", ts.localIP+":0")
	if err != nil {
		return fmt.Errorf("could not resolve local address: %w", err)
	}

	conn, err := net.DialUDP("udp4", localAddr, toAddr)
	if err != nil {
		return fmt.Errorf("unable to connect to %s:%d: %w", ts.IPAddress, ts.Port, err)
	}

	ts.Conn = conn
	ts.ClientStats = &ClientStats{
		LastReportTime: time.Now(),
		ReportInterval: 15 * time.Second,
		PacketTimes:    make(map[int]PacketTime),
		ConnectionLost: false,
	}
	ts.testComplete = make(chan bool, 1)

	if err := ts.sendHello(); err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	log.Printf("TrafficSim: Connection established successfully to %v", ts.OtherAgent.Hex())
	return nil
}

func (ts *TrafficSim) runClientSession(ctx context.Context, mtrProbe *Probe) error {
	errChan := make(chan error, 3) // Increased for ping goroutine
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ts.wg.Add(3)
	go func() {
		defer ts.wg.Done()
		ts.runTestCycles(sessionCtx, errChan, mtrProbe)
	}()
	go func() {
		defer ts.wg.Done()
		ts.receiveDataLoop(sessionCtx, errChan)
	}()
	go func() {
		defer ts.wg.Done()
		ts.runPingLoop(sessionCtx, errChan)
	}()

	select {
	case err := <-errChan:
		cancel()
		return err
	case <-sessionCtx.Done():
		return sessionCtx.Err()
	case <-ts.stopChan:
		cancel()
		return nil
	}
}

// New ping loop for bidirectional keepalive
func (ts *TrafficSim) runPingLoop(ctx context.Context, errChan chan<- error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !ts.isRunning() {
				return
			}

			pingData := TrafficSimData{
				Sent: time.Now().UnixMilli(),
				Seq:  -1, // Special sequence for ping
			}

			pingMsg, err := ts.buildMessage(TrafficSim_PING, pingData)
			if err != nil {
				continue
			}

			if _, err := ts.Conn.Write([]byte(pingMsg)); err != nil {
				log.Printf("TrafficSim: Failed to send ping: %v", err)
			}
		}
	}
}

func (ts *TrafficSim) sendHello() error {
	if !ts.isRunning() {
		return fmt.Errorf("trafficSim is not Running")
	}

	helloMsg, err := ts.buildMessage(TrafficSim_HELLO, TrafficSimData{Sent: time.Now().UnixMilli()})
	if err != nil {
		return err
	}

	if _, err := ts.Conn.Write([]byte(helloMsg)); err != nil {
		return fmt.Errorf("error sending hello message: %w", err)
	}

	msgBuf := make([]byte, 1024) // Increased buffer size
	ts.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := ts.Conn.ReadFromUDP(msgBuf); err != nil {
		return fmt.Errorf("error reading hello response: %w", err)
	}

	return nil
}

func (ts *TrafficSim) runTestCycles(ctx context.Context, errChan chan<- error, mtrProbe *Probe) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !ts.isRunning() {
				return
			}

			// Mark that we're starting a test cycle
			ts.setInTestCycle(true)

			// If we're stopping, don't start a new cycle
			if ts.isStopping() {
				ts.setInTestCycle(false)
				return
			}

			// Reset for new test cycle
			ts.Mutex.Lock()
			ts.Sequence = 0
			ts.Mutex.Unlock()

			ts.ClientStats.mu.Lock()
			ts.ClientStats.PacketTimes = make(map[int]PacketTime)
			ts.ClientStats.mu.Unlock()

			// Get flow for this test cycle
			flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")

			testStartTime := time.Now()
			packetsInTest := TrafficSim_ReportSeq / TrafficSim_DataInterval

			// Send packets for this test cycle
			connectionError := false
			for i := 0; i < packetsInTest; i++ {
				select {
				case <-ctx.Done():
					ts.setInTestCycle(false)
					return
				default:
					// Allow graceful completion of current test if stopping
					if !ts.isRunning() && !ts.isStopping() {
						ts.setInTestCycle(false)
						return
					}

					ts.Mutex.Lock()
					ts.Sequence++
					currentSeq := ts.Sequence
					ts.Mutex.Unlock()

					sentTime := time.Now().UnixMilli()
					data := TrafficSimData{Sent: sentTime, Seq: currentSeq}
					dataMsg, err := ts.buildMessage(TrafficSim_DATA, data)
					if err != nil {
						errChan <- fmt.Errorf("error building data message: %w", err)
						ts.setInTestCycle(false)
						return
					}

					msgSize := len(dataMsg)
					_, sendErr := ts.Conn.Write([]byte(dataMsg))

					// Handle send failures
					if sendErr != nil {
						if netErr, ok := sendErr.(net.Error); ok && netErr.Temporary() {
							log.Printf("TrafficSim: Temporary error sending data message: %v", sendErr)
							// Record as sent but failed
							ts.recordPacketSent(flow, currentSeq, msgSize, true)

							ts.ClientStats.mu.Lock()
							ts.ClientStats.PacketTimes[currentSeq] = PacketTime{
								Sent:       sentTime,
								Size:       msgSize,
								SendFailed: true,
								TimedOut:   true,
							}
							ts.ClientStats.mu.Unlock()
							continue
						}
						// Non-temporary error, connection likely lost
						connectionError = true
						// Record remaining packets as failed
						for j := i; j < packetsInTest; j++ {
							if j > i {
								ts.Mutex.Lock()
								ts.Sequence++
								currentSeq = ts.Sequence
								ts.Mutex.Unlock()
							}
							ts.recordPacketSent(flow, currentSeq, msgSize, true)

							ts.ClientStats.mu.Lock()
							ts.ClientStats.PacketTimes[currentSeq] = PacketTime{
								Sent:       sentTime,
								Size:       msgSize,
								SendFailed: true,
								TimedOut:   true,
							}
							ts.ClientStats.mu.Unlock()
						}
						break
					}

					// Record successful packet sent
					ts.recordPacketSent(flow, currentSeq, msgSize, false)

					ts.ClientStats.mu.Lock()
					ts.ClientStats.PacketTimes[currentSeq] = PacketTime{
						Sent:       sentTime,
						Size:       msgSize,
						SendFailed: false,
					}
					ts.ClientStats.mu.Unlock()

					// Wait for the interval before sending next packet
					select {
					case <-time.After(TrafficSim_DataInterval * time.Second):
					case <-ctx.Done():
						ts.setInTestCycle(false)
						return
					}
				}
			}

			if connectionError {
				ts.setInTestCycle(false)
				errChan <- fmt.Errorf("connection lost during packet transmission")
				return
			}

			// Wait for responses (only for packets that were sent successfully)
			log.Printf("TrafficSim: Finished sending %d packets, waiting for responses...", packetsInTest)
			ts.waitForResponses(ctx, packetsInTest)

			// Calculate and report stats
			ts.reportEnhancedStats(mtrProbe)

			// Mark test cycle as complete
			ts.setInTestCycle(false)

			// If we're stopping, exit after completing the test
			if ts.isStopping() {
				log.Print("TrafficSim: Completed final test cycle before shutdown")
				return
			}

			// Small delay before next cycle
			select {
			case <-time.After(1 * time.Second):
			case <-ctx.Done():
				return
			}

			log.Printf("TrafficSim: Test cycle completed in %v", time.Since(testStartTime))
		}
	}
}

func (ts *TrafficSim) waitForResponses(ctx context.Context, packetsInTest int) {
	waitStart := time.Now()
	maxWaitTime := PacketTimeout + (500 * time.Millisecond)
	checkInterval := 50 * time.Millisecond

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for time.Since(waitStart) < maxWaitTime {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !ts.isRunning() && !ts.isStopping() {
				return
			}

			ts.ClientStats.mu.Lock()
			allComplete := true
			now := time.Now().UnixMilli()

			for seq := 1; seq <= packetsInTest; seq++ {
				if pTime, ok := ts.ClientStats.PacketTimes[seq]; ok {
					// Skip packets that failed to send
					if pTime.SendFailed {
						continue
					}

					if pTime.Received == 0 && !pTime.TimedOut {
						if now-pTime.Sent > int64(PacketTimeout.Milliseconds()) {
							pTime.TimedOut = true
							ts.ClientStats.PacketTimes[seq] = pTime

							// Mark packet as timed out in flow
							flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
							flow.mu.Lock()
							if detail, exists := flow.PacketDetails[seq]; exists {
								detail.TimedOut = true
								flow.PacketsLost++
							}
							flow.mu.Unlock()

							log.Printf("TrafficSim: Packet %d timed out", seq)
						} else {
							allComplete = false
						}
					}
				}
			}
			ts.ClientStats.mu.Unlock()

			if allComplete {
				log.Print("TrafficSim: All packets complete or timed out")
				return
			}
		}
	}
}

func (ts *TrafficSim) reportEnhancedStats(probe *Probe) {
	// Report traditional stats
	ts.ClientStats.mu.RLock()
	stats := ts.calculateStats(probe)
	ts.ClientStats.mu.RUnlock()

	// Add flow statistics
	flowStats := make(map[string]interface{})
	ts.flowStatsMu.RLock()
	for flowKey, flow := range ts.flowStats {
		flowStats[flowKey] = ts.calculateFlowStats(flow)
	}
	ts.flowStatsMu.RUnlock()

	stats["flows"] = flowStats
	stats["timestamp"] = time.Now()

	if ts.DataChan != nil && ts.isRunning() {
		if ts.Probe.ID == primitive.NilObjectID {
			log.Warn("TrafficSim: Skipping reportStats due to empty ProbeID")
			return
		}

		reportingAgent, err := primitive.ObjectIDFromHex(os.Getenv("ID"))
		if err != nil {
			log.Printf("TrafficSim: Failed to get reporting agent ID: %v", err)
			return
		}

		select {
		case ts.DataChan <- ProbeData{
			ProbeID:   ts.Probe.ID,
			Triggered: false,
			CreatedAt: time.Now(),
			Data:      stats,
			Target: ProbeTarget{
				Target: string(ProbeType_TRAFFICSIM) + "%%%" + ts.IPAddress + ":" + strconv.FormatInt(ts.Port, 10),
				Agent:  ts.Probe.Config.Target[0].Agent,
				Group:  reportingAgent,
			},
		}:
		default:
			log.Print("TrafficSim: DataChan full, dropping stats report")
		}
	}
}

func (ts *TrafficSim) receiveDataLoop(ctx context.Context, errChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !ts.isRunning() && !ts.isStopping() {
				return
			}

			msgBuf := make([]byte, 2048) // Increased buffer for reports
			ts.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			msgLen, _, err := ts.Conn.ReadFromUDP(msgBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Printf("TrafficSim: Temporary error reading from UDP: %v", err)
					continue
				}
				errChan <- fmt.Errorf("error reading from UDP: %w", err)
				return
			}

			var tsMsg TrafficSimMsg
			if err := json.Unmarshal(msgBuf[:msgLen], &tsMsg); err != nil {
				log.Printf("TrafficSim: Error unmarshalling message: %v", err)
				continue
			}

			switch tsMsg.Type {
			case TrafficSim_ACK:
				ts.handleACK(tsMsg.Data)
			case TrafficSim_REPORT:
				ts.handleServerReport(tsMsg.Data)
			case TrafficSim_PONG:
				ts.handlePong(tsMsg.Data)
			}
		}
	}
}

func (ts *TrafficSim) handleACK(data TrafficSimData) {
	seq := data.Seq
	receivedTime := time.Now().UnixMilli()

	ts.ClientStats.mu.Lock()
	defer ts.ClientStats.mu.Unlock()

	if pTime, ok := ts.ClientStats.PacketTimes[seq]; ok {
		if pTime.Received == 0 && !pTime.TimedOut && !pTime.SendFailed {
			pTime.Received = receivedTime
			ts.ClientStats.PacketTimes[seq] = pTime

			// Update flow stats
			flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
			ts.recordPacketReceived(flow, seq, pTime.Sent)

			log.Printf("TrafficSim: Received ACK for packet %d, RTT: %dms", seq, receivedTime-pTime.Sent)
		} else if pTime.TimedOut {
			log.Printf("TrafficSim: Received late ACK for packet %d (already marked as timed out)", seq)
		} else if pTime.SendFailed {
			log.Printf("TrafficSim: Received ACK for packet %d that failed to send", seq)
		}
	}

	ts.LastResponse = time.Now()
}

// Handle server reports for bidirectional monitoring
// The client processes these reports to understand:
// 1. Server's view of the client->server flow
// 2. Server's transmission statistics (server->client flow)
// 3. Any discrepancies between what client sent vs what server received
func (ts *TrafficSim) handleServerReport(data TrafficSimData) {
	if data.Report != nil {
		log.Printf("TrafficSim: Received server report: %+v", data.Report)

		// TODO: Future enhancement - compare server's view with client's view
		// to detect asymmetric packet loss or network issues
		// For example:
		// - Client sent 60 packets but server only received 55
		// - Server sent 60 ACKs but client only received 50
		// This would indicate different loss rates in each direction
	}
}

func (ts *TrafficSim) handlePong(data TrafficSimData) {
	rtt := time.Now().UnixMilli() - data.Sent
	log.Printf("TrafficSim: Received PONG, RTT: %dms", rtt)
	ts.LastResponse = time.Now()
}

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no suitable local IP address found")
}

func (ts *TrafficSim) calculateStats(mtrProbe *Probe) map[string]interface{} {
	var totalRTT, minRTT, maxRTT int64
	var rtts []float64
	lostPackets := 0
	sendFailures := 0
	outOfOrder := 0
	duplicatePackets := 0
	receivedSequences := []int{}

	// Sort keys to process packets in sequence order
	var keys []int
	for k := range ts.ClientStats.PacketTimes {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// First pass: collect RTT data and identify lost packets
	for _, seq := range keys {
		pTime := ts.ClientStats.PacketTimes[seq]

		// Count send failures separately
		if pTime.SendFailed {
			sendFailures++
			lostPackets++
			log.Printf("TrafficSim: Packet %d failed to send", seq)
			continue
		}

		if pTime.Received == 0 || pTime.TimedOut {
			lostPackets++
			log.Printf("TrafficSim: Packet %d lost (timeout)", seq)
			continue
		}

		receivedSequences = append(receivedSequences, seq)
		rtt := pTime.Received - pTime.Sent
		rtts = append(rtts, float64(rtt))
		totalRTT += rtt

		if minRTT == 0 || rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}

	// Check for out of order packets
	for i := 1; i < len(receivedSequences); i++ {
		if receivedSequences[i] < receivedSequences[i-1] {
			outOfOrder++
			log.Printf("TrafficSim: Out of order: seq %d received after seq %d",
				receivedSequences[i], receivedSequences[i-1])
		}
	}

	// Calculate statistics
	avgRTT := float64(0)
	stdDevRTT := float64(0)
	if len(rtts) > 0 {
		avgRTT = float64(totalRTT) / float64(len(rtts))

		// Calculate standard deviation
		for _, rtt := range rtts {
			stdDevRTT += math.Pow(rtt-avgRTT, 2)
		}
		stdDevRTT = math.Sqrt(stdDevRTT / float64(len(rtts)))
	}

	totalPackets := len(ts.ClientStats.PacketTimes)
	lossPercentage := float64(0)
	if totalPackets > 0 {
		lossPercentage = (float64(lostPackets) / float64(totalPackets)) * 100
	}

	log.Printf("TrafficSim: Stats - Total: %d, Lost: %d (%.2f%%), Send Failures: %d, Out of Order: %d, Avg RTT: %.2fms",
		totalPackets, lostPackets, lossPercentage, sendFailures, outOfOrder, avgRTT)

	// Trigger MTR if packet loss exceeds threshold
	if totalPackets > 0 && lossPercentage > 5.0 && ts.isRunning() && !ts.isStopping() {
		ts.triggerMTR(mtrProbe, lossPercentage)
	}

	return map[string]interface{}{
		"lostPackets":      lostPackets,
		"sendFailures":     sendFailures,
		"lossPercentage":   lossPercentage,
		"outOfSequence":    outOfOrder,
		"duplicatePackets": duplicatePackets,
		"averageRTT":       avgRTT,
		"minRTT":           minRTT,
		"maxRTT":           maxRTT,
		"stdDevRTT":        stdDevRTT,
		"totalPackets":     totalPackets,
		"reportTime":       time.Now(),
		"connectionLost":   ts.ClientStats.ConnectionLost,
	}
}

func (ts *TrafficSim) triggerMTR(mtrProbe *Probe, lossPercentage float64) {
	if mtrProbe == nil || len(mtrProbe.Config.Target) == 0 {
		return
	}

	mtr, err := Mtr(mtrProbe, true)
	if err != nil {
		log.Printf("TrafficSim: MTR error: %v", err)
		return
	}

	if ts.DataChan != nil && ts.isRunning() {
		reportingAgent, err := primitive.ObjectIDFromHex(os.Getenv("ID"))
		if err != nil {
			log.Printf("TrafficSim: Failed to get reporting agent ID: %v", err)
			return
		}

		select {
		case ts.DataChan <- ProbeData{
			ProbeID:   mtrProbe.ID,
			Triggered: true,
			Data:      mtr,
			Target: ProbeTarget{
				Target: string(ProbeType_MTR) + "%%%" + mtrProbe.Config.Target[0].Target,
				Agent:  mtrProbe.Config.Target[0].Agent,
				Group:  reportingAgent,
			},
		}:
			log.Printf("TrafficSim: Triggered MTR for %s due to %.2f%% packet loss",
				mtrProbe.Config.Target[0].Target, lossPercentage)
		default:
			log.Print("TrafficSim: DataChan full, dropping MTR trigger")
		}
	}
}

func (ts *TrafficSim) runServer() error {
	ts.initFlowTracking()

	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", ts.localIP, ts.Port))
	if err != nil {
		return fmt.Errorf("unable to resolve address: %w", err)
	}

	ln, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("unable to listen on %s:%d: %w", ts.localIP, ts.Port, err)
	}
	defer ln.Close()

	log.Printf("TrafficSim: Server listening on %s:%d", ts.localIP, ts.Port)

	ts.Connections = make(map[primitive.ObjectID]*Connection)
	ts.lastServerReport = time.Now()

	// Start server report ticker
	reportTicker := time.NewTicker(ServerReportInterval)
	defer reportTicker.Stop()

	// Set read timeout to check status periodically
	for ts.isRunning() {
		select {
		case <-reportTicker.C:
			ts.sendServerReports(ln)
		default:
			msgBuf := make([]byte, 2048)
			ln.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			msgLen, remoteAddr, err := ln.ReadFromUDP(msgBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Printf("TrafficSim: Temporary error reading from UDP: %v", err)
					continue
				}
				return fmt.Errorf("error reading from UDP: %w", err)
			}

			ts.wg.Add(1)
			go func() {
				defer ts.wg.Done()
				ts.handleConnection(ln, remoteAddr, msgBuf[:msgLen])
			}()
		}
	}

	log.Print("TrafficSim: Server stopped")
	return nil
}

// Send periodic reports to all connected clients
// These reports enable bidirectional monitoring by sharing the server's
// perspective of each flow with the respective clients
func (ts *TrafficSim) sendServerReports(conn *net.UDPConn) {
	report := ts.generateServerReport()
	if report == nil {
		return
	}

	ts.ConnectionsMu.RLock()
	connections := make([]*Connection, 0, len(ts.Connections))
	for _, conn := range ts.Connections {
		connections = append(connections, conn)
	}
	ts.ConnectionsMu.RUnlock()

	for _, connection := range connections {
		reportData := TrafficSimData{
			Sent:   time.Now().UnixMilli(),
			Report: report,
		}

		reportMsg, err := ts.buildMessage(TrafficSim_REPORT, reportData)
		if err != nil {
			continue
		}

		if _, err := conn.WriteToUDP([]byte(reportMsg), connection.Addr); err != nil {
			log.Printf("TrafficSim: Failed to send report to %s: %v", connection.AgentID.Hex(), err)
		}
	}
}

func (ts *TrafficSim) handleConnection(conn *net.UDPConn, addr *net.UDPAddr, msg []byte) {
	if !ts.isRunning() {
		return
	}

	var tsMsg TrafficSimMsg
	if err := json.Unmarshal(msg, &tsMsg); err != nil {
		log.Printf("TrafficSim: Error unmarshalling message: %v", err)
		return
	}

	if !ts.isAgentAllowed(tsMsg.Src) {
		log.Printf("TrafficSim: Ignoring message from unknown agent: %v", tsMsg.Src)
		return
	}

	// Update server flow stats
	ts.updateServerFlowStats(tsMsg.Src, tsMsg.Type, tsMsg.Size, tsMsg.Data.Seq)

	ts.ConnectionsMu.Lock()
	connection, exists := ts.Connections[tsMsg.Src]
	if !exists {
		flowKey := fmt.Sprintf("%s-%s", tsMsg.Src.Hex(), ts.ThisAgent.Hex())
		connection = &Connection{
			Addr:         addr,
			LastResponse: time.Now(),
			AgentID:      tsMsg.Src,
			FlowKey:      flowKey,
		}
		ts.Connections[tsMsg.Src] = connection
	}
	ts.ConnectionsMu.Unlock()

	switch tsMsg.Type {
	case TrafficSim_HELLO:
		ts.sendACK(conn, addr, TrafficSimData{Sent: time.Now().UnixMilli()})
	case TrafficSim_DATA:
		ts.handleData(conn, addr, tsMsg.Data, connection)
	case TrafficSim_PING:
		ts.handlePing(conn, addr, tsMsg.Data)
	}
}

func (ts *TrafficSim) handlePing(conn *net.UDPConn, addr *net.UDPAddr, data TrafficSimData) {
	pongData := TrafficSimData{
		Sent:     data.Sent,
		Received: time.Now().UnixMilli(),
	}

	pongMsg, err := ts.buildMessage(TrafficSim_PONG, pongData)
	if err != nil {
		log.Printf("TrafficSim: Error building pong message: %v", err)
		return
	}

	if _, err := conn.WriteToUDP([]byte(pongMsg), addr); err != nil {
		log.Printf("TrafficSim: Error sending PONG: %v", err)
	}
}

func (ts *TrafficSim) sendACK(conn *net.UDPConn, addr *net.UDPAddr, data TrafficSimData) {
	if !ts.isRunning() {
		return
	}

	replyMsg, err := ts.buildMessage(TrafficSim_ACK, data)
	if err != nil {
		log.Printf("TrafficSim: Error building reply message: %v", err)
		return
	}

	if _, err := conn.WriteToUDP([]byte(replyMsg), addr); err != nil {
		log.Printf("TrafficSim: Error sending ACK: %v", err)
	}
}

func (ts *TrafficSim) handleData(conn *net.UDPConn, addr *net.UDPAddr, data TrafficSimData, connection *Connection) {
	connection.LastResponse = time.Now()

	log.Printf("TrafficSim: Received data from %s: Seq %d", addr.String(), data.Seq)

	ackData := TrafficSimData{
		Sent:     data.Sent,
		Received: time.Now().UnixMilli(),
		Seq:      data.Seq,
	}
	ts.sendACK(conn, addr, ackData)
}

func (ts *TrafficSim) isAgentAllowed(agentID primitive.ObjectID) bool {
	ts.Mutex.Lock()
	defer ts.Mutex.Unlock()

	for _, allowedAgent := range ts.AllowedAgents {
		if allowedAgent == agentID {
			return true
		}
	}
	return false
}

func (ts *TrafficSim) Start(mtrProbe *Probe) {
	// Set Running state
	atomic.StoreInt32(&ts.Running, 1)
	atomic.StoreInt32(&ts.stopping, 0)
	ts.stopChan = make(chan struct{})

	defer func() {
		log.Printf("TrafficSim: Start() exiting for probe %s", ts.Probe.ID.Hex())
		atomic.StoreInt32(&ts.Running, 0)
		if ts.Conn != nil {
			ts.Conn.Close()
		}
	}()

	ctx := context.Background()

	for ts.isRunning() {
		var err error
		ts.localIP, err = getLocalIP()
		if err != nil {
			log.Printf("TrafficSim: Failed to get local IP: %v", err)
			if !ts.waitOrStop(RetryInterval) {
				return
			}
			continue
		}

		if ts.IsServer {
			err = ts.runServer()
		} else {
			err = ts.runClient(ctx, mtrProbe)
		}

		if err != nil {
			log.Printf("TrafficSim: Error occurred: %v. Retrying in %v...", err, RetryInterval)
			if !ts.waitOrStop(RetryInterval) {
				return
			}
		}
	}
}

// Stop gracefully stops the TrafficSim instance
func (ts *TrafficSim) Stop() {
	log.Printf("TrafficSim: Stop requested for probe %s", ts.Probe.ID.Hex())

	// Mark that we're stopping
	atomic.StoreInt32(&ts.stopping, 1)

	// If we're in a test cycle, wait for it to complete
	if ts.isInTestCycle() {
		log.Print("TrafficSim: Waiting for current test cycle to complete...")

		gracefulCtx, cancel := context.WithTimeout(context.Background(), GracefulShutdownTimeout)
		defer cancel()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-gracefulCtx.Done():
				log.Print("TrafficSim: Graceful shutdown timeout reached, forcing stop")
				goto shutdown
			case <-ticker.C:
				if !ts.isInTestCycle() {
					log.Print("TrafficSim: Test cycle completed, proceeding with shutdown")
					goto shutdown
				}
			}
		}
	}

shutdown:
	// Now stop Running
	atomic.StoreInt32(&ts.Running, 0)

	// Signal stop to all goroutines
	if ts.stopChan != nil {
		close(ts.stopChan)
	}

	// Close connection
	if ts.Conn != nil {
		ts.Conn.Close()
	}

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Print("TrafficSim: All goroutines stopped")
	case <-time.After(5 * time.Second):
		log.Print("TrafficSim: Timeout waiting for goroutines to stop")
	}

	log.Printf("TrafficSim: Stopped probe %s", ts.Probe.ID.Hex())
}

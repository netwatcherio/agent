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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CycleTracker tracks packets for a specific reporting cycle
type CycleTracker struct {
	StartSeq    int
	EndSeq      int
	PacketSeqs  []int // All packet sequences in this cycle
	StartTime   time.Time
	PacketTimes map[int]PacketTime // Packet times for this cycle only
	mu          sync.RWMutex
}

// TrafficSim struct with improved cycle tracking
type TrafficSim struct {
	// Use atomic for thread-safe access
	Running       int32 // 0 = stopped, 1 = Running
	stopping      int32 // 0 = not stopping, 1 = stopping
	Errored       bool
	ThisAgent     primitive.ObjectID
	OtherAgent    primitive.ObjectID
	Conn          *net.UDPConn
	connMu        sync.RWMutex // Protect connection access
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

	// Cycle tracking
	currentCycle   *CycleTracker
	cycleMu        sync.RWMutex
	packetsInCycle int // Track actual packets sent in current cycle

	// Connection state tracking
	connectionValid     bool
	connectionValidMu   sync.RWMutex
	lastConnectionCheck time.Time

	sync.Mutex
}

// New helper methods for safe connection handling
func (ts *TrafficSim) getConnection() *net.UDPConn {
	ts.connMu.RLock()
	defer ts.connMu.RUnlock()
	return ts.Conn
}

func (ts *TrafficSim) setConnection(conn *net.UDPConn) {
	ts.connMu.Lock()
	defer ts.connMu.Unlock()
	if ts.Conn != nil && ts.Conn != conn {
		ts.Conn.Close()
	}
	ts.Conn = conn
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
	if !valid {
		log.Printf("TrafficSim: Connection marked as invalid")
	}
}

// Fixed runTestCycles to handle connection failures gracefully
func (ts *TrafficSim) runTestCycles(ctx context.Context, errChan chan<- error, mtrProbe *Probe, isConnected bool) {
	connectionState := isConnected
	consecutiveFailures := 0

	// This loop should NEVER exit unless explicitly stopped
	for {
		// Check for shutdown conditions at the start of each cycle
		select {
		case <-ctx.Done():
			log.Printf("TrafficSim: Context cancelled, stopping test cycles")
			return
		case <-ts.stopChan:
			log.Printf("TrafficSim: Stop signal received, stopping test cycles")
			return
		default:
			// Continue with the cycle
		}

		// Check if we're still running
		if !ts.isRunning() {
			log.Printf("TrafficSim: Not running, stopping test cycles")
			return
		}

		// Check if we're in the process of stopping
		if ts.isStopping() {
			log.Printf("TrafficSim: Stopping flag set, exiting test cycles")
			ts.setInTestCycle(false)
			return
		}

		// Start of a new test cycle
		ts.setInTestCycle(true)

		// Initialize a new cycle tracker
		cycle := ts.startNewCycle()

		// Get flow for this test cycle
		flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")

		testStartTime := time.Now()
		log.Printf("TrafficSim: Starting test cycle (connection state: %v, starting seq: %d)", connectionState, cycle.StartSeq)

		// Check if we need to re-establish connection
		if !connectionState || !ts.isConnectionValid() {
			log.Printf("TrafficSim: Connection lost or not established, attempting handshake...")
			connectionState = ts.continuousHandshakeAttempts(ctx, flow, cycle)
			if connectionState {
				consecutiveFailures = 0
				log.Printf("TrafficSim: Connection re-established successfully")
			} else {
				log.Printf("TrafficSim: Failed to re-establish connection, will continue with offline mode")
			}
		}

		// Send data packets - track exactly TrafficSim_ReportSeq packets
		cycleFailures := 0

		for ts.getPacketsInCurrentCycle() < TrafficSim_ReportSeq {
			// Check for shutdown during packet sending
			select {
			case <-ctx.Done():
				ts.setInTestCycle(false)
				return
			case <-ts.stopChan:
				ts.setInTestCycle(false)
				return
			default:
			}

			if !ts.isRunning() {
				ts.setInTestCycle(false)
				return
			}

			// If we're stopping and have sent at least one packet, break
			if ts.isStopping() && ts.getPacketsInCurrentCycle() > 0 {
				break
			}

			// Check connection validity
			needsReconnect := !connectionState || !ts.isConnectionValid()

			if needsReconnect {
				log.Printf("TrafficSim: No connection, attempting reconnection (packet %d/%d in cycle)...",
					ts.getPacketsInCurrentCycle()+1, TrafficSim_ReportSeq)

				// Try to re-establish connection without losing cycle state
				if ts.reestablishConnection() {
					// attemptSingleHandshake will increment sequence and packetsInCycle
					if ts.attemptSingleHandshake(flow, cycle) {
						connectionState = true
						log.Printf("TrafficSim: Reconnection successful")
					} else {
						connectionState = false
						log.Printf("TrafficSim: Reconnection failed")
					}
				} else {
					// Can't establish UDP connection, send a failed packet anyway
					ts.recordFailedPacket(cycle, flow)
					cycleFailures++
					log.Printf("TrafficSim: No connection for packet %d (marked as failed)", ts.Sequence+1)
				}
			} else {
				// We have a connection, send a regular data packet
				if !ts.sendDataPacket(cycle, flow) {
					cycleFailures++
					connectionState = false
					ts.setConnectionValid(false)
				}
			}

			// Wait for interval before next packet
			select {
			case <-time.After(TrafficSim_DataInterval * time.Second):
			case <-ctx.Done():
				ts.setInTestCycle(false)
				return
			case <-ts.stopChan:
				ts.setInTestCycle(false)
				return
			}
		}

		// Complete the cycle
		ts.completeCycle(cycle)

		// Reset sequence counter after reporting
		ts.Mutex.Lock()
		if ts.Sequence >= TrafficSim_ReportSeq {
			log.Printf("TrafficSim: Resetting sequence from %d to 0 after cycle", ts.Sequence)
			ts.Sequence = 0
		}
		ts.Mutex.Unlock()

		// Update consecutive failures counter
		if cycleFailures >= TrafficSim_ReportSeq/2 { // If more than half the packets failed
			consecutiveFailures++
			log.Printf("TrafficSim: Cycle had %d/%d failures, consecutive failure count: %d",
				cycleFailures, TrafficSim_ReportSeq, consecutiveFailures)
		} else if cycleFailures == 0 {
			consecutiveFailures = 0
		}

		// Wait for responses to all packets in this cycle
		log.Printf("TrafficSim: Waiting for responses to packets in cycle (sequences: %v)...",
			cycle.PacketSeqs)
		ts.waitForCycleResponses(ctx, cycle)

		// Calculate and report stats for this cycle
		ts.reportCycleStats(mtrProbe, cycle)

		// Clean up old packet times (keep last 2 cycles worth)
		ts.cleanupOldPacketTimes(cycle.StartSeq)

		ts.setInTestCycle(false)

		// Check if we should stop after this cycle
		if ts.isStopping() {
			log.Print("TrafficSim: Completed final test cycle before shutdown")
			return
		}

		log.Printf("TrafficSim: Test cycle completed in %v (connection state: %v, packets sent: %d)",
			time.Since(testStartTime), connectionState, len(cycle.PacketSeqs))

		// Small delay before next cycle - but check for shutdown during delay
		select {
		case <-time.After(1 * time.Second):
			// Continue to next cycle
		case <-ctx.Done():
			log.Printf("TrafficSim: Context cancelled during cycle delay")
			return
		case <-ts.stopChan:
			log.Printf("TrafficSim: Stop signal during cycle delay")
			return
		}

		// Loop will continue to next cycle automatically
	}
}

// New method to send a data packet with proper error handling
func (ts *TrafficSim) sendDataPacket(cycle *CycleTracker, flow *FlowStats) bool {
	ts.Mutex.Lock()
	ts.Sequence++
	currentSeq := ts.Sequence
	ts.Mutex.Unlock()

	// Add this sequence to the current cycle
	ts.addSequenceToCycle(cycle, currentSeq)

	sentTime := time.Now().UnixMilli()
	data := TrafficSimData{Sent: sentTime, Seq: currentSeq}

	// Track packet in cycle-specific stats
	cycle.mu.Lock()
	cycle.PacketTimes[currentSeq] = PacketTime{
		Sent: sentTime,
		Size: 0,
	}
	cycle.mu.Unlock()

	// Also track in ClientStats for backward compatibility
	ts.ClientStats.mu.Lock()
	ts.ClientStats.PacketTimes[currentSeq] = PacketTime{
		Sent: sentTime,
		Size: 0,
	}
	ts.ClientStats.mu.Unlock()

	// Try to send packet
	dataMsg, err := ts.buildMessage(TrafficSim_DATA, data)
	if err != nil {
		log.Printf("TrafficSim: Error building data message: %v", err)
		ts.markPacketAsFailed(currentSeq, cycle)
		ts.incrementPacketsInCycle()
		return false
	}

	msgSize := len(dataMsg)

	// Update packet size in both trackers
	cycle.mu.Lock()
	if pt, ok := cycle.PacketTimes[currentSeq]; ok {
		pt.Size = msgSize
		cycle.PacketTimes[currentSeq] = pt
	}
	cycle.mu.Unlock()

	ts.ClientStats.mu.Lock()
	if pt, ok := ts.ClientStats.PacketTimes[currentSeq]; ok {
		pt.Size = msgSize
		ts.ClientStats.PacketTimes[currentSeq] = pt
	}
	ts.ClientStats.mu.Unlock()

	// Get current connection
	conn := ts.getConnection()
	if conn == nil {
		log.Printf("TrafficSim: No connection available for packet %d", currentSeq)
		ts.markPacketAsFailed(currentSeq, cycle)
		ts.incrementPacketsInCycle()
		return false
	}

	// Set write deadline to detect connection issues quickly
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, sendErr := conn.Write([]byte(dataMsg))
	conn.SetWriteDeadline(time.Time{}) // Clear deadline

	// Record packet sent
	ts.recordPacketSent(flow, currentSeq, msgSize)

	if sendErr != nil {
		log.Printf("TrafficSim: Failed to send packet %d: %v", currentSeq, sendErr)
		ts.markPacketAsFailed(currentSeq, cycle)

		// Check if this is a connection-related error
		if ts.isConnectionError(sendErr) {
			log.Printf("TrafficSim: Connection error detected, marking connection as invalid")
			ts.setConnectionValid(false)
		}

		ts.incrementPacketsInCycle()
		return false
	}

	// Increment packets in cycle counter
	ts.incrementPacketsInCycle()
	return true
}

// New method to record a failed packet
func (ts *TrafficSim) recordFailedPacket(cycle *CycleTracker, flow *FlowStats) {
	ts.Mutex.Lock()
	ts.Sequence++
	currentSeq := ts.Sequence
	ts.Mutex.Unlock()

	ts.addSequenceToCycle(cycle, currentSeq)

	// Track failed packet
	sentTime := time.Now().UnixMilli()
	cycle.mu.Lock()
	cycle.PacketTimes[currentSeq] = PacketTime{
		Sent:     sentTime,
		Size:     0,
		TimedOut: true,
	}
	cycle.mu.Unlock()

	ts.ClientStats.mu.Lock()
	ts.ClientStats.PacketTimes[currentSeq] = PacketTime{
		Sent:     sentTime,
		Size:     0,
		TimedOut: true,
	}
	ts.ClientStats.mu.Unlock()

	ts.incrementPacketsInCycle()
}

// Fixed reestablishConnection to handle connection reopening properly
func (ts *TrafficSim) reestablishConnection() bool {
	// Close existing connection if any
	ts.closeConnection()

	// Try to establish new connection
	return ts.establishUDPConnection()
}

// Fixed receiveDataLoop to handle connection errors gracefully
func (ts *TrafficSim) receiveDataLoop(ctx context.Context, errChan chan<- error) {
	reconnectDelay := 100 * time.Millisecond
	maxReconnectDelay := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !ts.isRunning() && !ts.isStopping() {
				return
			}

			// Get current connection
			conn := ts.getConnection()
			if conn == nil {
				// No connection, wait a bit and check again
				select {
				case <-time.After(reconnectDelay):
					if reconnectDelay < maxReconnectDelay {
						reconnectDelay *= 2
					}
					continue
				case <-ctx.Done():
					return
				}
			}

			msgBuf := make([]byte, 2048)
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			msgLen, _, err := conn.ReadFromUDP(msgBuf)

			if err != nil {
				// Handle timeout separately - it's expected
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}

				// Handle temporary errors
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Printf("TrafficSim: Temporary error reading from UDP: %v", err)
					continue
				}

				// Check for "use of closed network connection" error
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("TrafficSim: Detected closed connection in receive loop, marking as invalid")
					ts.setConnectionValid(false)
					reconnectDelay = 100 * time.Millisecond // Reset delay
					continue
				}

				// Check if this is a connection error that should invalidate the connection
				if ts.isConnectionError(err) {
					log.Printf("TrafficSim: Connection error in receive loop: %v", err)
					ts.setConnectionValid(false)
					reconnectDelay = 100 * time.Millisecond // Reset delay
					continue
				}

				// Other errors might be fatal
				select {
				case errChan <- fmt.Errorf("error reading from UDP: %w", err):
				default:
				}
				return
			}

			// Successfully received data, reset reconnect delay
			reconnectDelay = 100 * time.Millisecond

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
			case TrafficSim_HELLO:
				// Handle hello response during handshake
				if tsMsg.Data.Seq > 0 {
					ts.handleACK(tsMsg.Data)
				}
			}
		}
	}
}

// Fixed establishUDPConnection with better error handling
func (ts *TrafficSim) establishUDPConnection() bool {
	toAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", ts.IPAddress, ts.Port))
	if err != nil {
		log.Printf("TrafficSim: Could not resolve %s:%d: %v", ts.IPAddress, ts.Port, err)
		return false
	}

	localAddr, err := net.ResolveUDPAddr("udp4", ts.localIP+":0")
	if err != nil {
		log.Printf("TrafficSim: Could not resolve local address: %v", err)
		return false
	}

	conn, err := net.DialUDP("udp4", localAddr, toAddr)
	if err != nil {
		log.Printf("TrafficSim: Unable to connect to %s:%d: %v", ts.IPAddress, ts.Port, err)
		return false
	}

	// Set the new connection
	ts.setConnection(conn)
	log.Printf("TrafficSim: UDP connection established to %s:%d", ts.IPAddress, ts.Port)
	return true
}

// Fixed runClientSession to handle connection failures better
func (ts *TrafficSim) runClientSession(ctx context.Context, mtrProbe *Probe, isConnected bool) error {
	errChan := make(chan error, 3)
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start test cycles - this runs forever until stopped
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		ts.runTestCycles(sessionCtx, errChan, mtrProbe, isConnected)
		// If runTestCycles returns, send a signal that it's done
		select {
		case errChan <- fmt.Errorf("test cycles stopped"):
		default:
		}
	}()

	// Always start receive loop - it will handle connection state
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		ts.receiveDataLoop(sessionCtx, errChan)
	}()

	// Only run ping loop if initially connected
	if isConnected && ts.getConnection() != nil {
		ts.wg.Add(1)
		go func() {
			defer ts.wg.Done()
			ts.runPingLoop(sessionCtx, errChan)
		}()
	}

	// Wait for session to complete
	select {
	case err := <-errChan:
		cancel()
		ts.wg.Wait()

		// Don't treat connection errors as fatal - just log them
		if err != nil && strings.Contains(err.Error(), "test cycles stopped") {
			return nil
		}
		return err
	case <-sessionCtx.Done():
		ts.wg.Wait()
		return sessionCtx.Err()
	case <-ts.stopChan:
		cancel()
		ts.wg.Wait()
		return nil
	}
}

// Fixed runPingLoop to handle connection state changes
func (ts *TrafficSim) runPingLoop(ctx context.Context, errChan chan<- error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !ts.isRunning() {
				continue
			}

			conn := ts.getConnection()
			if conn == nil || !ts.isConnectionValid() {
				continue
			}

			pingData := TrafficSimData{
				Sent: time.Now().UnixMilli(),
				Seq:  -1, // Special sequence for ping
			}

			pingMsg, err := ts.buildMessage(TrafficSim_PING, pingData)
			if err != nil {
				continue
			}

			conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, err = conn.Write([]byte(pingMsg))
			conn.SetWriteDeadline(time.Time{}) // Clear deadline

			if err != nil {
				log.Printf("TrafficSim: Failed to send ping: %v", err)
				if ts.isConnectionError(err) {
					ts.setConnectionValid(false)
				}
			}
		}
	}
}

// Keep all the existing helper methods and other functions from the original code...
// (Include all the other methods from the original file that weren't modified)

// New helper methods for cycle management
func (ts *TrafficSim) startNewCycle() *CycleTracker {
	ts.cycleMu.Lock()
	defer ts.cycleMu.Unlock()

	ts.Mutex.Lock()
	startSeq := ts.Sequence + 1
	ts.Mutex.Unlock()

	cycle := &CycleTracker{
		StartSeq:    startSeq,
		StartTime:   time.Now(),
		PacketSeqs:  make([]int, 0, TrafficSim_ReportSeq),
		PacketTimes: make(map[int]PacketTime),
	}

	ts.currentCycle = cycle
	ts.packetsInCycle = 0

	return cycle
}

func (ts *TrafficSim) addSequenceToCycle(cycle *CycleTracker, seq int) {
	cycle.mu.Lock()
	defer cycle.mu.Unlock()
	cycle.PacketSeqs = append(cycle.PacketSeqs, seq)
}

func (ts *TrafficSim) completeCycle(cycle *CycleTracker) {
	cycle.mu.Lock()
	defer cycle.mu.Unlock()

	if len(cycle.PacketSeqs) > 0 {
		cycle.EndSeq = cycle.PacketSeqs[len(cycle.PacketSeqs)-1]
	} else {
		cycle.EndSeq = cycle.StartSeq
	}
}

func (ts *TrafficSim) getPacketsInCurrentCycle() int {
	ts.cycleMu.RLock()
	defer ts.cycleMu.RUnlock()
	return ts.packetsInCycle
}

func (ts *TrafficSim) incrementPacketsInCycle() {
	ts.cycleMu.Lock()
	defer ts.cycleMu.Unlock()
	ts.packetsInCycle++
}

// Modified waitForCycleResponses to work with CycleTracker
func (ts *TrafficSim) waitForCycleResponses(ctx context.Context, cycle *CycleTracker) {
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

			cycle.mu.Lock()
			allComplete := true
			now := time.Now().UnixMilli()

			// Check only packets in this cycle
			for _, seq := range cycle.PacketSeqs {
				if pTime, ok := cycle.PacketTimes[seq]; ok {
					if pTime.Received == 0 && !pTime.TimedOut {
						if now-pTime.Sent > int64(PacketTimeout.Milliseconds()) {
							pTime.TimedOut = true
							cycle.PacketTimes[seq] = pTime

							// Also update in ClientStats
							ts.ClientStats.mu.Lock()
							if pt, ok := ts.ClientStats.PacketTimes[seq]; ok {
								pt.TimedOut = true
								ts.ClientStats.PacketTimes[seq] = pt
							}
							ts.ClientStats.mu.Unlock()

							// Mark packet as timed out in flow
							flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
							flow.mu.Lock()
							if detail, exists := flow.PacketDetails[seq]; exists {
								detail.TimedOut = true
							}
							flow.mu.Unlock()

							log.Printf("TrafficSim: Packet %d timed out", seq)
						} else {
							allComplete = false
						}
					}
				}
			}
			cycle.mu.Unlock()

			if allComplete {
				log.Printf("TrafficSim: All packets in cycle complete or timed out")
				return
			}
		}
	}
}

// Modified reportCycleStats to work with CycleTracker
func (ts *TrafficSim) reportCycleStats(mtrProbe *Probe, cycle *CycleTracker) {
	// Calculate stats based on this cycle's packets
	stats := ts.calculateCycleStatsFromTracker(mtrProbe, cycle)

	// Add flow statistics
	flowStats := make(map[string]interface{})
	ts.flowStatsMu.RLock()
	for flowKey, flow := range ts.flowStats {
		flowStats[flowKey] = ts.calculateFlowStats(flow)
	}
	ts.flowStatsMu.RUnlock()

	stats["flows"] = flowStats
	stats["timestamp"] = time.Now()
	stats["cycleRange"] = map[string]int{
		"startSeq": cycle.StartSeq,
		"endSeq":   cycle.EndSeq,
	}

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

// Include all the remaining methods from the original file...
// (All the type definitions, constants, and other methods remain the same)

// New method to calculate stats from CycleTracker
func (ts *TrafficSim) calculateCycleStatsFromTracker(mtrProbe *Probe, cycle *CycleTracker) map[string]interface{} {
	cycle.mu.RLock()
	defer cycle.mu.RUnlock()

	var totalRTT, minRTT, maxRTT int64
	var rtts []float64
	lostPackets := 0
	outOfOrder := 0
	duplicatePackets := 0
	receivedSequences := []int{}
	totalPackets := len(cycle.PacketSeqs)

	// Analyze all packets in this cycle (including HELLO packets)
	for _, seq := range cycle.PacketSeqs {
		if pTime, ok := cycle.PacketTimes[seq]; ok {
			if pTime.Received == 0 || pTime.TimedOut {
				lostPackets++
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
		} else {
			// This packet sequence is in the cycle but not in PacketTimes - shouldn't happen
			log.Printf("TrafficSim: Warning - packet %d in cycle but not in PacketTimes", seq)
			lostPackets++
		}
	}

	// Check for out of order packets
	for i := 1; i < len(receivedSequences); i++ {
		if receivedSequences[i] < receivedSequences[i-1] {
			outOfOrder++
		}
	}

	// Calculate statistics
	avgRTT := float64(0)
	stdDevRTT := float64(0)
	if len(rtts) > 0 {
		avgRTT = float64(totalRTT) / float64(len(rtts))
		for _, rtt := range rtts {
			stdDevRTT += math.Pow(rtt-avgRTT, 2)
		}
		stdDevRTT = math.Sqrt(stdDevRTT / float64(len(rtts)))
	}

	lossPercentage := float64(0)
	if totalPackets > 0 {
		lossPercentage = (float64(lostPackets) / float64(totalPackets)) * 100
	}

	// Create sequence range string showing all sequences
	seqRangeStr := ""
	if len(cycle.PacketSeqs) > 0 {
		seqRangeStr = fmt.Sprintf("%d-%d", cycle.PacketSeqs[0], cycle.PacketSeqs[len(cycle.PacketSeqs)-1])
	}

	log.Printf("TrafficSim: Cycle Stats - Total: %d packets (sequences: %v), Lost: %d (%.2f%%), Out of Order: %d, Avg RTT: %.2fms",
		totalPackets, cycle.PacketSeqs, lostPackets, lossPercentage, outOfOrder, avgRTT)

	// Trigger MTR if packet loss exceeds threshold
	if totalPackets > 0 && lossPercentage > 5.0 && ts.isRunning() && !ts.isStopping() {
		ts.triggerMTR(mtrProbe, lossPercentage)
	}

	return map[string]interface{}{
		"lostPackets":      lostPackets,
		"lossPercentage":   lossPercentage,
		"outOfSequence":    outOfOrder,
		"duplicatePackets": duplicatePackets,
		"averageRTT":       avgRTT,
		"minRTT":           minRTT,
		"maxRTT":           maxRTT,
		"stdDevRTT":        stdDevRTT,
		"totalPackets":     totalPackets,
		"sequenceRange":    seqRangeStr,
		"allSequences":     cycle.PacketSeqs,
		"reportTime":       time.Now(),
	}
}

// Modified markPacketAsFailed to also update cycle tracker
func (ts *TrafficSim) markPacketAsFailed(seq int, cycle *CycleTracker) {
	// Ensure the packet exists in cycle tracker before marking as failed
	cycle.mu.Lock()
	if _, ok := cycle.PacketTimes[seq]; !ok {
		// If it doesn't exist, create it with the current time as sent time
		cycle.PacketTimes[seq] = PacketTime{
			Sent:     time.Now().UnixMilli(),
			TimedOut: true,
			Size:     0,
		}
	} else {
		// If it exists, just mark as timed out
		if pt, ok := cycle.PacketTimes[seq]; ok {
			pt.TimedOut = true
			cycle.PacketTimes[seq] = pt
		}
	}
	cycle.mu.Unlock()

	// Update in ClientStats
	ts.ClientStats.mu.Lock()
	if pt, ok := ts.ClientStats.PacketTimes[seq]; ok {
		pt.TimedOut = true
		ts.ClientStats.PacketTimes[seq] = pt
	}
	ts.ClientStats.mu.Unlock()

	// Mark in flow stats
	flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
	flow.mu.Lock()
	if detail, exists := flow.PacketDetails[seq]; exists {
		detail.TimedOut = true
	}
	flow.mu.Unlock()
}

// Modified continuousHandshakeAttempts to properly count handshake packets
func (ts *TrafficSim) continuousHandshakeAttempts(ctx context.Context, flow *FlowStats, cycle *CycleTracker) bool {
	maxHandshakeTime := 10 * time.Second
	handshakeStart := time.Now()

	log.Printf("TrafficSim: Starting continuous handshake attempts...")

	for time.Since(handshakeStart) < maxHandshakeTime {
		select {
		case <-ctx.Done():
			return false
		case <-ts.stopChan:
			return false
		default:
			if !ts.isRunning() || ts.isStopping() {
				return false
			}

			// Check if we've already used up our packet budget with failed handshakes
			if ts.getPacketsInCurrentCycle() >= TrafficSim_ReportSeq {
				log.Printf("TrafficSim: Reached packet limit during handshake attempts")
				return false
			}

			// Always try to establish fresh connection for handshake
			ts.closeConnection()

			if !ts.establishUDPConnection() {
				// Wait a bit before trying again
				select {
				case <-time.After(1 * time.Second):
				case <-ctx.Done():
					return false
				case <-ts.stopChan:
					return false
				}
				continue
			}

			// Attempt handshake (this will increment packetsInCycle)
			if ts.attemptSingleHandshake(flow, cycle) {
				log.Printf("TrafficSim: Handshake successful after %v", time.Since(handshakeStart))
				return true
			}

			// Wait before next handshake attempt
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return false
			case <-ts.stopChan:
				return false
			}
		}
	}

	log.Printf("TrafficSim: Handshake attempts timed out after %v", time.Since(handshakeStart))
	return false
}

// Modified attemptSingleHandshake to properly count as a packet in the cycle
func (ts *TrafficSim) attemptSingleHandshake(flow *FlowStats, cycle *CycleTracker) bool {
	// Increment sequence for this handshake attempt
	ts.Mutex.Lock()
	ts.Sequence++
	helloSeq := ts.Sequence
	ts.Mutex.Unlock()

	// Add to current cycle
	ts.addSequenceToCycle(cycle, helloSeq)
	// Increment packetsInCycle - handshakes DO count towards the 60 packets per cycle
	ts.incrementPacketsInCycle()

	sentTime := time.Now().UnixMilli()

	// Track handshake packet in both trackers
	cycle.mu.Lock()
	cycle.PacketTimes[helloSeq] = PacketTime{
		Sent: sentTime,
		Size: 0,
	}
	cycle.mu.Unlock()

	ts.ClientStats.mu.Lock()
	ts.ClientStats.PacketTimes[helloSeq] = PacketTime{
		Sent: sentTime,
		Size: 0,
	}
	ts.ClientStats.mu.Unlock()

	helloData := TrafficSimData{
		Sent: sentTime,
		Seq:  helloSeq,
	}

	helloMsg, err := ts.buildMessage(TrafficSim_HELLO, helloData)
	if err != nil {
		log.Printf("TrafficSim: Error building HELLO message: %v", err)
		ts.markPacketAsFailed(helloSeq, cycle)
		return false
	}

	msgSize := len(helloMsg)

	// Update packet size in both trackers
	cycle.mu.Lock()
	if pt, ok := cycle.PacketTimes[helloSeq]; ok {
		pt.Size = msgSize
		cycle.PacketTimes[helloSeq] = pt
	}
	cycle.mu.Unlock()

	ts.ClientStats.mu.Lock()
	if pt, ok := ts.ClientStats.PacketTimes[helloSeq]; ok {
		pt.Size = msgSize
		ts.ClientStats.PacketTimes[helloSeq] = pt
	}
	ts.ClientStats.mu.Unlock()

	// Record packet sent
	ts.recordPacketSent(flow, helloSeq, msgSize)

	// Send handshake with timeout
	ts.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = ts.Conn.Write([]byte(helloMsg))
	ts.Conn.SetWriteDeadline(time.Time{}) // Clear deadline

	if err != nil {
		log.Printf("TrafficSim: Failed to send HELLO packet %d: %v", helloSeq, err)
		ts.markPacketAsFailed(helloSeq, cycle)
		return false
	}

	log.Printf("TrafficSim: Sent HELLO packet %d, waiting for response...", helloSeq)

	// Wait for response with timeout
	msgBuf := make([]byte, 1024)
	ts.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = ts.Conn.ReadFromUDP(msgBuf)
	ts.Conn.SetReadDeadline(time.Time{}) // Clear deadline

	if err != nil {
		log.Printf("TrafficSim: No hello response received: %v", err)
		ts.markPacketAsFailed(helloSeq, cycle)
		return false
	}

	// Mark handshake as successful in both trackers
	receivedTime := time.Now().UnixMilli()

	cycle.mu.Lock()
	if pt, ok := cycle.PacketTimes[helloSeq]; ok {
		pt.Received = receivedTime
		cycle.PacketTimes[helloSeq] = pt
	}
	cycle.mu.Unlock()

	ts.ClientStats.mu.Lock()
	if pt, ok := ts.ClientStats.PacketTimes[helloSeq]; ok {
		pt.Received = receivedTime
		ts.ClientStats.PacketTimes[helloSeq] = pt
	}
	ts.ClientStats.mu.Unlock()

	// Update flow stats
	ts.recordPacketReceived(flow, helloSeq, sentTime)

	log.Printf("TrafficSim: Received HELLO response for packet %d, RTT: %dms", helloSeq, receivedTime-sentTime)
	return true
}

// Modified handleACK to update cycle tracker if applicable
func (ts *TrafficSim) handleACK(data TrafficSimData) {
	seq := data.Seq
	receivedTime := time.Now().UnixMilli()

	// Update in current cycle if it contains this sequence
	ts.cycleMu.RLock()
	if ts.currentCycle != nil {
		ts.currentCycle.mu.Lock()
		if pTime, ok := ts.currentCycle.PacketTimes[seq]; ok {
			if pTime.Received == 0 && !pTime.TimedOut {
				pTime.Received = receivedTime
				ts.currentCycle.PacketTimes[seq] = pTime
			}
		}
		ts.currentCycle.mu.Unlock()
	}
	ts.cycleMu.RUnlock()

	// Also update ClientStats for compatibility
	ts.ClientStats.mu.Lock()
	defer ts.ClientStats.mu.Unlock()

	if pTime, ok := ts.ClientStats.PacketTimes[seq]; ok {
		if pTime.Received == 0 && !pTime.TimedOut {
			pTime.Received = receivedTime
			ts.ClientStats.PacketTimes[seq] = pTime

			// Update flow stats
			flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
			ts.recordPacketReceived(flow, seq, pTime.Sent)

			log.Printf("TrafficSim: Received ACK for packet %d, RTT: %dms", seq, receivedTime-pTime.Sent)
		} else if pTime.TimedOut {
			log.Printf("TrafficSim: Received late ACK for packet %d (already marked as timed out)", seq)
		}
	}

	ts.LastResponse = time.Now()
}

// Keep all the existing type definitions and other methods from the original code...

// Modified calculateStats to work with specific sequence range
func (ts *TrafficSim) calculateCycleStats(mtrProbe *Probe, startSeq, endSeq int) map[string]interface{} {
	var totalRTT, minRTT, maxRTT int64
	var rtts []float64
	lostPackets := 0
	outOfOrder := 0
	duplicatePackets := 0
	receivedSequences := []int{}
	totalPackets := 0

	// Analyze packets only in this cycle's range
	for seq := startSeq; seq <= endSeq; seq++ {
		if pTime, ok := ts.ClientStats.PacketTimes[seq]; ok {
			totalPackets++

			if pTime.Received == 0 || pTime.TimedOut {
				lostPackets++
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
	}

	// Check for out of order packets
	for i := 1; i < len(receivedSequences); i++ {
		if receivedSequences[i] < receivedSequences[i-1] {
			outOfOrder++
		}
	}

	// Calculate statistics
	avgRTT := float64(0)
	stdDevRTT := float64(0)
	if len(rtts) > 0 {
		avgRTT = float64(totalRTT) / float64(len(rtts))
		for _, rtt := range rtts {
			stdDevRTT += math.Pow(rtt-avgRTT, 2)
		}
		stdDevRTT = math.Sqrt(stdDevRTT / float64(len(rtts)))
	}

	lossPercentage := float64(0)
	if totalPackets > 0 {
		lossPercentage = (float64(lostPackets) / float64(totalPackets)) * 100
	}

	log.Printf("TrafficSim: Cycle Stats - Seq Range: %d-%d, Total: %d, Lost: %d (%.2f%%), Out of Order: %d, Avg RTT: %.2fms",
		startSeq, endSeq, totalPackets, lostPackets, lossPercentage, outOfOrder, avgRTT)

	// Trigger MTR if packet loss exceeds threshold
	if totalPackets > 0 && lossPercentage > 5.0 && ts.isRunning() && !ts.isStopping() {
		ts.triggerMTR(mtrProbe, lossPercentage)
	}

	return map[string]interface{}{
		"lostPackets":      lostPackets,
		"lossPercentage":   lossPercentage,
		"outOfSequence":    outOfOrder,
		"duplicatePackets": duplicatePackets,
		"averageRTT":       avgRTT,
		"minRTT":           minRTT,
		"maxRTT":           maxRTT,
		"stdDevRTT":        stdDevRTT,
		"totalPackets":     totalPackets,
		"sequenceRange":    fmt.Sprintf("%d-%d", startSeq, endSeq),
		"reportTime":       time.Now(),
	}
}

// New method to clean up old packet times while keeping recent history
func (ts *TrafficSim) cleanupOldPacketTimes(currentCycleStart int) {
	ts.ClientStats.mu.Lock()
	defer ts.ClientStats.mu.Unlock()

	// Since sequences reset every TrafficSim_ReportSeq (30), we need to be smarter about cleanup
	// Keep packets from the last 2 cycles worth (60 sequences)
	// But handle the wraparound case when sequences reset

	toDelete := []int{}
	for seq := range ts.ClientStats.PacketTimes {
		// If this is an old sequence from before the current cycle
		// (considering wraparound at TrafficSim_ReportSeq)
		if currentCycleStart > TrafficSim_ReportSeq {
			// We've wrapped around, so old sequences are those > TrafficSim_ReportSeq
			if seq > TrafficSim_ReportSeq && seq < currentCycleStart {
				toDelete = append(toDelete, seq)
			}
		} else {
			// Normal case: delete sequences that are too old
			// Keep last 60 sequences worth of data
			if seq < currentCycleStart-60 && seq < currentCycleStart {
				toDelete = append(toDelete, seq)
			}
		}
	}

	for _, seq := range toDelete {
		delete(ts.ClientStats.PacketTimes, seq)
	}

	if len(toDelete) > 0 {
		log.Printf("TrafficSim: Cleaned up %d old packet times", len(toDelete))
	}
}

// Modified runClient to handle session restarts properly
func (ts *TrafficSim) runClient(ctx context.Context, mtrProbe *Probe) error {
	ts.Probe = mtrProbe
	ts.initFlowTracking()

	// Initialize client stats once
	if ts.ClientStats == nil {
		ts.ClientStats = &ClientStats{
			LastReportTime: time.Now(),
			ReportInterval: 15 * time.Second,
			PacketTimes:    make(map[int]PacketTime),
		}
		ts.testComplete = make(chan bool, 1)
	}

	// Main client loop
	for ts.isRunning() && !ts.isStopping() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ts.stopChan:
			return nil
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

		// Try to establish connection but don't block on failure
		connectionEstablished := ts.tryEstablishConnection()

		// Run client session - this should run indefinitely until stopped
		log.Printf("TrafficSim: Starting client session (connection: %v)", connectionEstablished)
		if err := ts.runClientSession(ctx, mtrProbe, connectionEstablished); err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				log.Printf("TrafficSim: Context cancelled, stopping client")
				return err
			}

			log.Printf("TrafficSim: Client session error: %v, will restart session", err)

			// Wait a bit before restarting the session
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			case <-ts.stopChan:
				return nil
			}
		}
	}

	log.Print("TrafficSim: Client stopped")
	return nil
}

const (
	TrafficSim_ReportSeq    = 60
	TrafficSim_DataInterval = 1
	RetryInterval           = 5 * time.Second
	PacketTimeout           = 2 * time.Second
	GracefulShutdownTimeout = 70 * time.Second
	ServerReportInterval    = 15 * time.Second
)

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
	Sent     int64
	Received int64
	TimedOut bool
	Size     int
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

// Record packet sent
func (ts *TrafficSim) recordPacketSent(flow *FlowStats, seq int, size int) {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	flow.PacketsSent++
	flow.BytesSent += int64(size)
	flow.PacketDetails[seq] = &PacketDetail{
		Sequence: seq,
		SentTime: time.Now(),
		Size:     size,
	}
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
		if !detail.RecvTime.IsZero() && detail.RTT > 0 {
			rtts = append(rtts, detail.RTT)
			if lastRTT > 0 {
				jitter := detail.RTT - lastRTT
				if jitter < 0 {
					jitter = -jitter
				}
				jitters = append(jitters, jitter)
			}
			lastRTT = detail.RTT
		} else if detail.TimedOut {
			flow.PacketsLost++
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
func (ts *TrafficSim) generateServerReport() map[string]interface{} {
	if ts.serverStats == nil {
		return nil
	}

	ts.serverStats.mu.RLock()
	defer ts.serverStats.mu.RUnlock()

	flows := make(map[string]interface{})
	for agentID, flow := range ts.serverStats.ActiveFlows {
		flows[agentID] = map[string]interface{}{
			"packetsReceived": flow.PacketsRecv,
			"packetsSent":     flow.PacketsSent,
			"bytesReceived":   flow.BytesRecv,
			"bytesSent":       flow.BytesSent,
			"outOfOrder":      flow.OutOfOrder,
			"duplicates":      flow.Duplicates,
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

func (ts *TrafficSim) sendHelloNonBlocking() bool {
	// Increment sequence for HELLO packet
	ts.Mutex.Lock()
	ts.Sequence++
	helloSeq := ts.Sequence
	ts.Mutex.Unlock()

	// Track HELLO packet as sent
	flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
	sentTime := time.Now().UnixMilli()

	ts.ClientStats.mu.Lock()
	ts.ClientStats.PacketTimes[helloSeq] = PacketTime{
		Sent: sentTime,
		Size: 0, // Will be updated after building message
	}
	ts.ClientStats.mu.Unlock()

	helloData := TrafficSimData{
		Sent: sentTime,
		Seq:  helloSeq,
	}

	helloMsg, err := ts.buildMessage(TrafficSim_HELLO, helloData)
	if err != nil {
		return false
	}

	msgSize := len(helloMsg)

	// Update packet size
	ts.ClientStats.mu.Lock()
	if pt, ok := ts.ClientStats.PacketTimes[helloSeq]; ok {
		pt.Size = msgSize
		ts.ClientStats.PacketTimes[helloSeq] = pt
	}
	ts.ClientStats.mu.Unlock()

	// Record packet sent
	ts.recordPacketSent(flow, helloSeq, msgSize)

	if _, err := ts.Conn.Write([]byte(helloMsg)); err != nil {
		// Mark as timed out immediately
		ts.ClientStats.mu.Lock()
		if pt, ok := ts.ClientStats.PacketTimes[helloSeq]; ok {
			pt.TimedOut = true
			ts.ClientStats.PacketTimes[helloSeq] = pt
		}
		ts.ClientStats.mu.Unlock()

		flow.mu.Lock()
		if detail, exists := flow.PacketDetails[helloSeq]; exists {
			detail.TimedOut = true
		}
		flow.mu.Unlock()

		return false
	}

	// Use a shorter timeout and track response
	msgBuf := make([]byte, 1024)
	ts.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := ts.Conn.ReadFromUDP(msgBuf); err != nil {
		log.Printf("TrafficSim: No hello response received: %v", err)

		// Mark HELLO packet as timed out
		ts.ClientStats.mu.Lock()
		if pt, ok := ts.ClientStats.PacketTimes[helloSeq]; ok {
			pt.TimedOut = true
			ts.ClientStats.PacketTimes[helloSeq] = pt
		}
		ts.ClientStats.mu.Unlock()

		flow.mu.Lock()
		if detail, exists := flow.PacketDetails[helloSeq]; exists {
			detail.TimedOut = true
		}
		flow.mu.Unlock()

		return false
	}

	// Mark HELLO packet as received
	receivedTime := time.Now().UnixMilli()
	ts.ClientStats.mu.Lock()
	if pt, ok := ts.ClientStats.PacketTimes[helloSeq]; ok {
		pt.Received = receivedTime
		ts.ClientStats.PacketTimes[helloSeq] = pt
	}
	ts.ClientStats.mu.Unlock()

	// Update flow stats for successful handshake
	ts.recordPacketReceived(flow, helloSeq, sentTime)

	return true
}

// 2. Helper method to check if error is connection-related
func (ts *TrafficSim) isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "host is unreachable")
}

func (ts *TrafficSim) closeConnection() {
	ts.connMu.Lock()
	defer ts.connMu.Unlock()

	if ts.Conn != nil {
		ts.Conn.Close()
		ts.Conn = nil
		log.Printf("TrafficSim: Connection closed")
	}
	ts.connectionValidMu.Lock()
	ts.connectionValid = false
	ts.connectionValidMu.Unlock()
}

// 6. Modified waitForAllResponses to handle all packets in cycle
func (ts *TrafficSim) waitForAllResponses(ctx context.Context) {
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

			// Check all packets in this cycle
			for seq, pTime := range ts.ClientStats.PacketTimes {
				if pTime.Received == 0 && !pTime.TimedOut {
					if now-pTime.Sent > int64(PacketTimeout.Milliseconds()) {
						pTime.TimedOut = true
						ts.ClientStats.PacketTimes[seq] = pTime

						// Mark packet as timed out in flow
						flow := ts.getOrCreateFlow(ts.ThisAgent, ts.OtherAgent, "client-server")
						flow.mu.Lock()
						if detail, exists := flow.PacketDetails[seq]; exists {
							detail.TimedOut = true
						}
						flow.mu.Unlock()

						log.Printf("TrafficSim: Packet %d timed out", seq)
					} else {
						allComplete = false
					}
				}
			}
			ts.ClientStats.mu.Unlock()

			if allComplete {
				log.Print("TrafficSim: All packets in cycle complete or timed out")
				return
			}
		}
	}
}

// 7. Modified tryEstablishConnection to be simpler
func (ts *TrafficSim) tryEstablishConnection() bool {
	if ts.Conn == nil {
		return ts.establishUDPConnection()
	}

	// If we have a connection, do a quick test
	return ts.testExistingConnection()
}

// 8. Test existing connection with a simple ping
func (ts *TrafficSim) testExistingConnection() bool {
	if ts.Conn == nil {
		return false
	}

	// Send a quick ping to test connection
	pingData := TrafficSimData{
		Sent: time.Now().UnixMilli(),
		Seq:  -1, // Special sequence for connection test
	}

	pingMsg, err := ts.buildMessage(TrafficSim_PING, pingData)
	if err != nil {
		return false
	}

	// Test with short timeout
	ts.Conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = ts.Conn.Write([]byte(pingMsg))
	ts.Conn.SetWriteDeadline(time.Time{}) // Clear deadline

	if err != nil {
		log.Printf("TrafficSim: Connection test failed: %v", err)
		ts.closeConnection()
		return false
	}

	return true
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
	}
	ts.testComplete = make(chan bool, 1)

	if err := ts.sendHello(); err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	log.Printf("TrafficSim: Connection established successfully to %v", ts.OtherAgent.Hex())
	return nil
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

func (ts *TrafficSim) handleServerReport(data TrafficSimData) {
	if data.Report != nil {
		log.Printf("TrafficSim: Received server report: %+v", data.Report)
		// Process server report data as needed
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

// 9. Modified calculateStats to work with per-cycle reset
func (ts *TrafficSim) calculateStats(mtrProbe *Probe) map[string]interface{} {
	ts.ClientStats.mu.RLock()
	defer ts.ClientStats.mu.RUnlock()

	var totalRTT, minRTT, maxRTT int64
	var rtts []float64
	lostPackets := 0
	outOfOrder := 0
	duplicatePackets := 0
	receivedSequences := []int{}

	// Get all packets from this cycle
	var keys []int
	for k := range ts.ClientStats.PacketTimes {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// Analyze packets
	for _, seq := range keys {
		pTime := ts.ClientStats.PacketTimes[seq]
		if pTime.Received == 0 || pTime.TimedOut {
			lostPackets++
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
		}
	}

	// Calculate statistics
	avgRTT := float64(0)
	stdDevRTT := float64(0)
	if len(rtts) > 0 {
		avgRTT = float64(totalRTT) / float64(len(rtts))
		for _, rtt := range rtts {
			stdDevRTT += math.Pow(rtt-avgRTT, 2)
		}
		stdDevRTT = math.Sqrt(stdDevRTT / float64(len(rtts)))
	}

	totalPackets := len(keys)
	lossPercentage := float64(0)
	if totalPackets > 0 {
		lossPercentage = (float64(lostPackets) / float64(totalPackets)) * 100
	}

	log.Printf("TrafficSim: Cycle Stats - Total: %d, Lost: %d (%.2f%%), Out of Order: %d, Avg RTT: %.2fms",
		totalPackets, lostPackets, lossPercentage, outOfOrder, avgRTT)

	// Trigger MTR if packet loss exceeds threshold
	if totalPackets > 0 && lossPercentage > 5.0 && ts.isRunning() && !ts.isStopping() {
		ts.triggerMTR(mtrProbe, lossPercentage)
	}

	return map[string]interface{}{
		"lostPackets":      lostPackets,
		"lossPercentage":   lossPercentage,
		"outOfSequence":    outOfOrder,
		"duplicatePackets": duplicatePackets,
		"averageRTT":       avgRTT,
		"minRTT":           minRTT,
		"maxRTT":           maxRTT,
		"stdDevRTT":        stdDevRTT,
		"totalPackets":     totalPackets,
		"cycleMaxSeq":      ts.Sequence,
		"reportTime":       time.Now(),
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

package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
	GracefulShutdownTimeout = 70 * time.Second // Enough time for a full test cycle
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
	sync.Mutex
}

type Connection struct {
	Addr         *net.UDPAddr
	LastResponse time.Time
	ExpectedSeq  int
	AgentID      primitive.ObjectID
	ClientStats  *ClientStats
}

type ClientStats struct {
	DuplicatePackets int                `json:"duplicatePackets"`
	OutOfSequence    int                `json:"outOfSequence"`
	PacketTimes      map[int]PacketTime `json:"-"`
	LastReportTime   time.Time          `json:"lastReportTime"`
	ReportInterval   time.Duration      `json:"reportInterval"`
	mu               sync.RWMutex
}

type PacketTime struct {
	Sent     int64
	Received int64
	TimedOut bool
}

const (
	TrafficSim_HELLO TrafficSimMsgType = "HELLO"
	TrafficSim_ACK   TrafficSimMsgType = "ACK"
	TrafficSim_DATA  TrafficSimMsgType = "DATA"
)

type TrafficSimMsgType string

type TrafficSimMsg struct {
	Type TrafficSimMsgType  `json:"type"`
	Data TrafficSimData     `json:"data"`
	Src  primitive.ObjectID `json:"src"`
	Dst  primitive.ObjectID `json:"dst"`
}

type TrafficSimData struct {
	Sent     int64 `json:"sent"`
	Received int64 `json:"received"`
	Seq      int   `json:"seq"`
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
		Type: msgType,
		Data: data,
		Src:  ts.ThisAgent,
		Dst:  ts.OtherAgent,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message: %w", err)
	}
	return string(msgBytes), nil
}

func (ts *TrafficSim) runClient(ctx context.Context, mtrProbe *Probe) error {
	ts.Probe = mtrProbe

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
	errChan := make(chan error, 2)
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ts.wg.Add(2)
	go func() {
		defer ts.wg.Done()
		ts.runTestCycles(sessionCtx, errChan, mtrProbe)
	}()
	go func() {
		defer ts.wg.Done()
		ts.receiveDataLoop(sessionCtx, errChan)
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

	msgBuf := make([]byte, 256)
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

			testStartTime := time.Now()
			packetsInTest := TrafficSim_ReportSeq / TrafficSim_DataInterval

			// Send packets for this test cycle
			allPacketsSent := true
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

					if _, err := ts.Conn.Write([]byte(dataMsg)); err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
							log.Printf("TrafficSim: Temporary error sending data message: %v", err)
							continue
						}
						allPacketsSent = false
						break
					}

					ts.ClientStats.mu.Lock()
					ts.ClientStats.PacketTimes[currentSeq] = PacketTime{Sent: sentTime}
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

			if !allPacketsSent {
				ts.setInTestCycle(false)
				errChan <- fmt.Errorf("failed to send all packets")
				return
			}

			// Wait for responses
			log.Printf("TrafficSim: Finished sending %d packets, waiting for responses...", packetsInTest)
			ts.waitForResponses(ctx, packetsInTest)

			// Calculate and report stats
			ts.reportStats(mtrProbe)

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
					if pTime.Received == 0 && !pTime.TimedOut {
						if now-pTime.Sent > int64(PacketTimeout.Milliseconds()) {
							pTime.TimedOut = true
							ts.ClientStats.PacketTimes[seq] = pTime
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

func (ts *TrafficSim) reportStats(mtrProbe *Probe) {
	ts.ClientStats.mu.RLock()
	stats := ts.calculateStats(mtrProbe)
	ts.ClientStats.mu.RUnlock()

	if ts.DataChan != nil && ts.isRunning() {
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

			msgBuf := make([]byte, 256)
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

			if tsMsg.Type == TrafficSim_ACK {
				ts.handleACK(tsMsg.Data)
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
		if pTime.Received == 0 && !pTime.TimedOut {
			pTime.Received = receivedTime
			ts.ClientStats.PacketTimes[seq] = pTime
			log.Printf("TrafficSim: Received ACK for packet %d, RTT: %dms", seq, receivedTime-pTime.Sent)
		} else if pTime.TimedOut {
			log.Printf("TrafficSim: Received late ACK for packet %d (already marked as timed out)", seq)
		}
	}

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
		if pTime.Received == 0 || pTime.TimedOut {
			lostPackets++
			log.Printf("TrafficSim: Packet %d lost", seq)
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

	log.Printf("TrafficSim: Stats - Total: %d, Lost: %d (%.2f%%), Out of Order: %d, Avg RTT: %.2fms",
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

	// Set read timeout to check status periodically
	for ts.isRunning() {
		msgBuf := make([]byte, 256)
		ln.SetReadDeadline(time.Now().Add(1 * time.Second))
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

	log.Print("TrafficSim: Server stopped")
	return nil
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

	ts.ConnectionsMu.Lock()
	connection, exists := ts.Connections[tsMsg.Src]
	if !exists {
		connection = &Connection{
			Addr:         addr,
			LastResponse: time.Now(),
			AgentID:      tsMsg.Src,
		}
		ts.Connections[tsMsg.Src] = connection
	}
	ts.ConnectionsMu.Unlock()

	switch tsMsg.Type {
	case TrafficSim_HELLO:
		ts.sendACK(conn, addr, TrafficSimData{Sent: time.Now().UnixMilli()})
	case TrafficSim_DATA:
		ts.handleData(conn, addr, tsMsg.Data, connection)
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
				break
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

package web

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// heartbeatLagLimit is how far behind the controller may fall in
	// processing this connection before the agent reconnects. The controller
	// handles each agent's messages one at a time, so a slow handler there
	// delays every later message, including pings, by the same amount.
	heartbeatLagLimit = 2 * time.Minute

	// lagReconnectMinGap stops a lagging controller from causing a
	// reconnect storm.
	lagReconnectMinGap = 10 * time.Minute

	// probeGetPendingMax is how long an unanswered probe_get blocks the next
	// one. Requests sent while the controller is still building the previous
	// list would only queue up behind it.
	probeGetPendingMax = 3 * time.Minute
)

// lagTracker measures how far behind the controller is on this connection by
// matching each pong to the oldest unanswered ping.
type lagTracker struct {
	mu              sync.Mutex
	pendingPings    []time.Time
	lastLag         time.Duration
	lastReconnect   time.Time
	probeGetPending time.Time
}

// reset forgets in-flight requests; call when a new connection is established.
func (l *lagTracker) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pendingPings = l.pendingPings[:0]
	l.probeGetPending = time.Time{}
}

func (l *lagTracker) pingSent(at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Bound memory if the controller never answers.
	if len(l.pendingPings) >= 256 {
		l.pendingPings = l.pendingPings[1:]
	}
	l.pendingPings = append(l.pendingPings, at)
}

// pongReceived returns the round trip of the oldest unanswered ping.
func (l *lagTracker) pongReceived(at time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pendingPings) == 0 {
		return 0, false
	}
	sent := l.pendingPings[0]
	l.pendingPings = l.pendingPings[1:]
	l.lastLag = at.Sub(sent)
	return l.lastLag, true
}

// oldestUnanswered returns how long the oldest unanswered ping has waited.
func (l *lagTracker) oldestUnanswered(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pendingPings) == 0 {
		return 0
	}
	return now.Sub(l.pendingPings[0])
}

// allowReconnect reports whether a lag-triggered reconnect may happen now,
// and if so records it.
func (l *lagTracker) allowReconnect(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lastReconnect.IsZero() && now.Sub(l.lastReconnect) < lagReconnectMinGap {
		return false
	}
	l.lastReconnect = now
	return true
}

// beginProbeGet reports whether a new probe_get may be sent now.
func (l *lagTracker) beginProbeGet(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.probeGetPending.IsZero() && now.Sub(l.probeGetPending) < probeGetPendingMax {
		return false
	}
	l.probeGetPending = now
	return true
}

func (l *lagTracker) endProbeGet() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.probeGetPending = time.Time{}
}

// HeartbeatLag returns the most recent ping round trip, a direct measure of
// how far behind the controller is on this connection.
func (c *WSClient) HeartbeatLag() time.Duration {
	c.lag.mu.Lock()
	defer c.lag.mu.Unlock()
	return c.lag.lastLag
}

// RequestProbes asks the controller for the probe list unless an earlier
// request is still unanswered. Returns true if a request was sent.
func (c *WSClient) RequestProbes() bool {
	if !c.lag.beginProbeGet(time.Now()) {
		log.Debug("WS: previous probe_get still unanswered, not sending another")
		return false
	}
	if !c.Emit("probe_get", []byte("please")) {
		c.lag.endProbeGet()
		return false
	}
	return true
}

// checkLag reconnects when the controller is too far behind on this
// connection. A fresh connection gets its own processing on the controller,
// so new data flows again while the old backlog drains.
func (c *WSClient) checkLag(lag time.Duration, reason string) {
	if lag < heartbeatLagLimit {
		return
	}
	if !c.lag.allowReconnect(time.Now()) {
		log.Warnf("WS: controller is %v behind on this connection (%s); reconnected recently, waiting", lag.Round(time.Second), reason)
		return
	}
	log.Warnf("WS: controller is %v behind on this connection (%s); reconnecting", lag.Round(time.Second), reason)
	c.TriggerReconnect(0)
}

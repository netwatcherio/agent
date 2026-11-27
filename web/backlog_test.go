package web

import (
	"testing"
	"time"
)

func TestLagTrackerMatchesPongToOldestPing(t *testing.T) {
	var l lagTracker
	t0 := time.Now()
	l.pingSent(t0)
	l.pingSent(t0.Add(30 * time.Second))

	// Controller 80 minutes behind: the first pong answers the first ping.
	lag, ok := l.pongReceived(t0.Add(80 * time.Minute))
	if !ok || lag != 80*time.Minute {
		t.Fatalf("lag = %v ok=%v, want 80m", lag, ok)
	}
	if got := l.oldestUnanswered(t0.Add(80 * time.Minute)); got != 80*time.Minute-30*time.Second {
		t.Fatalf("oldestUnanswered = %v", got)
	}
	l.reset()
	if _, ok := l.pongReceived(time.Now()); ok {
		t.Fatal("pong after reset should not match a ping")
	}
}

func TestLagTrackerReconnectRateLimit(t *testing.T) {
	var l lagTracker
	now := time.Now()
	if !l.allowReconnect(now) {
		t.Fatal("first reconnect should be allowed")
	}
	if l.allowReconnect(now.Add(time.Minute)) {
		t.Fatal("second reconnect within the gap should be refused")
	}
	if !l.allowReconnect(now.Add(lagReconnectMinGap + time.Second)) {
		t.Fatal("reconnect after the gap should be allowed")
	}
}

func TestProbeGetGuard(t *testing.T) {
	var l lagTracker
	now := time.Now()
	if !l.beginProbeGet(now) {
		t.Fatal("first request should be allowed")
	}
	if l.beginProbeGet(now.Add(time.Minute)) {
		t.Fatal("request while previous unanswered should be refused")
	}
	l.endProbeGet()
	if !l.beginProbeGet(now.Add(61 * time.Second)) {
		t.Fatal("request after reply should be allowed")
	}
	if !l.beginProbeGet(now.Add(61*time.Second + probeGetPendingMax)) {
		t.Fatal("request after the pending limit should be allowed even without reply")
	}
}

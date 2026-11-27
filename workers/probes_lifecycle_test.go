package workers

import (
	"sync"
	"testing"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// These tests use the "AGENT" probe type: it does no network I/O and waits
// 30s between runs, which makes "did the worker stop promptly?" observable.

func loadWorker(t *testing.T, key string) (ProbeWorkerS, bool) {
	t.Helper()
	v, ok := checkWorkers.Load(key)
	if !ok {
		return ProbeWorkerS{}, false
	}
	return v.(ProbeWorkerS), true
}

func waitGroupDone(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func eventually(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func resetWorkers(t *testing.T) {
	t.Helper()
	ClearAllProbeWorkers()
}

// Regression: changing a non-key-identity field (interval) used to move the
// map entry to a new key while the goroutine kept looking up the old key, so
// the worker exited and the probe silently stopped forever.
func TestConfigChangeRestartsWorker(t *testing.T) {
	t.Cleanup(func() { resetWorkers(t) })

	probeCh := make(chan []probes.Probe)
	dataCh := make(chan probes.ProbeData, 16)
	FetchProbesWorker(probeCh, dataCh, primitive.NewObjectID())

	p1 := probes.Probe{ID: 9001, Type: "AGENT", IntervalSec: 60,
		Targets: []probes.ProbeTarget{{Target: "10.0.0.1"}}}
	probeCh <- []probes.Probe{p1}

	key1 := makeProbeKey(p1)
	if !eventually(t, time.Second, func() bool { _, ok := loadWorker(t, key1); return ok }) {
		t.Fatalf("worker for initial config not registered")
	}
	w1, _ := loadWorker(t, key1)

	p2 := p1
	p2.IntervalSec = 120
	key2 := makeProbeKey(p2)
	if key1 == key2 {
		t.Fatalf("test assumption broken: interval change should change probe key")
	}
	probeCh <- []probes.Probe{p2}

	if !eventually(t, time.Second, func() bool { _, ok := loadWorker(t, key2); return ok }) {
		t.Fatalf("worker for changed config not registered under new key")
	}
	if _, ok := loadWorker(t, key1); ok {
		t.Fatalf("old key still registered after config change")
	}

	// Old worker must stop promptly (it is mid-way through a 30s wait).
	if !waitGroupDone(w1.WaitGroup, 2*time.Second) {
		t.Fatalf("old worker did not stop after config change")
	}

	// New worker must actually be running (not orphaned).
	w2, _ := loadWorker(t, key2)
	if waitGroupDone(w2.WaitGroup, 200*time.Millisecond) {
		t.Fatalf("new worker exited immediately; probe would be dead")
	}
}

// Removing a probe must stop its worker promptly and must not block the
// reconciler (which would stall the websocket read loop feeding it).
func TestRemovedProbeStopsPromptly(t *testing.T) {
	t.Cleanup(func() { resetWorkers(t) })

	probeCh := make(chan []probes.Probe)
	dataCh := make(chan probes.ProbeData, 16)
	FetchProbesWorker(probeCh, dataCh, primitive.NewObjectID())

	var list []probes.Probe
	for i := uint(0); i < 5; i++ {
		list = append(list, probes.Probe{ID: 9100 + i, Type: "AGENT", IntervalSec: 60,
			Targets: []probes.ProbeTarget{{Target: "10.0.0.2"}}})
	}
	probeCh <- list

	var wgs []*sync.WaitGroup
	for _, p := range list {
		key := makeProbeKey(p)
		if !eventually(t, time.Second, func() bool { _, ok := loadWorker(t, key); return ok }) {
			t.Fatalf("worker %d not registered", p.ID)
		}
		w, _ := loadWorker(t, key)
		wgs = append(wgs, w.WaitGroup)
	}

	start := time.Now()
	probeCh <- []probes.Probe{}
	// The next send only succeeds once the reconciler finished the previous list.
	probeCh <- []probes.Probe{}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("reconciler blocked for %v while removing probes", elapsed)
	}

	for i, wg := range wgs {
		if !waitGroupDone(wg, 2*time.Second) {
			t.Fatalf("worker %d did not stop after removal", list[i].ID)
		}
	}
}

// A replacement worker under the same key must not leave the old goroutine
// running alongside it.
func TestSupersededWorkerExits(t *testing.T) {
	t.Cleanup(func() { resetWorkers(t) })

	p := probes.Probe{ID: 9200, Type: "AGENT", IntervalSec: 60,
		Targets: []probes.ProbeTarget{{Target: "10.0.0.3"}}}
	key := makeProbeKey(p)
	dataCh := make(chan probes.ProbeData, 1)

	old := newProbeWorker(p)
	startCheckWorker(old, dataCh, primitive.NewObjectID())

	// Replace the map entry without going through the reconciler, then wake
	// the old worker. It must notice it was superseded and exit rather than
	// keep running next to the replacement.
	replacement := newProbeWorker(p)
	checkWorkers.Store(key, replacement)
	old.CancelFunc()
	if !waitGroupDone(old.WaitGroup, time.Second) {
		t.Fatalf("old worker did not exit")
	}
	replacement.CancelFunc()
}

func TestRunProbeOnceNoTargetDoesNotPanic(t *testing.T) {
	for _, typ := range []probes.ProbeType{
		probes.ProbeType_PING, probes.ProbeType_MTR, probes.ProbeType_DNS,
		probes.ProbeType_HTTP, probes.ProbeType_TLS, probes.ProbeType_SNMP,
	} {
		p := probes.Probe{ID: 1, Type: typ}
		w := newProbeWorker(p)
		if got := runProbeOnce(w.Ctx, p, make(chan probes.ProbeData, 1)); got != noTargetBackoff {
			t.Errorf("%s with no targets: wait = %v, want %v", typ, got, noTargetBackoff)
		}
		w.CancelFunc()
	}
}

func TestWaitOrStopReturnsOnCancel(t *testing.T) {
	w := newProbeWorker(probes.Probe{ID: 2, Type: "AGENT"})
	go func() { time.Sleep(20 * time.Millisecond); w.CancelFunc() }()
	start := time.Now()
	if waitOrStop(w, time.Hour) {
		t.Fatalf("waitOrStop returned true after cancel")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("waitOrStop did not return promptly")
	}
}

func TestNextWaitKeepsFixedPeriod(t *testing.T) {
	if got := nextWait(120*time.Second, 45*time.Second); got != 75*time.Second {
		t.Fatalf("nextWait = %v, want 75s", got)
	}
	if got := nextWait(60*time.Second, 90*time.Second); got != minProbeWait {
		t.Fatalf("overrun nextWait = %v, want %v", got, minProbeWait)
	}
}

func TestStartupJitterBounds(t *testing.T) {
	for _, iv := range []int{0, 5, 60, 3600} {
		p := probes.Probe{IntervalSec: iv}
		for i := 0; i < 200; i++ {
			j := startupJitter(p)
			if j < 0 || j >= maxStartupJitter {
				t.Fatalf("interval %d: jitter %v out of range", iv, j)
			}
			if iv > 0 && iv < 30 && j >= time.Duration(iv)*time.Second {
				t.Fatalf("interval %d: jitter %v exceeds interval", iv, j)
			}
		}
	}
}

package web

import (
	"context"
	"testing"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
)

func TestDeliverLatestProbesNeverBlocksAndKeepsNewest(t *testing.T) {
	ch := make(chan []probes.Probe, 1)
	done := make(chan struct{})
	go func() {
		deliverLatestProbes(ch, []probes.Probe{{ID: 1}})
		deliverLatestProbes(ch, []probes.Probe{{ID: 2}})
		deliverLatestProbes(ch, []probes.Probe{{ID: 3}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deliverLatestProbes blocked with no reader")
	}
	got := <-ch
	if len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("got %+v, want newest list (ID 3)", got)
	}
}

func TestWithJitterBounds(t *testing.T) {
	d := 8 * time.Second
	for i := 0; i < 1000; i++ {
		j := withJitter(d)
		if j < 6*time.Second || j > 10*time.Second {
			t.Fatalf("withJitter(%v) = %v, outside ±25%%", d, j)
		}
	}
	if withJitter(0) != 0 {
		t.Fatal("withJitter(0) should be 0")
	}
}

func TestSleepCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Hour) {
		t.Fatal("sleepCtx should return false on a cancelled context")
	}
}

func TestEmitWithoutConnection(t *testing.T) {
	c := &WSClient{}
	if c.Emit("probe_post", []byte("{}")) {
		t.Fatal("Emit should return false with no connection")
	}
}

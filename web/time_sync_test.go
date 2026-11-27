package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
)

func TestSampleOffsetUsesRoundTripMidpoint(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(400 * time.Millisecond)
	// Controller read its clock at the midpoint and is exactly 1h ahead.
	server := t0.Add(200 * time.Millisecond).Add(time.Hour)
	s := sampleOffset(server, t0, t1)
	if s.offset != time.Hour || s.rtt != 400*time.Millisecond {
		t.Fatalf("got offset %v rtt %v, want 1h / 400ms", s.offset, s.rtt)
	}
}

func TestBestSamplePicksShortestRoundTrip(t *testing.T) {
	best, ok := bestSample([]clockSample{
		{offset: time.Hour + 300*time.Millisecond, rtt: 600 * time.Millisecond},
		{offset: time.Hour + 5*time.Millisecond, rtt: 10 * time.Millisecond},
		{offset: time.Hour - 200*time.Millisecond, rtt: 400 * time.Millisecond},
	})
	if !ok || best.rtt != 10*time.Millisecond {
		t.Fatalf("best = %+v", best)
	}
}

// End to end against a fake controller whose clock is 1h behind this host
// (the agent-96 case: host UTC an hour fast).
func TestSyncTimeMeasuresAndAppliesOffset(t *testing.T) {
	t.Cleanup(func() { probes.SetClockOffset(0) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"server_unix_ms": %d}`, time.Now().Add(-time.Hour).UnixMilli())
	}))
	defer srv.Close()

	if err := SyncTime(context.Background(), srv.URL, 1, 2, "psk"); err != nil {
		t.Fatal(err)
	}
	off := probes.ClockOffset()
	if d := off + time.Hour; d < -20*time.Millisecond || d > 20*time.Millisecond {
		t.Fatalf("offset %v, want -1h within 20ms", off)
	}
	// Reported time now matches the controller's clock.
	if d := probes.Now().Sub(time.Now().Add(-time.Hour)); d < -50*time.Millisecond || d > 50*time.Millisecond {
		t.Fatalf("corrected Now off by %v", d)
	}
}

func TestSyncTimeKeepsOffsetWhenControllerUnreachable(t *testing.T) {
	t.Cleanup(func() { probes.SetClockOffset(0) })
	probes.SetClockOffset(-time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if err := SyncTime(context.Background(), srv.URL, 1, 2, "psk"); err == nil {
		t.Fatal("expected an error")
	}
	if probes.ClockOffset() != -time.Hour {
		t.Fatalf("offset changed to %v after a failed sync", probes.ClockOffset())
	}
}

package probes

import (
	"testing"
	"time"
)

func TestClockOffsetCorrectsNow(t *testing.T) {
	t.Cleanup(func() { SetClockOffset(0) })

	// Host clock an hour fast: controller time = local - 1h.
	SetClockOffset(-time.Hour)
	if d := time.Now().Sub(Now()); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("Now() not corrected by -1h: diff %v", d)
	}
	if Now().Location() != time.UTC {
		t.Fatal("Now() should be UTC")
	}

	// Sub-second offsets are measurement noise and ignored.
	SetClockOffset(300 * time.Millisecond)
	if ClockOffset() != 0 {
		t.Fatalf("small offset applied: %v", ClockOffset())
	}
}

func TestUpdateClockOffsetHysteresis(t *testing.T) {
	t.Cleanup(func() { SetClockOffset(0) })
	SetClockOffset(0)

	if got := UpdateClockOffset(1200 * time.Millisecond); got != 1200*time.Millisecond {
		t.Fatalf("first real offset not applied: %v", got)
	}
	// Re-measurement within noise keeps the current offset.
	if got := UpdateClockOffset(1400 * time.Millisecond); got != 1200*time.Millisecond {
		t.Fatalf("noise moved the offset: %v", got)
	}
	// A real change (e.g. the clock was corrected) is applied.
	if got := UpdateClockOffset(-time.Hour); got != -time.Hour {
		t.Fatalf("real change not applied: %v", got)
	}
	// Clock fixed on the host: offset returns to zero.
	if got := UpdateClockOffset(100 * time.Millisecond); got != 0 {
		t.Fatalf("offset after host fix = %v, want 0", got)
	}
}

// Converting to a reported time must never change the instant when no
// correction is needed, and durations must still come from local times.
func TestReportTimePreservesInstantAndDurations(t *testing.T) {
	t.Cleanup(func() { SetClockOffset(0) })
	SetClockOffset(0)

	loc := time.FixedZone("PST", -8*3600)
	start := time.Now().In(loc)
	stop := start.Add(1234 * time.Millisecond)

	rs, rp := ReportTime(start), ReportTime(stop)
	if !rs.Equal(start) || !rp.Equal(stop) {
		t.Fatal("ReportTime changed the instant with zero offset")
	}
	if rs.Location() != time.UTC {
		t.Fatal("ReportTime should normalize to UTC")
	}
	if rp.Sub(rs) != 1234*time.Millisecond {
		t.Fatalf("duration changed: %v", rp.Sub(rs))
	}
	if !ReportTime(time.Time{}).IsZero() {
		t.Fatal("zero time should stay zero")
	}

	// With a correction, both ends shift equally: durations are unchanged.
	SetClockOffset(-time.Hour)
	if ReportTime(stop).Sub(ReportTime(start)) != 1234*time.Millisecond {
		t.Fatal("correction changed a duration")
	}
}

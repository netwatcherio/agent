package probes

import (
	"sync/atomic"
	"time"
)

// clockOffset is controller time minus local time, in nanoseconds, as last
// measured by the time sync with the controller. Positive means the local
// clock is behind.
//
// It corrects reported timestamps only. Measurements (RTTs, jitter,
// durations) always use the local monotonic clock and never this offset.
var clockOffset atomic.Int64

const (
	// minClockCorrection is the smallest offset that is applied. Below it the
	// measurement (accurate to about half a round trip) is mostly noise, and
	// a well-synced host is better left uncorrected.
	minClockCorrection = time.Second

	// clockOffsetHysteresis is how much a new measurement must differ from
	// the offset in use before it replaces it, so repeated syncs don't nudge
	// timestamps back and forth by a few milliseconds.
	clockOffsetHysteresis = 500 * time.Millisecond
)

// SetClockOffset sets the offset directly (offsets under minClockCorrection
// become 0).
func SetClockOffset(d time.Duration) {
	if d > -minClockCorrection && d < minClockCorrection {
		d = 0
	}
	clockOffset.Store(int64(d))
}

// UpdateClockOffset applies a new measurement unless it is within
// clockOffsetHysteresis of the offset already in use. It returns the offset
// in effect afterwards.
func UpdateClockOffset(measured time.Duration) time.Duration {
	current := ClockOffset()
	diff := measured - current
	if diff < 0 {
		diff = -diff
	}
	if diff >= clockOffsetHysteresis {
		SetClockOffset(measured)
	} else if current == 0 {
		// Still apply the small-offset rule on the first measurement.
		SetClockOffset(0)
	}
	return ClockOffset()
}

// ClockOffset returns the offset applied to local timestamps.
func ClockOffset() time.Duration {
	return time.Duration(clockOffset.Load())
}

// Now returns the current time corrected to the controller's clock, in UTC.
//
// Use it for timestamps reported to the controller, so a host whose clock or
// time zone rules are wrong (for example an hour ahead after a missed time
// zone change) still reports data at the right moment. UTC changes only how
// the instant is written, never the instant itself.
//
// The result carries no monotonic reading, so never use it to measure a
// duration; use time.Now()/time.Since for that.
func Now() time.Time {
	return time.Now().Add(ClockOffset()).UTC()
}

// ReportTime converts a locally taken timestamp into a reported one: it
// applies the clock correction and normalizes to UTC. Zero stays zero.
func ReportTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.Add(ClockOffset()).UTC()
}

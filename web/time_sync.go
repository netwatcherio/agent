package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
	log "github.com/sirupsen/logrus"
)

const (
	// clockSyncSamples is how many round trips each sync takes. The sample
	// with the shortest round trip is used: its offset has the smallest
	// possible error (at most half that round trip).
	clockSyncSamples = 3

	// clockSyncMaxRTT rejects a sync whose best round trip was this slow. The
	// offset error is bounded by RTT/2, so keeping the previous offset is
	// more accurate than applying a poor measurement.
	clockSyncMaxRTT = 2 * time.Second

	// ClockResyncInterval is how often the agent re-measures its clock
	// against the controller while connected, so a clock that changes while
	// the agent runs (manual correction, time zone or DST change applied by
	// hand, drift) is picked up without waiting for a reconnect.
	ClockResyncInterval = 30 * time.Minute
)

// absDuration returns the absolute value of a duration
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// clockSample is one round trip to the controller's time endpoint.
type clockSample struct {
	offset time.Duration // controller time minus local time at the midpoint
	rtt    time.Duration
}

// sampleOffset estimates controller-minus-local time from one exchange.
//
// The controller reads its clock somewhere between our send (t0) and receive
// (t1). Assuming that is the midpoint, as NTP does, the error is at most
// RTT/2. Durations use the monotonic clock, so a wall-clock jump during the
// request cannot distort the result.
func sampleOffset(serverTime, t0, t1 time.Time) clockSample {
	rtt := t1.Sub(t0)
	mid := t0.Add(rtt / 2)
	return clockSample{offset: serverTime.Sub(mid), rtt: rtt}
}

// bestSample returns the sample with the smallest round trip.
func bestSample(samples []clockSample) (clockSample, bool) {
	if len(samples) == 0 {
		return clockSample{}, false
	}
	best := samples[0]
	for _, s := range samples[1:] {
		if s.rtt < best.rtt {
			best = s
		}
	}
	return best, true
}

// SyncTime measures the offset between the controller's clock and this
// host's clock and applies it to timestamps the agent reports.
//
// Only reported timestamps use the offset. Measurements (RTT, jitter,
// durations) keep using the local monotonic clock and are unaffected.
func SyncTime(ctx context.Context, apiURL string, workspaceID uint, agentID uint, psk string) error {
	timeURL := apiURL + "/time"

	// One client for all samples so later ones reuse the connection and
	// measure a single round trip rather than DNS + TCP + TLS setup.
	httpClient := &http.Client{Timeout: 10 * time.Second}
	defer httpClient.CloseIdleConnections()

	var samples []clockSample
	var lastErr error
	for i := 0; i < clockSyncSamples; i++ {
		s, err := fetchClockSample(ctx, httpClient, timeURL, workspaceID, agentID, psk)
		if err != nil {
			lastErr = err
			continue
		}
		samples = append(samples, s)
	}

	best, ok := bestSample(samples)
	if !ok {
		return lastErr
	}
	if best.rtt > clockSyncMaxRTT {
		return fmt.Errorf("time sync: best round trip %v too slow for an accurate offset, keeping %v",
			best.rtt.Round(time.Millisecond), probes.ClockOffset())
	}

	applied := probes.UpdateClockOffset(best.offset)
	if absDuration(best.offset) > 30*time.Second {
		log.Warnf("Time sync: this host's clock differs from the controller by %v (rtt %v); correcting reported timestamps by %v",
			best.offset.Round(time.Millisecond), best.rtt.Round(time.Millisecond), applied)
	} else {
		log.Infof("Time sync: offset=%v (rtt %v, applied %v)",
			best.offset.Round(time.Millisecond), best.rtt.Round(time.Millisecond), applied)
	}
	return nil
}

func fetchClockSample(ctx context.Context, client *http.Client, timeURL string, workspaceID, agentID uint, psk string) (clockSample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, timeURL, nil)
	if err != nil {
		return clockSample{}, fmt.Errorf("failed to create time request: %w", err)
	}
	req.Header.Set("X-Workspace-ID", fmt.Sprintf("%d", workspaceID))
	req.Header.Set("X-Agent-ID", fmt.Sprintf("%d", agentID))
	req.Header.Set("X-Agent-PSK", psk)

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return clockSample{}, fmt.Errorf("failed to fetch controller time: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	t1 := time.Now()
	resp.Body.Close()
	if err != nil {
		return clockSample{}, fmt.Errorf("failed to read time response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return clockSample{}, fmt.Errorf("time endpoint returned status %d", resp.StatusCode)
	}

	var timeResp struct {
		Time int64 `json:"server_unix_ms"` // Unix timestamp in milliseconds
	}
	if err := json.Unmarshal(body, &timeResp); err != nil {
		return clockSample{}, fmt.Errorf("failed to parse time response: %w", err)
	}
	if timeResp.Time <= 0 {
		return clockSample{}, fmt.Errorf("time endpoint returned no time")
	}
	return sampleOffset(time.UnixMilli(timeResp.Time), t0, t1), nil
}

// GetTimeOffset returns the current time offset
func GetTimeOffset() time.Duration {
	return probes.ClockOffset()
}

// AdjustedTime returns time.Now() adjusted by the time offset
// Use this instead of time.Now() when creating timestamps for probe data
func AdjustedTime() time.Time {
	return probes.Now()
}

package nettime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// timeOffset is a global variable holding the time offset between agent and controller
// Positive offset means local time is behind server time
var timeOffset time.Duration

// absDuration returns the absolute value of a duration
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// SyncTime fetches the controller's time and calculates the offset between local and server clocks
func SyncTime(ctx context.Context, apiURL string, workspaceID uint, agentID uint, psk string) error {
	timeURL := apiURL + "/time"

	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, timeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create time request: %w", err)
	}

	req.Header.Set("X-Workspace-ID", fmt.Sprintf("%d", workspaceID))
	req.Header.Set("X-Agent-ID", fmt.Sprintf("%d", agentID))
	req.Header.Set("X-Agent-PSK", psk)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch controller time: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("time endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read time response: %w", err)
	}

	var timeResp struct {
		Time int64 `json:"server_unix_ms"` // Unix timestamp in milliseconds
	}
	if err := json.Unmarshal(body, &timeResp); err != nil {
		return fmt.Errorf("failed to parse time response: %w", err)
	}

	serverTime := time.UnixMilli(timeResp.Time)
	localTime := time.Now()
	offset := serverTime.Sub(localTime).Truncate(time.Hour)

	timeOffset = offset

	// Warn if offset is significant (> 30 seconds)
	if absDuration(offset) > 30*time.Second {
		log.Warnf("Time sync: significant offset detected: %v (server=%v, local=%v)", offset, serverTime, localTime)
	} else {
		log.Infof("Time sync: offset=%v (server=%v, local=%v)", offset, serverTime, localTime)
	}

	return nil
}

// GetTimeOffset returns the current time offset
func GetTimeOffset() time.Duration {
	return timeOffset
}

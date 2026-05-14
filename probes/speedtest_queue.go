package probes

import (
	"encoding/json"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
	log "github.com/sirupsen/logrus"
)

// SpeedtestQueueItem represents a queued speedtest request from the controller.
type SpeedtestQueueItem struct {
	ID          uint      `json:"id"`
	WorkspaceID uint      `json:"workspace_id"`
	AgentID     uint      `json:"agent_id"`
	ServerID    string    `json:"server_id"`
	ServerName  string    `json:"server_name"`
	Status      string    `json:"status"`
	RequestedAt time.Time `json:"requested_at"`
}

// SpeedtestServerInfo is the format we send to the controller.
type SpeedtestServerInfo struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Sponsor  string  `json:"sponsor"`
	Host     string  `json:"host"`
	URL      string  `json:"url"`
	Country  string  `json:"country"`
	Lat      string  `json:"lat"`
	Lon      string  `json:"lon"`
	Distance float64 `json:"distance"`
}

// SpeedtestResult is the format we send to the controller.
type SpeedtestResult struct {
	QueueID uint            `json:"queue_id"`
	Success bool            `json:"success"`
	Error   string          `json:"error,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// FetchSpeedtestServers fetches available speedtest.net servers.
func FetchSpeedtestServers() ([]SpeedtestServerInfo, error) {
	client := speedtest.New()
	serverList, err := client.FetchServers()
	if err != nil {
		return nil, err
	}

	var servers []SpeedtestServerInfo
	// Return up to 50 nearest servers
	count := 0
	for _, s := range serverList {
		if count >= 50 {
			break
		}
		servers = append(servers, SpeedtestServerInfo{
			ID:       s.ID,
			Name:     s.Name,
			Sponsor:  s.Sponsor,
			Host:     s.Host,
			URL:      s.URL,
			Country:  s.Country,
			Lat:      s.Lat,
			Lon:      s.Lon,
			Distance: s.Distance,
		})
		count++
	}

	log.Infof("Fetched %d speedtest servers", len(servers))
	return servers, nil
}

// RunSpeedtestForQueue runs a speedtest for a specific queue item.
func RunSpeedtestForQueue(item SpeedtestQueueItem) SpeedtestResult {
	log.Infof("Running speedtest for queue item %d (server: %s)", item.ID, item.ServerID)

	client := speedtest.New()
	serverList, err := client.FetchServers()
	if err != nil {
		return SpeedtestResult{
			QueueID: item.ID,
			Success: false,
			Error:   err.Error(),
		}
	}

	var targets []*speedtest.Server

	if item.ServerID == "" {
		// Auto-select nearest servers
		found, err := serverList.FindServer([]int{})
		if err != nil {
			return SpeedtestResult{
				QueueID: item.ID,
				Success: false,
				Error:   err.Error(),
			}
		}
		targets = append(targets, found...)
	} else {
		// Find specific server by ID
		for _, s := range serverList {
			if s.ID == item.ServerID {
				targets = append(targets, s)
				break
			}
		}
		if len(targets) == 0 {
			return SpeedtestResult{
				QueueID: item.ID,
				Success: false,
				Error:   "specified server not found",
			}
		}
	}

	// Limit to first target
	if len(targets) > 1 {
		targets = targets[:1]
	}

	var results []speedtest.Server
	for _, s := range targets {
		log.Infof("Testing server: %s (%s)", s.Name, s.Sponsor)

		if err := s.PingTest(nil); err != nil {
			log.Warnf("Ping test failed: %v", err)
			continue
		}
		if err := s.DownloadTest(); err != nil {
			log.Warnf("Download test failed: %v", err)
			continue
		}
		if err := s.UploadTest(); err != nil {
			log.Warnf("Upload test failed: %v", err)
			continue
		}

		results = append(results, *s)
		s.Context.Reset()
	}

	if len(results) == 0 {
		return SpeedtestResult{
			QueueID: item.ID,
			Success: false,
			Error:   "all speed tests failed",
		}
	}

	// Package results
	payload := SpeedTestPayload{
		TestData:  results,
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return SpeedtestResult{
			QueueID: item.ID,
			Success: false,
			Error:   err.Error(),
		}
	}

	log.Infof("Speedtest completed for queue item %d", item.ID)
	return SpeedtestResult{
		QueueID: item.ID,
		Success: true,
		Data:    data,
	}
}

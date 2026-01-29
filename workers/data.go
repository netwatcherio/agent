package workers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/netwatcherio/netwatcher-agent/web"
	log "github.com/sirupsen/logrus"
)

// Global retry queue instance
var probeRetryQueue = NewRetryQueue(DefaultMaxQueueSize)

// GetRetryQueue returns the global retry queue for probe data.
// This can be used to flush queued data on reconnection.
func GetRetryQueue() *RetryQueue {
	return probeRetryQueue
}

// ProbeDataWorker processes probe data and sends it to the controller.
// If the WebSocket connection is unavailable, data is queued for retry.
func ProbeDataWorker(wsH *web.WSClient, ch chan probes.ProbeData) {
	const maxSendFailures = 3 // Trigger reconnect after 3 consecutive failures
	sendFailures := 0

	go func(cn *web.WSClient, c chan probes.ProbeData) {
		for p := range ch {
			p.CreatedAt = time.Now()
			marshal, err := json.Marshal(p)
			if err != nil {
				log.Errorf("ProbeDataWorker: failed to marshal probe data: %v", err)
				continue
			}

			// Check if connection is available
			if wsH.WsConn == nil || !wsH.IsConnected() {
				log.Debug("ProbeDataWorker: no connection, queuing probe data")
				probeRetryQueue.Enqueue(p)
				sendFailures++
				if sendFailures >= maxSendFailures {
					log.Warnf("ProbeDataWorker: %d consecutive send failures (no connection), triggering reconnection", sendFailures)
					sendFailures = 0
					go wsH.ConnectWithRetry(context.Background())
				}
				continue
			}

			// Try to send
			if !wsH.WsConn.Emit("probe_post", marshal) {
				log.Warn("ProbeDataWorker: emit failed, queuing probe data for retry")
				probeRetryQueue.Enqueue(p)
				sendFailures++
				if sendFailures >= maxSendFailures {
					log.Warnf("ProbeDataWorker: %d consecutive emit failures, triggering reconnection", sendFailures)
					sendFailures = 0
					go wsH.ConnectWithRetry(context.Background())
				}
			} else {
				log.Debug("ProbeDataWorker: probe data sent successfully")
				sendFailures = 0 // Reset on successful send
			}
		}
	}(wsH, ch)
}

// FlushRetryQueue attempts to send all queued probe data.
// Call this after reconnection to flush any buffered data.
func FlushRetryQueue(wsH *web.WSClient) int {
	if wsH.WsConn == nil {
		log.Warn("FlushRetryQueue: no connection available")
		return 0
	}
	return probeRetryQueue.Flush(wsH.WsConn)
}

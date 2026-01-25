package workers

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/netwatcherio/netwatcher-agent/probes"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultMaxQueueSize = 1000
	DefaultRetryTick    = 5 * time.Second
)

// RetryQueue holds probe data that failed to send and retries delivery.
// Thread-safe for concurrent access from multiple goroutines.
type RetryQueue struct {
	mu      sync.Mutex
	queue   []probes.ProbeData
	maxSize int
}

// NewRetryQueue creates a new retry queue with the specified max size.
// If maxSize is 0, DefaultMaxQueueSize (1000) is used.
func NewRetryQueue(maxSize int) *RetryQueue {
	if maxSize <= 0 {
		maxSize = DefaultMaxQueueSize
	}
	return &RetryQueue{
		queue:   make([]probes.ProbeData, 0, 100),
		maxSize: maxSize,
	}
}

// Enqueue adds probe data to the retry queue.
// If the queue is full, the oldest item is dropped.
func (q *RetryQueue) Enqueue(data probes.ProbeData) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Drop oldest if at capacity
	if len(q.queue) >= q.maxSize {
		log.Warnf("RetryQueue: queue full (%d items), dropping oldest item", q.maxSize)
		q.queue = q.queue[1:]
	}

	q.queue = append(q.queue, data)
	log.Debugf("RetryQueue: enqueued probe data (queue size: %d)", len(q.queue))
}

// Size returns the current number of items in the queue.
func (q *RetryQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queue)
}

// Emitter is an interface for sending probe data (allows mocking in tests)
type Emitter interface {
	Emit(event string, data []byte) bool
}

// Flush attempts to send all queued items.
// Returns the number of items successfully sent.
func (q *RetryQueue) Flush(emitter Emitter) int {
	q.mu.Lock()
	if len(q.queue) == 0 {
		q.mu.Unlock()
		return 0
	}

	// Take a copy of the queue for processing and clear the original
	// This ensures new items added during flush are tracked separately
	toSend := make([]probes.ProbeData, len(q.queue))
	copy(toSend, q.queue)
	q.queue = q.queue[:0] // Clear the queue - new items will be appended fresh
	q.mu.Unlock()

	log.Infof("RetryQueue: flushing %d queued items", len(toSend))

	sent := 0
	var failed []probes.ProbeData

	for _, data := range toSend {
		marshal, err := json.Marshal(data)
		if err != nil {
			log.Errorf("RetryQueue: failed to marshal probe data: %v", err)
			continue // Skip this item, don't retry
		}

		if emitter.Emit("probe_post", marshal) {
			sent++
		} else {
			// Failed to send, keep for next retry
			failed = append(failed, data)
		}
	}

	// Re-queue failed items plus any new items that arrived during flush
	if len(failed) > 0 {
		q.mu.Lock()
		// Prepend failed items (oldest first) to any new items added during flush
		q.queue = append(failed, q.queue...)
		q.mu.Unlock()
	}

	if sent > 0 {
		log.Infof("RetryQueue: successfully sent %d items, %d remaining", sent, len(failed))
	}

	return sent
}

// Clear empties the queue.
func (q *RetryQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queue = q.queue[:0]
	log.Info("RetryQueue: cleared")
}

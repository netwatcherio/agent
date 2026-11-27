package probes

import (
	"math"
	"testing"
	"time"
)

func newTestCycle() *CycleTracker {
	return &CycleTracker{
		PacketTimes:  make(map[int]PacketTime),
		receivedSeqs: make(map[int]int),
	}
}

func sendAt(c *CycleTracker, seq int, at time.Time) PacketTime {
	pt := newPacketTime(at)
	c.PacketSeqs = append(c.PacketSeqs, seq)
	c.PacketTimes[seq] = pt
	return pt
}

// Sub-millisecond round trips must not collapse to 0.
func TestRecordAckSubMillisecondRTT(t *testing.T) {
	c := newTestCycle()
	base := time.Now()
	pt := sendAt(c, 1, base)

	rtt, ok := c.recordAck(1, pt.Sent, base.Add(420*time.Microsecond))
	if !ok {
		t.Fatal("ACK not applied")
	}
	if math.Abs(rtt-0.42) > 0.001 {
		t.Fatalf("rtt = %v ms, want 0.42", rtt)
	}
	if got := c.PacketTimes[1].RTT(); math.Abs(got-0.42) > 0.001 {
		t.Fatalf("stored RTT = %v, want 0.42", got)
	}
}

// A late ACK from an earlier cycle that reused the sequence number must not
// be counted as a receipt of the new packet.
func TestRecordAckRejectsStaleEcho(t *testing.T) {
	c := newTestCycle()
	now := time.Now()
	pt := sendAt(c, 1, now)

	staleSent := pt.Sent - 60_000 // sent a cycle (60s) earlier
	if _, ok := c.recordAck(1, staleSent, now.Add(5*time.Millisecond)); ok {
		t.Fatal("stale ACK was applied")
	}
	if c.staleAcks != 1 {
		t.Fatalf("staleAcks = %d, want 1", c.staleAcks)
	}
	if c.PacketTimes[1].Received != 0 {
		t.Fatal("stale ACK marked packet as received")
	}
	if c.duplicates != 0 {
		t.Fatal("stale ACK counted as duplicate")
	}

	// The genuine ACK still lands afterwards.
	if _, ok := c.recordAck(1, pt.Sent, now.Add(10*time.Millisecond)); !ok {
		t.Fatal("genuine ACK rejected after stale one")
	}
}

func TestRecordAckDuplicate(t *testing.T) {
	c := newTestCycle()
	now := time.Now()
	pt := sendAt(c, 1, now)
	c.recordAck(1, pt.Sent, now.Add(time.Millisecond))
	if _, ok := c.recordAck(1, pt.Sent, now.Add(2*time.Millisecond)); ok {
		t.Fatal("duplicate ACK applied twice")
	}
	if c.duplicates != 1 {
		t.Fatalf("duplicates = %d, want 1", c.duplicates)
	}
}

// RFC 3550 jitter used to be skipped whenever the first transit time rounded
// to 0ms (any LAN path). It must now be computed from the monotonic clock.
func TestRecordAckRFC3550JitterOnFastPath(t *testing.T) {
	c := newTestCycle()
	base := time.Now()
	// Packets sent 20ms apart; RTTs alternate 0.2ms / 1.2ms => |D| = 1ms each.
	for i := 1; i <= 50; i++ {
		sent := base.Add(time.Duration(i) * 20 * time.Millisecond)
		pt := sendAt(c, i, sent)
		rtt := 200 * time.Microsecond
		if i%2 == 0 {
			rtt = 1200 * time.Microsecond
		}
		c.recordAck(i, pt.Sent, sent.Add(rtt))
	}
	if c.rfc3550Jitter < 0.9 || c.rfc3550Jitter > 1.01 {
		t.Fatalf("rfc3550Jitter = %v ms, want ~1.0", c.rfc3550Jitter)
	}
}

func TestCalculateStatsPrecisionAndWireTypes(t *testing.T) {
	ts := &TrafficSim{Probe: &Probe{ID: 1}}
	c := newTestCycle()
	base := time.Now()
	rtts := []time.Duration{300 * time.Microsecond, 700 * time.Microsecond, 1600 * time.Microsecond}
	for i, r := range rtts {
		sent := base.Add(time.Duration(i) * time.Second)
		pt := sendAt(c, i+1, sent)
		c.recordAck(i+1, pt.Sent, sent.Add(r))
	}
	sendAt(c, 4, base.Add(4*time.Second)) // never ACKed
	pt4 := c.PacketTimes[4]
	pt4.TimedOut = true
	c.PacketTimes[4] = pt4

	stats := ts.calculateStats(c)

	if avg := stats["averageRTT"].(float64); math.Abs(avg-0.8667) > 0.001 {
		t.Fatalf("averageRTT = %v, want ~0.867", avg)
	}
	// minRTT/maxRTT stay integers: the controller decodes them as int64.
	if v, ok := stats["minRTT"].(int64); !ok || v != 0 {
		t.Fatalf("minRTT = %#v, want int64(0)", stats["minRTT"])
	}
	if v, ok := stats["maxRTT"].(int64); !ok || v != 2 {
		t.Fatalf("maxRTT = %#v, want int64(2)", stats["maxRTT"])
	}
	if lost := stats["lostPackets"].(int); lost != 1 {
		t.Fatalf("lostPackets = %d, want 1", lost)
	}
}

func TestPacketAgeUsesMonotonicClock(t *testing.T) {
	now := time.Now()
	pt := newPacketTime(now.Add(-3 * time.Second))
	if age := pt.age(now); age < 2900*time.Millisecond || age > 3100*time.Millisecond {
		t.Fatalf("age = %v, want ~3s", age)
	}
}

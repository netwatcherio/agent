package probes

import (
	"context"
	"encoding/json"
	"fmt"
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"runtime"
	"time"
)

type PingPayload struct {
	StartTimestamp        time.Time     `json:"start_timestamp" bson:"start_timestamp"`
	StopTimestamp         time.Time     `json:"stop_timestamp" bson:"stop_timestamp"`
	PacketsRecv           int           `json:"packets_recv" bson:"packets_recv"`
	PacketsSent           int           `json:"packets_sent" bson:"packets_sent"`
	PacketsRecvDuplicates int           `json:"packets_recv_duplicates" bson:"packets_recv_duplicates"`
	PacketLoss            float64       `json:"packet_loss" bson:"packet_loss"`
	Addr                  string        `json:"addr" bson:"addr"`
	MinRtt                time.Duration `json:"min_rtt" bson:"min_rtt"`
	MaxRtt                time.Duration `json:"max_rtt" bson:"max_rtt"`
	AvgRtt                time.Duration `json:"avg_rtt" bson:"avg_rtt"`
	StdDevRtt             time.Duration `json:"std_dev_rtt" bson:"std_dev_rtt"`
}

func Ping(ac *Probe, pingChan chan ProbeData, mtrProbe Probe) error {
	if len(ac.Targets) == 0 || ac.Targets[0].Target == "" {
		return fmt.Errorf("ping: no target provided")
	}
	target := ac.Targets[0].Target

	startTime := time.Now()

	pinger, err := probing.NewPinger(target)
	if err != nil {
		return fmt.Errorf("ping: new pinger: %w", err)
	}

	// ----- Configure pinger per pro-bing docs -----

	// Count: if >0, send exactly Count packets; if 0, run until Timeout/context.
	if ac.Count > 0 {
		pinger.Count = ac.Count
	}

	// Interval: default 1s if not provided.
	if ac.IntervalSec > 0 {
		pinger.Interval = time.Duration(ac.IntervalSec) * time.Second
	} else {
		pinger.Interval = time.Second
	}

	// Timeout: total runtime cap (pinger exits when reached).
	// Fall back to 60s if not set on the probe.
	runCap := time.Duration(ac.DurationSec) * time.Second
	if runCap <= 0 {
		runCap = 60 * time.Second
	}
	pinger.Timeout = runCap

	// OS privilege behavior (see README notes):
	switch runtime.GOOS {
	case "windows":
		// Windows requires privileged mode per docs.
		pinger.SetPrivileged(true)
		// Optional: Windows-friendly payload size
		pinger.Size = 548
	case "linux", "darwin":
		// On Linux/macOS you can use unprivileged mode if your system is set up,
		// otherwise enable privileged/raw-socket mode:
		pinger.SetPrivileged(true)
	default:
		// Default to privileged to be safe.
		pinger.SetPrivileged(true)
	}

	// ----- Callbacks -----

	pinger.OnRecv = func(pkt *probing.Packet) {
		// match README: simple per-packet output (keep or remove)
		/*fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
		pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)*/
	}
	pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
		// optional: show dups like README example
		/*fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
		pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL)*/
	}
	pinger.OnFinish = func(stats *probing.Statistics) {
		// NOTE: stats.* RTT fields are already time.Duration per pro-bing
		pingR := PingPayload{
			StartTimestamp:        startTime,
			StopTimestamp:         time.Now(),
			PacketsRecv:           stats.PacketsRecv,
			PacketsSent:           stats.PacketsSent,
			PacketsRecvDuplicates: stats.PacketsRecvDuplicates,
			PacketLoss:            stats.PacketLoss,
			Addr:                  stats.Addr,
			MinRtt:                stats.MinRtt,
			MaxRtt:                stats.MaxRtt,
			AvgRtt:                stats.AvgRtt,
			StdDevRtt:             stats.StdDevRtt,
		}

		/*if marshaled, err := json.Marshal(stats); err == nil {
			log.WithField("target", target).Info(string(marshaled))
		}*/

		bytes, err := json.Marshal(pingR)
		if err != nil {
			log.WithError(err).Warn("ping: marshal payload")
			return
		}

		cD := ProbeData{
			ProbeID:      ac.ID,
			ProbeAgentID: ac.AgentID,
			Type:         ProbeType_PING,
			Payload:      bytes,
			Target:       target,
		}
		pingChan <- cD

		// Optional: trigger follow-up probes based on loss here.
	}

	// ----- Run with context so callers can cancel early -----
	// Context will also stop early even if pinger.Timeout not yet reached.
	ctx, cancel := context.WithTimeout(context.Background(), runCap)
	defer cancel()

	if err := pinger.RunWithContext(ctx); err != nil {
		// per issues, timeout doesn’t return an error; other errors should be surfaced
		log.WithError(err).Error("ping: RunWithContext failed")
		return err
	}

	return nil
}

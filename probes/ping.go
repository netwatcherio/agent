package probes

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
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

	// Count: use configured count (default to 60 if not set)
	// Each packet is sent at 1s intervals, so count=60 = ~60s per run
	if ac.Count > 0 {
		pinger.Count = ac.Count
	} else {
		pinger.Count = 60
	}

	// Interval between individual pings: fixed at 1 second
	// Note: IntervalSec is for SCHEDULING between probe runs, not individual ping interval
	pinger.Interval = time.Second

	// Timeout: use configured timeout, default to 30s
	timeout := ac.TimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	pinger.Timeout = time.Duration(timeout) * time.Second

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

	// Interface binding: if the probe specifies a BindInterface, resolve its IP
	// and set it as the source address for ICMP packets.
	var sourceIP, sourceIface string
	if ac.BindInterface != "" {
		if bindIP := resolveBindIP(ac.BindInterface); bindIP != "" {
			pinger.Source = bindIP
			sourceIP = bindIP
			sourceIface = ac.BindInterface
			log.Infof("[ping] probe=%d binding to interface %q (source: %s)", ac.ID, ac.BindInterface, bindIP)
		} else {
			log.Warnf("[ping] probe=%d: configured interface %q has no valid IP, using OS default", ac.ID, ac.BindInterface)
		}
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
			ProbeID:         ac.ID,
			Type:            ProbeType_PING,
			Payload:         bytes,
			Target:          target,
			SourceIP:        sourceIP,
			SourceInterface: sourceIface,
		}
		pingChan <- cD

		// Optional: trigger follow-up probes based on loss here.
	}

	if err := pinger.Run(); err != nil {
		// per issues, timeout doesn’t return an error; other errors should be surfaced
		log.WithError(err).Error("ping: failed")
		return err
	}

	return nil
}

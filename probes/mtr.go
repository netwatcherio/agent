package probes

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/util"
	log "github.com/sirupsen/logrus"
)

type MtrPayload struct {
	StartTimestamp time.Time `json:"start_timestamp"bson:"start_timestamp"`
	StopTimestamp  time.Time `json:"stop_timestamp"bson:"stop_timestamp"`
	Report         struct {
		Info struct {
			Target struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"target"`
		} `json:"info"`
		Hops []struct {
			TTL   int `json:"ttl"`
			Hosts []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"hosts"`
			Extensions []string `json:"extensions"`
			LossPct    string   `json:"loss_pct"`
			Sent       int      `json:"sent"`
			Last       string   `json:"last"`
			Recv       int      `json:"recv"`
			Avg        string   `json:"avg"`
			Best       string   `json:"best"`
			Worst      string   `json:"worst"`
			StdDev     string   `json:"stddev"`
		} `json:"hops"`
	} `json:"report"bson:"report"`
}

// Mtr runs MTR-style traceroute using NTrace-core
func Mtr(cd *Probe, triggered bool) (MtrPayload, error) {
	var mtrResult MtrPayload
	mtrResult.StartTimestamp = time.Now()

	numMeasurements := 5
	if triggered {
		numMeasurements = 15
	}

	target := cd.Targets[0].Target

	// Resolve the target to an IP address
	ip, err := resolveTarget(target)
	if err != nil {
		return mtrResult, fmt.Errorf("failed to resolve target %s: %w", target, err)
	}

	// Set target info
	mtrResult.Report.Info.Target.IP = ip.String()
	mtrResult.Report.Info.Target.Hostname = target

	// Configure NTrace
	config := trace.Config{
		DstIP:            ip,
		BeginHop:         1, // Must be >= 1 to avoid index out of range
		MaxHops:          30,
		NumMeasurements:  numMeasurements,
		MaxAttempts:      3,
		ParallelRequests: 18,
		Timeout:          1000 * time.Millisecond,
		RDNS:             true,
		AlwaysWaitRDNS:   true,
		IPGeoSource:      nil, // Disable geo IP lookup
		PacketInterval:   50,
		TTLInterval:      50,
		PktSize:          52,
	}

	log.WithFields(log.Fields{
		"target":       target,
		"ip":           ip.String(),
		"measurements": numMeasurements,
	}).Debug("Starting NTrace traceroute")

	// Execute traceroute
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Run the trace in a goroutine so we can handle timeout
	resultChan := make(chan *trace.Result, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := trace.Traceroute(trace.ICMPTrace, config)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- result
	}()

	var result *trace.Result
	select {
	case result = <-resultChan:
		// Success
	case err := <-errChan:
		return mtrResult, fmt.Errorf("traceroute failed: %w", err)
	case <-ctx.Done():
		return mtrResult, fmt.Errorf("traceroute timeout")
	}

	// Transform NTrace result to MtrPayload format
	mtrResult.Report.Hops = transformHops(result, numMeasurements)
	mtrResult.StopTimestamp = time.Now()

	log.WithFields(log.Fields{
		"target": target,
		"hops":   len(mtrResult.Report.Hops),
	}).Info("NTrace traceroute completed successfully")

	return mtrResult, nil
}

// resolveTarget resolves a hostname or IP string to a net.IP
func resolveTarget(target string) (net.IP, error) {
	// Check if it's already an IP
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}

	// Use NTrace's domain lookup (or fall back to standard resolver)
	ip, err := util.DomainLookUp(target, "all", "", true)
	if err != nil {
		// Fallback to standard resolver
		ips, err := net.LookupIP(target)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses found for %s", target)
		}
		return ips[0], nil
	}
	return ip, nil
}

// transformHops converts NTrace [][]Hop to MtrPayload hop format
func transformHops(result *trace.Result, numMeasurements int) []struct {
	TTL   int `json:"ttl"`
	Hosts []struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	} `json:"hosts"`
	Extensions []string `json:"extensions"`
	LossPct    string   `json:"loss_pct"`
	Sent       int      `json:"sent"`
	Last       string   `json:"last"`
	Recv       int      `json:"recv"`
	Avg        string   `json:"avg"`
	Best       string   `json:"best"`
	Worst      string   `json:"worst"`
	StdDev     string   `json:"stddev"`
} {
	var hops []struct {
		TTL   int `json:"ttl"`
		Hosts []struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		} `json:"hosts"`
		Extensions []string `json:"extensions"`
		LossPct    string   `json:"loss_pct"`
		Sent       int      `json:"sent"`
		Last       string   `json:"last"`
		Recv       int      `json:"recv"`
		Avg        string   `json:"avg"`
		Best       string   `json:"best"`
		Worst      string   `json:"worst"`
		StdDev     string   `json:"stddev"`
	}

	for ttlIdx, attempts := range result.Hops {
		if len(attempts) == 0 {
			continue
		}

		ttl := ttlIdx + 1

		// Aggregate statistics across all attempts for this TTL
		var (
			sent       = len(attempts)
			recv       = 0
			rtts       []float64
			lastRTT    float64
			bestRTT    = math.MaxFloat64
			worstRTT   = 0.0
			hostsMap   = make(map[string]string) // IP -> Hostname
			extensions = make([]string, 0)       // Initialize to empty slice, not nil
		)

		for _, hop := range attempts {
			if hop.Success {
				recv++
				rttMs := float64(hop.RTT) / float64(time.Millisecond)
				rtts = append(rtts, rttMs)
				lastRTT = rttMs

				if rttMs < bestRTT {
					bestRTT = rttMs
				}
				if rttMs > worstRTT {
					worstRTT = rttMs
				}
			}

			// Collect unique hosts
			if hop.Address != nil {
				ipStr := hop.Address.String()
				if _, exists := hostsMap[ipStr]; !exists {
					hostsMap[ipStr] = hop.Hostname
				}
			}

			// Collect MPLS labels as extensions
			if len(hop.MPLS) > 0 {
				for _, label := range hop.MPLS {
					extensions = append(extensions, label)
				}
			}
		}

		// Calculate statistics
		lossPct := 0.0
		if sent > 0 {
			lossPct = float64(sent-recv) / float64(sent) * 100
		}

		avgRTT := 0.0
		if len(rtts) > 0 {
			sum := 0.0
			for _, r := range rtts {
				sum += r
			}
			avgRTT = sum / float64(len(rtts))
		}

		stdDev := 0.0
		if len(rtts) > 1 {
			variance := 0.0
			for _, r := range rtts {
				diff := r - avgRTT
				variance += diff * diff
			}
			stdDev = math.Sqrt(variance / float64(len(rtts)))
		}

		// Reset best/worst if no successful attempts
		if recv == 0 {
			bestRTT = 0
			worstRTT = 0
		}

		// Build hosts list
		var hosts []struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		}
		for ip, hostname := range hostsMap {
			hosts = append(hosts, struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			}{
				IP:       ip,
				Hostname: hostname,
			})
		}

		// If no hosts were found (all timeouts), ensure hosts is empty array not nil
		if hosts == nil {
			hosts = make([]struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			}, 0)
		}

		hopData := struct {
			TTL   int `json:"ttl"`
			Hosts []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"hosts"`
			Extensions []string `json:"extensions"`
			LossPct    string   `json:"loss_pct"`
			Sent       int      `json:"sent"`
			Last       string   `json:"last"`
			Recv       int      `json:"recv"`
			Avg        string   `json:"avg"`
			Best       string   `json:"best"`
			Worst      string   `json:"worst"`
			StdDev     string   `json:"stddev"`
		}{
			TTL:        ttl,
			Hosts:      hosts,
			Extensions: extensions,
			LossPct:    fmt.Sprintf("%.2f", lossPct),
			Sent:       sent,
			Last:       fmt.Sprintf("%.2f", lastRTT),
			Recv:       recv,
			Avg:        fmt.Sprintf("%.2f", avgRTT),
			Best:       fmt.Sprintf("%.2f", bestRTT),
			Worst:      fmt.Sprintf("%.2f", worstRTT),
			StdDev:     fmt.Sprintf("%.2f", stdDev),
		}

		hops = append(hops, hopData)
	}

	return hops
}

func mtrNumDashCheck(str string) int {
	if str == "-" {
		return 0
	}
	return ConvHandleStrInt(str)
}

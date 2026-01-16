// Package tracert provides Windows tracert command execution and parsing.
// This is used as a fallback when Trippy cannot run (e.g., antivirus blocks it).
package tracert

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Result represents the parsed tracert output in a format compatible with MtrPayload.
type Result struct {
	TargetIP       string
	TargetHostname string
	StartTimestamp time.Time
	StopTimestamp  time.Time
	Hops           []Hop
}

// Hop represents a single hop in the tracert output.
type Hop struct {
	TTL      int
	IP       string
	Hostname string
	// Latencies from the 3 probes (in ms), -1 means timeout
	Latencies [3]float64
	// Calculated stats
	Sent    int
	Recv    int
	LossPct float64
	Best    float64
	Avg     float64
	Worst   float64
}

// Run executes the Windows tracert command and returns parsed results.
func Run(ctx context.Context, target string, maxHops int) (*Result, error) {
	if maxHops <= 0 {
		maxHops = 30 // Windows default
	}

	// tracert -h <maxHops> <target>
	cmd := exec.CommandContext(ctx, "tracert", "-h", strconv.Itoa(maxHops), target)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// tracert may return non-zero for incomplete traces, so check output
		if len(output) == 0 {
			return nil, fmt.Errorf("tracert failed: %w", err)
		}
		// Continue with parsing even if error, as partial results are useful
	}

	return ParseOutput(string(output), target)
}

// ParseOutput parses the raw Windows tracert output into a Result.
func ParseOutput(output string, target string) (*Result, error) {
	result := &Result{
		TargetHostname: target,
		StartTimestamp: time.Now(),
		Hops:           []Hop{},
	}

	scanner := bufio.NewScanner(strings.NewReader(output))

	// Patterns
	// Header: "Tracing route to hostname [ip]" or "Tracing route to ip"
	// Match either: "hostname [ip]" or just "ip/hostname"
	headerWithIPPattern := regexp.MustCompile(`Tracing route to (.+?)\s+\[(\d+\.\d+\.\d+\.\d+)\]`)
	headerPlainPattern := regexp.MustCompile(`Tracing route to (\S+)`)
	// Hop line: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
	// or:       "  1     3 ms     3 ms     3 ms  hostname [ip]"
	// or:       "  4     *        *        *     Request timed out."
	hopPattern := regexp.MustCompile(`^\s*(\d+)\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()

		// Parse header - try pattern with IP in brackets first
		if matches := headerWithIPPattern.FindStringSubmatch(line); matches != nil {
			result.TargetHostname = strings.TrimSpace(matches[1])
			result.TargetIP = matches[2]
			continue
		}
		// Try plain hostname/IP pattern
		if strings.HasPrefix(line, "Tracing route to") {
			if matches := headerPlainPattern.FindStringSubmatch(line); matches != nil {
				result.TargetHostname = strings.TrimSpace(matches[1])
				// Check if it's just an IP
				if ip := net.ParseIP(result.TargetHostname); ip != nil {
					result.TargetIP = result.TargetHostname
				}
				continue
			}
		}

		// Parse hop lines
		if matches := hopPattern.FindStringSubmatch(line); matches != nil {
			ttl, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}

			hop := parseHopLine(ttl, matches[2])
			if hop != nil {
				result.Hops = append(result.Hops, *hop)
			}
		}
	}

	result.StopTimestamp = time.Now()
	return result, nil
}

// parseHopLine parses the content after TTL number.
// Examples:
//
//	"   <1 ms    <1 ms    <1 ms  192.168.1.1"
//	"    3 ms     3 ms     3 ms  10.31.14.1"
//	"    *        8 ms     4 ms  96.1.214.126"
//	"    *        *        *     Request timed out."
//	"    4 ms     3 ms     3 ms  s206-116-50-83.bc.hsia.telus.net [206.116.50.83]"
func parseHopLine(ttl int, content string) *Hop {
	hop := &Hop{
		TTL:       ttl,
		Latencies: [3]float64{-1, -1, -1},
		Sent:      3,
		Recv:      0,
	}

	// Check for complete timeout
	if strings.Contains(content, "Request timed out") {
		// Complete timeout - no responses
		hop.LossPct = 100.0
		return hop
	}

	// Parse latencies and hostname/IP
	// Latency patterns: "<1 ms", "3 ms", "*"
	latencyPattern := regexp.MustCompile(`(<?\d+)\s*ms|(\*)`)

	latencies := latencyPattern.FindAllStringSubmatch(content, 3)
	for i, match := range latencies {
		if i >= 3 {
			break
		}
		if match[2] == "*" {
			hop.Latencies[i] = -1 // Timeout
		} else {
			val := match[1]
			if strings.HasPrefix(val, "<") {
				// <1 ms - approximate as 0.5ms
				hop.Latencies[i] = 0.5
			} else {
				ms, err := strconv.ParseFloat(val, 64)
				if err == nil {
					hop.Latencies[i] = ms
				}
			}
		}
	}

	// Calculate stats
	var sum float64
	hop.Best = -1
	hop.Worst = -1
	for _, lat := range hop.Latencies {
		if lat >= 0 {
			hop.Recv++
			sum += lat
			if hop.Best < 0 || lat < hop.Best {
				hop.Best = lat
			}
			if lat > hop.Worst {
				hop.Worst = lat
			}
		}
	}
	if hop.Recv > 0 {
		hop.Avg = sum / float64(hop.Recv)
	}
	hop.LossPct = float64(hop.Sent-hop.Recv) / float64(hop.Sent) * 100.0

	// Extract hostname and IP
	// Pattern: "hostname [ip]" or just "ip"
	// Remove the latency parts first
	remaining := latencyPattern.ReplaceAllString(content, "")
	remaining = strings.TrimSpace(remaining)
	remaining = strings.TrimSuffix(remaining, "ms")
	remaining = strings.TrimSpace(remaining)

	hostIPPattern := regexp.MustCompile(`^(.+?)\s*\[(\d+\.\d+\.\d+\.\d+)\]$`)
	if matches := hostIPPattern.FindStringSubmatch(remaining); matches != nil {
		hop.Hostname = strings.TrimSpace(matches[1])
		hop.IP = matches[2]
	} else {
		// Check if remaining is just an IP
		remaining = strings.TrimSpace(remaining)
		if ip := net.ParseIP(remaining); ip != nil {
			hop.IP = remaining
			hop.Hostname = remaining
		} else if remaining != "" {
			hop.Hostname = remaining
		}
	}

	return hop
}

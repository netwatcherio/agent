package tracert

import (
	"testing"
)

func TestParseOutput_BasicTrace(t *testing.T) {
	output := `Tracing route to r1.topsoffice.ca [206.116.50.83]
over a maximum of 30 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     3 ms     3 ms     3 ms  10.31.14.1
  3     *        8 ms     4 ms  96.1.214.126
  4     *        *        *     Request timed out.
  5     4 ms     3 ms     3 ms  96.1.214.119
  6     4 ms     3 ms     3 ms  s206-116-50-83.bc.hsia.telus.net [206.116.50.83]

Trace complete.
`

	result, err := ParseOutput(output, "r1.topsoffice.ca")
	if err != nil {
		t.Fatalf("ParseOutput failed: %v", err)
	}

	// Check target info
	if result.TargetHostname != "r1.topsoffice.ca" {
		t.Errorf("Expected hostname r1.topsoffice.ca, got %s", result.TargetHostname)
	}
	if result.TargetIP != "206.116.50.83" {
		t.Errorf("Expected IP 206.116.50.83, got %s", result.TargetIP)
	}

	// Check hop count
	if len(result.Hops) != 6 {
		t.Fatalf("Expected 6 hops, got %d", len(result.Hops))
	}

	// Check hop 1 - <1 ms values
	hop1 := result.Hops[0]
	if hop1.TTL != 1 {
		t.Errorf("Hop 1 TTL: expected 1, got %d", hop1.TTL)
	}
	if hop1.IP != "192.168.1.1" {
		t.Errorf("Hop 1 IP: expected 192.168.1.1, got %s", hop1.IP)
	}
	if hop1.Recv != 3 {
		t.Errorf("Hop 1 Recv: expected 3, got %d", hop1.Recv)
	}
	if hop1.LossPct != 0 {
		t.Errorf("Hop 1 LossPct: expected 0, got %.2f", hop1.LossPct)
	}
	// <1 ms should be parsed as 0.5ms
	for i, lat := range hop1.Latencies {
		if lat != 0.5 {
			t.Errorf("Hop 1 Latency[%d]: expected 0.5, got %.2f", i, lat)
		}
	}

	// Check hop 3 - partial timeout
	hop3 := result.Hops[2]
	if hop3.TTL != 3 {
		t.Errorf("Hop 3 TTL: expected 3, got %d", hop3.TTL)
	}
	if hop3.Recv != 2 {
		t.Errorf("Hop 3 Recv: expected 2, got %d", hop3.Recv)
	}
	if hop3.Latencies[0] != -1 {
		t.Errorf("Hop 3 Latency[0]: expected -1 (timeout), got %.2f", hop3.Latencies[0])
	}
	// Loss should be ~33.33%
	if hop3.LossPct < 33 || hop3.LossPct > 34 {
		t.Errorf("Hop 3 LossPct: expected ~33.33, got %.2f", hop3.LossPct)
	}

	// Check hop 4 - complete timeout
	hop4 := result.Hops[3]
	if hop4.TTL != 4 {
		t.Errorf("Hop 4 TTL: expected 4, got %d", hop4.TTL)
	}
	if hop4.Recv != 0 {
		t.Errorf("Hop 4 Recv: expected 0, got %d", hop4.Recv)
	}
	if hop4.LossPct != 100 {
		t.Errorf("Hop 4 LossPct: expected 100, got %.2f", hop4.LossPct)
	}

	// Check hop 6 - hostname with IP
	hop6 := result.Hops[5]
	if hop6.TTL != 6 {
		t.Errorf("Hop 6 TTL: expected 6, got %d", hop6.TTL)
	}
	if hop6.IP != "206.116.50.83" {
		t.Errorf("Hop 6 IP: expected 206.116.50.83, got %s", hop6.IP)
	}
	if hop6.Hostname != "s206-116-50-83.bc.hsia.telus.net" {
		t.Errorf("Hop 6 Hostname: expected s206-116-50-83.bc.hsia.telus.net, got %s", hop6.Hostname)
	}
}

func TestParseOutput_IPOnly(t *testing.T) {
	output := `Tracing route to 8.8.8.8
over a maximum of 30 hops:

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     5 ms     5 ms     5 ms  8.8.8.8

Trace complete.
`

	result, err := ParseOutput(output, "8.8.8.8")
	if err != nil {
		t.Fatalf("ParseOutput failed: %v", err)
	}

	// When target is IP, both hostname and IP should be the same
	if result.TargetIP != "8.8.8.8" {
		t.Errorf("Expected IP 8.8.8.8, got %s", result.TargetIP)
	}

	if len(result.Hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(result.Hops))
	}
}

func TestParseHopLine_RegularLatencies(t *testing.T) {
	hop := parseHopLine(2, "    3 ms     3 ms     3 ms  10.31.14.1")

	if hop == nil {
		t.Fatal("parseHopLine returned nil")
	}

	if hop.TTL != 2 {
		t.Errorf("Expected TTL 2, got %d", hop.TTL)
	}

	if hop.Recv != 3 {
		t.Errorf("Expected Recv 3, got %d", hop.Recv)
	}

	if hop.Avg != 3 {
		t.Errorf("Expected Avg 3, got %.2f", hop.Avg)
	}

	if hop.IP != "10.31.14.1" {
		t.Errorf("Expected IP 10.31.14.1, got %s", hop.IP)
	}
}

func TestParseHopLine_MixedLatencies(t *testing.T) {
	hop := parseHopLine(3, "    *        8 ms     4 ms  96.1.214.126")

	if hop == nil {
		t.Fatal("parseHopLine returned nil")
	}

	if hop.Recv != 2 {
		t.Errorf("Expected Recv 2, got %d", hop.Recv)
	}

	if hop.Best != 4 {
		t.Errorf("Expected Best 4, got %.2f", hop.Best)
	}

	if hop.Worst != 8 {
		t.Errorf("Expected Worst 8, got %.2f", hop.Worst)
	}
}

func TestParseHopLine_SubMillisecond(t *testing.T) {
	hop := parseHopLine(1, "   <1 ms    <1 ms    <1 ms  192.168.1.1")

	if hop == nil {
		t.Fatal("parseHopLine returned nil")
	}

	// <1 ms should be approximated as 0.5ms
	for i, lat := range hop.Latencies {
		if lat != 0.5 {
			t.Errorf("Expected Latency[%d] 0.5, got %.2f", i, lat)
		}
	}

	if hop.Avg != 0.5 {
		t.Errorf("Expected Avg 0.5, got %.2f", hop.Avg)
	}
}

func TestParseHopLine_HostnameWithIP(t *testing.T) {
	hop := parseHopLine(6, "    4 ms     3 ms     3 ms  s206-116-50-83.bc.hsia.telus.net [206.116.50.83]")

	if hop == nil {
		t.Fatal("parseHopLine returned nil")
	}

	if hop.IP != "206.116.50.83" {
		t.Errorf("Expected IP 206.116.50.83, got %s", hop.IP)
	}

	if hop.Hostname != "s206-116-50-83.bc.hsia.telus.net" {
		t.Errorf("Expected Hostname s206-116-50-83.bc.hsia.telus.net, got %s", hop.Hostname)
	}
}

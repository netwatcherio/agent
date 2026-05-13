package probes

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// DNSConfig is extracted from probe Metadata JSONB
type DNSConfig struct {
	DNSServer  string `json:"dns_server"`  // e.g. "8.8.8.8:53"
	RecordType string `json:"record_type"` // A, AAAA, MX, NS, SOA, TXT, CNAME, SRV, PTR
	Protocol   string `json:"protocol"`    // "udp" or "tcp" (default: udp)
}

// DNSAnswer represents a single answer record
type DNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// DNSPayload is what the agent posts to the controller
type DNSPayload struct {
	DNSServer    string      `json:"dns_server"`
	RecordType   string      `json:"record_type"`
	QueryTimeMs  float64     `json:"query_time_ms"`
	ResponseCode string      `json:"response_code"`
	Answers      []DNSAnswer `json:"answers"`
	RawResponse  string      `json:"raw_response"`
	Error        string      `json:"error,omitempty"`
	Protocol     string      `json:"protocol"`
	Target       string      `json:"target"`
}

// parseDNSConfig extracts DNS configuration from probe metadata.
// Falls back to sensible defaults if fields are missing.
func parseDNSConfig(metadata json.RawMessage) DNSConfig {
	cfg := DNSConfig{
		DNSServer:  "8.8.8.8:53",
		RecordType: "A",
		Protocol:   "udp",
	}

	if len(metadata) == 0 || string(metadata) == "{}" || string(metadata) == "null" {
		return cfg
	}

	if err := json.Unmarshal(metadata, &cfg); err != nil {
		log.Warnf("[dns] failed to parse metadata: %v, using defaults", err)
		return cfg
	}

	// Normalize
	cfg.RecordType = strings.ToUpper(cfg.RecordType)
	cfg.Protocol = strings.ToLower(cfg.Protocol)
	if cfg.Protocol == "" {
		cfg.Protocol = "udp"
	}

	// Ensure server has port
	if cfg.DNSServer != "" && !strings.Contains(cfg.DNSServer, ":") {
		cfg.DNSServer = cfg.DNSServer + ":53"
	}

	return cfg
}

// recordTypeToUint16 maps string record types to dns package constants
func recordTypeToUint16(rt string) (uint16, error) {
	switch strings.ToUpper(rt) {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "MX":
		return dns.TypeMX, nil
	case "NS":
		return dns.TypeNS, nil
	case "SOA":
		return dns.TypeSOA, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "CNAME":
		return dns.TypeCNAME, nil
	case "SRV":
		return dns.TypeSRV, nil
	case "PTR":
		return dns.TypePTR, nil
	default:
		return 0, fmt.Errorf("unsupported record type: %s", rt)
	}
}

// extractAnswers converts dns.RR answer records into our DNSAnswer structs
func extractAnswers(rrs []dns.RR) []DNSAnswer {
	answers := make([]DNSAnswer, 0, len(rrs))
	for _, rr := range rrs {
		answer := DNSAnswer{
			Name: rr.Header().Name,
			Type: dns.TypeToString[rr.Header().Rrtype],
			TTL:  rr.Header().Ttl,
		}

		// Extract the value based on record type
		switch v := rr.(type) {
		case *dns.A:
			answer.Value = v.A.String()
		case *dns.AAAA:
			answer.Value = v.AAAA.String()
		case *dns.MX:
			answer.Value = fmt.Sprintf("%d %s", v.Preference, v.Mx)
		case *dns.NS:
			answer.Value = v.Ns
		case *dns.SOA:
			answer.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
				v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
		case *dns.TXT:
			answer.Value = strings.Join(v.Txt, " ")
		case *dns.CNAME:
			answer.Value = v.Target
		case *dns.SRV:
			answer.Value = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
		case *dns.PTR:
			answer.Value = v.Ptr
		default:
			// Fallback: use the string representation minus the header
			full := rr.String()
			// Try to strip the header portion
			answer.Value = full
		}

		answers = append(answers, answer)
	}
	return answers
}

// DNSQuery performs a single DNS lookup against the configured server.
func DNSQuery(probe *Probe, dataChan chan ProbeData) error {
	if len(probe.Targets) == 0 || probe.Targets[0].Target == "" {
		return fmt.Errorf("dns: no target hostname provided")
	}

	target := probe.Targets[0].Target
	cfg := parseDNSConfig(probe.Metadata)

	log.Infof("[dns] Querying %s %s @%s (proto=%s)", cfg.RecordType, target, cfg.DNSServer, cfg.Protocol)

	// Resolve interface binding early (before any emitDNSResult calls)
	var sourceIP, sourceIface string
	if probe.BindInterface != "" {
		bindIP, err := ResolveBindInterface(probe.BindInterface)
		if err != nil {
			return fmt.Errorf("dns probe=%d: bind interface %q: %w", probe.ID, probe.BindInterface, err)
		}
		sourceIP = bindIP
		sourceIface = probe.BindInterface
	}

	// Build the DNS message
	qtype, err := recordTypeToUint16(cfg.RecordType)
	if err != nil {
		payload := DNSPayload{
			DNSServer:    cfg.DNSServer,
			RecordType:   cfg.RecordType,
			Protocol:     cfg.Protocol,
			Target:       target,
			ResponseCode: "ERROR",
			Error:        err.Error(),
			Answers:      []DNSAnswer{},
		}
		emitDNSResult(probe, dataChan, target, payload, sourceIP, sourceIface)
		return err
	}

	// Ensure target is FQDN
	fqdn := dns.Fqdn(target)

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true

	// Create client with timeout
	client := &dns.Client{
		Net:     cfg.Protocol,
		Timeout: time.Duration(probe.TimeoutSec) * time.Second,
	}
	if client.Timeout <= 0 {
		client.Timeout = 10 * time.Second
	}

	// Interface binding: if BindInterface is configured, set a custom Dialer
	// with LocalAddr so DNS queries originate from the specified interface.
	if sourceIP != "" {
		client.Dialer = &net.Dialer{
			Timeout:   client.Timeout,
			LocalAddr: &net.UDPAddr{IP: net.ParseIP(sourceIP)},
		}
		log.Infof("[dns] probe=%d binding to interface %q (source: %s)", probe.ID, probe.BindInterface, sourceIP)
	}

	// Execute the query
	start := time.Now()
	resp, rtt, err := client.Exchange(msg, cfg.DNSServer)
	queryMs := float64(rtt.Microseconds()) / 1000.0

	if err != nil {
		payload := DNSPayload{
			DNSServer:    cfg.DNSServer,
			RecordType:   cfg.RecordType,
			QueryTimeMs:  queryMs,
			Protocol:     cfg.Protocol,
			Target:       target,
			ResponseCode: "ERROR",
			Error:        err.Error(),
			Answers:      []DNSAnswer{},
			RawResponse:  fmt.Sprintf("; query failed: %v\n; server: %s\n; elapsed: %v", err, cfg.DNSServer, rtt),
		}
		emitDNSResult(probe, dataChan, target, payload, sourceIP, sourceIface)
		return fmt.Errorf("dns exchange failed: %w", err)
	}

	// If rtt was zero (shouldn't happen on success), fall back to wall clock
	if queryMs <= 0 {
		queryMs = float64(time.Since(start).Microseconds()) / 1000.0
	}

	// Build the payload
	payload := DNSPayload{
		DNSServer:    cfg.DNSServer,
		RecordType:   cfg.RecordType,
		QueryTimeMs:  queryMs,
		ResponseCode: dns.RcodeToString[resp.Rcode],
		Answers:      extractAnswers(resp.Answer),
		Protocol:     cfg.Protocol,
		Target:       target,
		RawResponse:  resp.String(),
	}

	log.Infof("[dns] %s %s @%s -> %s (%d answers, %.2fms)",
		cfg.RecordType, target, cfg.DNSServer, payload.ResponseCode, len(payload.Answers), queryMs)

	emitDNSResult(probe, dataChan, target, payload, sourceIP, sourceIface)
	return nil
}

func emitDNSResult(probe *Probe, dataChan chan ProbeData, target string, payload DNSPayload, sourceIP, sourceIface string) {
	raw, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("[dns] marshal error: %v", err)
		return
	}

	dataChan <- ProbeData{
		ProbeID:         probe.ID,
		Type:            ProbeType_DNS,
		Payload:         raw,
		Target:          target,
		CreatedAt:       nettime.AdjustedTime(),
		SourceIP:        sourceIP,
		SourceInterface: sourceIface,
	}
}

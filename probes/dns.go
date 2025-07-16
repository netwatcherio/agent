package probes

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"os"
	"strings"
	"time"
)

type DNSResult struct {
	StartTimestamp time.Time         `json:"start_timestamp" bson:"start_timestamp"`
	StopTimestamp  time.Time         `json:"stop_timestamp" bson:"stop_timestamp"`
	Domain         string            `json:"domain" bson:"domain"`
	QueryType      string            `json:"query_type" bson:"query_type"`
	Servers        []DNSServerResult `json:"servers" bson:"servers"`
}

type DNSServerResult struct {
	Server         string        `json:"server" bson:"server"`
	ResponseTime   time.Duration `json:"response_time" bson:"response_time"`
	Success        bool          `json:"success" bson:"success"`
	Error          string        `json:"error,omitempty" bson:"error,omitempty"`
	ResponseCode   string        `json:"response_code" bson:"response_code"`
	Authoritative  bool          `json:"authoritative" bson:"authoritative"`
	RecursionAvail bool          `json:"recursion_available" bson:"recursion_available"`
	Truncated      bool          `json:"truncated" bson:"truncated"`
	Records        []DNSRecord   `json:"records,omitempty" bson:"records,omitempty"`
	Protocol       string        `json:"protocol" bson:"protocol"`
}

type DNSRecord struct {
	Type  string `json:"type" bson:"type"`
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
	TTL   uint32 `json:"ttl" bson:"ttl"`
	Class string `json:"class" bson:"class"`
}

func DNSProbe(ac *Probe, dnsChan chan ProbeData) error {
	startTime := time.Now()

	// Parse the query configuration
	// Expected format: "domain.com:A" or just "domain.com" (defaults to A record)
	parts := strings.Split(ac.Config.Target[0].Target, ":")
	domain := parts[0]
	queryType := dns.TypeA
	queryTypeStr := "A"

	if len(parts) > 1 {
		queryTypeStr = strings.ToUpper(parts[1])
		switch queryTypeStr {
		case "A":
			queryType = dns.TypeA
		case "AAAA":
			queryType = dns.TypeAAAA
		case "MX":
			queryType = dns.TypeMX
		case "TXT":
			queryType = dns.TypeTXT
		case "NS":
			queryType = dns.TypeNS
		case "CNAME":
			queryType = dns.TypeCNAME
		case "SOA":
			queryType = dns.TypeSOA
		case "PTR":
			queryType = dns.TypePTR
		case "SRV":
			queryType = dns.TypeSRV
		default:
			queryType = dns.TypeA
			queryTypeStr = "A"
		}
	}

	result := DNSResult{
		StartTimestamp: startTime,
		Domain:         domain,
		QueryType:      queryTypeStr,
		Servers:        []DNSServerResult{},
	}

	// Get DNS servers to test
	// If no additional targets specified, use some common public DNS servers
	dnsServers := []string{}
	if len(ac.Config.Target) > 1 {
		// Use user-provided DNS servers (skip the first target which is the domain)
		for i := 1; i < len(ac.Config.Target); i++ {
			server := ac.Config.Target[i].Target
			// Ensure port is specified
			if !strings.Contains(server, ":") {
				server += ":53"
			}
			dnsServers = append(dnsServers, server)
		}
	} else {
		// Default to common public DNS servers
		dnsServers = []string{
			"8.8.8.8:53",        // Google
			"8.8.4.4:53",        // Google Secondary
			"1.1.1.1:53",        // Cloudflare
			"1.0.0.1:53",        // Cloudflare Secondary
			"208.67.222.222:53", // OpenDNS
			"9.9.9.9:53",        // Quad9
		}
	}

	// Test each DNS server
	for _, server := range dnsServers {
		serverResult := testDNSServer(domain, queryType, queryTypeStr, server, ac.Config.Duration)
		result.Servers = append(result.Servers, serverResult)
	}

	result.StopTimestamp = time.Now()

	// Log the result
	marshal, _ := json.Marshal(result)
	log.Info(string(marshal))

	// Send result
	reportingAgent, err := primitive.ObjectIDFromHex(os.Getenv("ID"))
	if err != nil {
		log.Printf("DNSProbe: Failed to get reporting agent ID: %v", err)
		return err
	}

	cD := ProbeData{
		ProbeID: ac.ID,
		Data:    result,
		Target: ProbeTarget{
			Target: string(ProbeType_DNS) + "%%%" + ac.Config.Target[0].Target,
			Agent:  ac.Config.Target[0].Agent,
			Group:  reportingAgent,
		},
	}

	dnsChan <- cD

	return nil
}

func testDNSServer(domain string, queryType uint16, queryTypeStr string, server string, timeout int) DNSServerResult {
	result := DNSServerResult{
		Server:   server,
		Protocol: "UDP",
		Records:  []DNSRecord{},
	}

	//startTime := time.Now()

	// Create DNS message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), queryType)
	m.SetEdns0(4096, true)

	// Create DNS client
	c := new(dns.Client)
	c.Timeout = time.Duration(timeout) * time.Second

	// Try UDP first
	r, rtt, err := c.Exchange(m, server)

	// If UDP fails or response is truncated, try TCP
	if err != nil || (r != nil && r.Truncated) {
		result.Protocol = "TCP"
		c.Net = "tcp"
		r, rtt, err = c.Exchange(m, server)
	}

	result.ResponseTime = rtt

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.ResponseCode = dns.RcodeToString[r.Rcode]
	result.Authoritative = r.Authoritative
	result.RecursionAvail = r.RecursionAvailable
	result.Truncated = r.Truncated

	// Parse answers
	for _, ans := range r.Answer {
		record := DNSRecord{
			Name:  ans.Header().Name,
			TTL:   ans.Header().Ttl,
			Class: dns.ClassToString[ans.Header().Class],
		}

		switch v := ans.(type) {
		case *dns.A:
			record.Type = "A"
			record.Value = v.A.String()
		case *dns.AAAA:
			record.Type = "AAAA"
			record.Value = v.AAAA.String()
		case *dns.MX:
			record.Type = "MX"
			record.Value = fmt.Sprintf("%d %s", v.Preference, v.Mx)
		case *dns.TXT:
			record.Type = "TXT"
			record.Value = strings.Join(v.Txt, " ")
		case *dns.CNAME:
			record.Type = "CNAME"
			record.Value = v.Target
		case *dns.NS:
			record.Type = "NS"
			record.Value = v.Ns
		case *dns.SOA:
			record.Type = "SOA"
			record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
				v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
		case *dns.PTR:
			record.Type = "PTR"
			record.Value = v.Ptr
		case *dns.SRV:
			record.Type = "SRV"
			record.Value = fmt.Sprintf("%d %d %d %s",
				v.Priority, v.Weight, v.Port, v.Target)
		default:
			record.Type = dns.TypeToString[ans.Header().Rrtype]
			record.Value = ans.String()
		}

		result.Records = append(result.Records, record)
	}

	return result
}

package probes

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"
)

type WebResult struct {
	// Timing information
	StartTimestamp       time.Time     `json:"start_timestamp" bson:"start_timestamp"`
	StopTimestamp        time.Time     `json:"stop_timestamp" bson:"stop_timestamp"`
	DNSLookupDuration    time.Duration `json:"dns_lookup_duration" bson:"dns_lookup_duration"`
	TCPConnectDuration   time.Duration `json:"tcp_connect_duration" bson:"tcp_connect_duration"`
	TLSHandshakeDuration time.Duration `json:"tls_handshake_duration" bson:"tls_handshake_duration"`
	FirstByteDuration    time.Duration `json:"first_byte_duration" bson:"first_byte_duration"`
	TotalDuration        time.Duration `json:"total_duration" bson:"total_duration"`

	// Response information
	URL         string            `json:"url" bson:"url"`
	StatusCode  int               `json:"status_code" bson:"status_code"`
	StatusText  string            `json:"status_text" bson:"status_text"`
	Headers     map[string]string `json:"headers" bson:"headers"`
	BodySize    int64             `json:"body_size" bson:"body_size"`
	ContentType string            `json:"content_type" bson:"content_type"`

	// Connection information
	RemoteAddr     string `json:"remote_addr" bson:"remote_addr"`
	Protocol       string `json:"protocol" bson:"protocol"`
	TLSVersion     string `json:"tls_version,omitempty" bson:"tls_version,omitempty"`
	TLSCipherSuite string `json:"tls_cipher_suite,omitempty" bson:"tls_cipher_suite,omitempty"`

	// Certificate information (for HTTPS)
	CertificateInfo *CertInfo `json:"certificate_info,omitempty" bson:"certificate_info,omitempty"`

	// Error information
	Error string `json:"error,omitempty" bson:"error,omitempty"`
}

type CertInfo struct {
	Subject         string    `json:"subject" bson:"subject"`
	Issuer          string    `json:"issuer" bson:"issuer"`
	NotBefore       time.Time `json:"not_before" bson:"not_before"`
	NotAfter        time.Time `json:"not_after" bson:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry" bson:"days_until_expiry"`
	SANs            []string  `json:"sans" bson:"sans"`
}

func WebProbe(ac *Probe, webChan chan ProbeData) error {
	startTime := time.Now()
	result := WebResult{
		StartTimestamp: startTime,
		URL:            ac.Config.Target[0].Target,
	}

	// Create variables to track timing
	var dnsStart, dnsEnd, connectStart, connectEnd, tlsStart, tlsEnd time.Time
	var firstByteTime time.Time

	// Create HTTP client with custom transport
	client := &http.Client{
		Timeout: time.Duration(ac.Config.Duration) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			DisableKeepAlives:   true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Create request
	req, err := http.NewRequest("GET", ac.Config.Target[0].Target, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		sendWebResult(ac, webChan, result)
		return err
	}

	// Add custom headers if needed
	req.Header.Set("User-Agent", "ProbeAgent/1.0")

	// Create HTTP trace
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
			result.DNSLookupDuration = dnsEnd.Sub(dnsStart)
		},
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connectEnd = time.Now()
			result.TCPConnectDuration = connectEnd.Sub(connectStart)
			result.RemoteAddr = addr
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsEnd = time.Now()
			result.TLSHandshakeDuration = tlsEnd.Sub(tlsStart)

			// Extract TLS information
			result.TLSVersion = getTLSVersion(state.Version)
			result.TLSCipherSuite = tls.CipherSuiteName(state.CipherSuite)

			// Extract certificate information
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				result.CertificateInfo = &CertInfo{
					Subject:         cert.Subject.String(),
					Issuer:          cert.Issuer.String(),
					NotBefore:       cert.NotBefore,
					NotAfter:        cert.NotAfter,
					DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
					SANs:            cert.DNSNames,
				}
			}
		},
		GotFirstResponseByte: func() {
			firstByteTime = time.Now()
			result.FirstByteDuration = firstByteTime.Sub(startTime)
		},
	}

	// Add trace to request context
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.StopTimestamp = time.Now()
		result.TotalDuration = result.StopTimestamp.Sub(startTime)
		sendWebResult(ac, webChan, result)
		return err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read body: %v", err)
	}

	// Populate response information
	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.BodySize = int64(len(body))
	result.Protocol = resp.Proto
	result.ContentType = resp.Header.Get("Content-Type")

	// Copy important headers
	result.Headers = make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			result.Headers[key] = values[0]
		}
	}

	// Final timing
	result.StopTimestamp = time.Now()
	result.TotalDuration = result.StopTimestamp.Sub(startTime)

	// Log the result
	marshal, _ := json.Marshal(result)
	log.Info(string(marshal))

	// Send result
	sendWebResult(ac, webChan, result)

	return nil
}

func sendWebResult(ac *Probe, webChan chan ProbeData, result WebResult) {
	reportingAgent, err := primitive.ObjectIDFromHex(os.Getenv("ID"))
	if err != nil {
		log.Printf("WebProbe: Failed to get reporting agent ID: %v", err)
		return
	}

	cD := ProbeData{
		ProbeID: ac.ID,
		Data:    result,
		Target: ProbeTarget{
			Target: string(ProbeType_WEB) + "%%%" + ac.Config.Target[0].Target,
			Agent:  ac.Config.Target[0].Agent,
			Group:  reportingAgent,
		},
	}

	webChan <- cD
}

func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

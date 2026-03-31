package probes

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type CertInfo struct {
	Subject         string    `json:"subject" bson:"subject"`
	Issuer          string    `json:"issuer" bson:"issuer"`
	NotBefore       time.Time `json:"not_before" bson:"not_before"`
	NotAfter        time.Time `json:"not_after" bson:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry" bson:"days_until_expiry"`
	SANs            []string  `json:"sans" bson:"sans"`
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

type HTTPConfig struct {
	Method           string            `json:"method"`
	URL              string            `json:"url"`
	ExpectedStatus   []int             `json:"expected_status"`
	ExpectedContent  string            `json:"expected_content"`
	ContentMatchType string            `json:"content_match_type"`
	Headers          map[string]string `json:"headers"`
	TimeoutSec       int               `json:"timeout_sec"`
	FollowRedirects  bool              `json:"follow_redirects"`
	InsecureTLS      bool              `json:"insecure_tls"`
}

type HTTPPayload struct {
	StartTimestamp    time.Time         `json:"start_timestamp"`
	StopTimestamp     time.Time         `json:"stop_timestamp"`
	DNSLookupMs       float64           `json:"dns_lookup_ms"`
	TCPConnectMs      float64           `json:"tcp_connect_ms"`
	TLSHandshakeMs    float64           `json:"tls_handshake_ms"`
	FirstByteMs       float64           `json:"first_byte_ms"`
	TotalMs           float64           `json:"total_ms"`
	URL               string            `json:"url"`
	StatusCode        int               `json:"status_code"`
	StatusText        string            `json:"status_text"`
	Headers           map[string]string `json:"headers"`
	BodySize          int64             `json:"body_size"`
	ContentType       string            `json:"content_type"`
	RemoteAddr        string            `json:"remote_addr"`
	Protocol          string            `json:"protocol"`
	TLSVersion        string            `json:"tls_version,omitempty"`
	TLSCipherSuite    string            `json:"tls_cipher_suite,omitempty"`
	CertificateInfo   *CertInfo         `json:"certificate_info,omitempty"`
	ContentMatch      bool              `json:"content_match"`
	ContentMatchFound string            `json:"content_match_found,omitempty"`
	Error             string            `json:"error,omitempty"`
}

func parseHTTPConfig(metadata json.RawMessage) HTTPConfig {
	cfg := HTTPConfig{
		Method:           "GET",
		ExpectedStatus:   []int{200},
		ContentMatchType: "contains",
		TimeoutSec:       10,
		FollowRedirects:  true,
		InsecureTLS:      false,
	}

	if len(metadata) == 0 || string(metadata) == "{}" || string(metadata) == "null" {
		return cfg
	}

	if err := json.Unmarshal(metadata, &cfg); err != nil {
		log.Warnf("[http] failed to parse metadata: %v, using defaults", err)
		return cfg
	}

	cfg.Method = strings.ToUpper(cfg.Method)
	if cfg.Method == "" {
		cfg.Method = "GET"
	}
	if cfg.ContentMatchType == "" {
		cfg.ContentMatchType = "contains"
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 10
	}

	return cfg
}

func HTTPProbe(probe *Probe, dataChan chan ProbeData) error {
	if len(probe.Targets) == 0 || probe.Targets[0].Target == "" {
		return fmt.Errorf("http: no target URL provided")
	}

	cfg := parseHTTPConfig(probe.Metadata)
	targetURL := cfg.URL
	if targetURL == "" {
		targetURL = probe.Targets[0].Target
	}

	startTime := time.Now()

	var dnsStart, dnsEnd, connectStart, connectEnd, tlsStart, tlsEnd, firstByteTime time.Time
	var tlsHandshakeDone bool

	client := &http.Client{
		Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			DisableKeepAlives:   true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureTLS,
			},
		},
	}

	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	method := cfg.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return fmt.Errorf("http: failed to create request: %w", err)
	}

	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "NetWatcher-Probe/1.0")
	}

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connectStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connectEnd = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsEnd = time.Now()
			tlsHandshakeDone = true
		},
		GotFirstResponseByte: func() {
			firstByteTime = time.Now()
		},
	}

	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)

	result := HTTPPayload{
		StartTimestamp: startTime,
		URL:            targetURL,
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.StopTimestamp = time.Now()
		result.TotalMs = float64(result.StopTimestamp.Sub(startTime).Microseconds()) / 1000.0
		emitHTTPResult(probe, dataChan, result)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		result.Error = fmt.Sprintf("failed to read body: %v", err)
	}

	bodySize := int64(len(body))

	dnsMs := float64(dnsEnd.Sub(dnsStart).Microseconds()) / 1000.0
	tcpMs := float64(connectEnd.Sub(connectStart).Microseconds()) / 1000.0
	var tlsMs float64
	if tlsHandshakeDone {
		tlsMs = float64(tlsEnd.Sub(tlsStart).Microseconds()) / 1000.0
	}
	var firstByteMs float64
	if !firstByteTime.IsZero() {
		firstByteMs = float64(firstByteTime.Sub(startTime).Microseconds()) / 1000.0
	} else {
		firstByteMs = float64(time.Since(startTime).Microseconds()) / 1000.0
	}
	totalMs := float64(time.Since(startTime).Microseconds()) / 1000.0

	result.DNSLookupMs = dnsMs
	result.TCPConnectMs = tcpMs
	result.TLSHandshakeMs = tlsMs
	result.FirstByteMs = firstByteMs
	result.TotalMs = totalMs
	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.BodySize = bodySize
	result.Protocol = resp.Proto
	result.ContentType = resp.Header.Get("Content-Type")
	result.RemoteAddr = resp.Request.RemoteAddr

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	result.Headers = headers

	if resp.TLS != nil {
		result.TLSVersion = getTLSVersion(resp.TLS.Version)
		result.TLSCipherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.CertificateInfo = &CertInfo{
				Subject:         cert.Subject.String(),
				Issuer:          cert.Issuer.String(),
				NotBefore:       cert.NotBefore,
				NotAfter:        cert.NotAfter,
				DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
				SANs:            cert.DNSNames,
			}
		}
	}

	if cfg.ExpectedContent != "" {
		result.ContentMatch = contentMatches(string(body), cfg.ExpectedContent, cfg.ContentMatchType)
		if result.ContentMatch {
			result.ContentMatchFound = cfg.ExpectedContent
		}
	}

	result.StopTimestamp = time.Now()

	log.Infof("[http] %s %s -> %d (%.2fms)", method, targetURL, result.StatusCode, result.TotalMs)

	emitHTTPResult(probe, dataChan, result)
	return nil
}

func contentMatches(body, expected, matchType string) bool {
	switch matchType {
	case "contains":
		return strings.Contains(body, expected)
	case "regex":
		matched, err := regexp.MatchString(expected, body)
		if err != nil {
			log.Warnf("[http] invalid regex: %v", err)
			return false
		}
		return matched
	default:
		return strings.Contains(body, expected)
	}
}

func emitHTTPResult(probe *Probe, dataChan chan ProbeData, result HTTPPayload) {
	raw, err := json.Marshal(result)
	if err != nil {
		log.Errorf("[http] marshal error: %v", err)
		return
	}

	target := result.URL
	if target == "" && len(probe.Targets) > 0 {
		target = probe.Targets[0].Target
	}

	dataChan <- ProbeData{
		ProbeID:         probe.ID,
		Type:            ProbeType_HTTP,
		Payload:         raw,
		Target:          target,
		CreatedAt:       time.Now(),
		SourceInterface: probe.BindInterface,
	}
}

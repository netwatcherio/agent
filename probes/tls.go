package probes

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"crypto/x509/pkix"
	"github.com/netwatcherio/netwatcher-agent/nettime"
	log "github.com/sirupsen/logrus"
)

type TLSConfig struct {
	Target             string `json:"target"`
	TimeoutSec         int    `json:"timeout_sec"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type TLSPayload struct {
	StartTimestamp   time.Time   `json:"start_timestamp"`
	StopTimestamp    time.Time   `json:"stop_timestamp"`
	RemoteAddr       string      `json:"remote_addr"`
	Protocol         string      `json:"protocol"`
	TLSVersion       string      `json:"tls_version"`
	TLSCipherSuite   string      `json:"tls_cipher_suite"`
	Certificate      *CertInfo   `json:"certificate"`
	CertificateChain []ChainCert `json:"certificate_chain"`
	IsExpired        bool        `json:"is_expired"`
	IsExpiringSoon   bool        `json:"is_expiring_soon"`
	DaysUntilExpiry  int         `json:"days_until_expiry"`
	IssuerOrg        string      `json:"issuer_org"`
	CertType         string      `json:"cert_type"`
	CertFingerprint  string      `json:"cert_fingerprint"`
	Error            string      `json:"error,omitempty"`
}

type ChainCert struct {
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	IssuerOrg       string    `json:"issuer_org"`
	Fingerprint     string    `json:"fingerprint"`
}

func parseTLSConfig(metadata json.RawMessage) TLSConfig {
	cfg := TLSConfig{
		TimeoutSec: 10,
	}

	if len(metadata) == 0 || string(metadata) == "{}" || string(metadata) == "null" {
		return cfg
	}

	if err := json.Unmarshal(metadata, &cfg); err != nil {
		log.Warnf("[tls] failed to parse metadata: %v, using defaults", err)
		return cfg
	}

	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 10
	}

	return cfg
}

func TLSProbe(probe *Probe, dataChan chan ProbeData) error {
	if len(probe.Targets) == 0 || probe.Targets[0].Target == "" {
		return fmt.Errorf("tls: no target provided")
	}

	cfg := parseTLSConfig(probe.Metadata)
	target := cfg.Target
	if target == "" {
		target = probe.Targets[0].Target
	}

	// Strip scheme if present (e.g., https:// from https://example.com)
	if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
	} else if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	}

	// Add default TLS port 443 if no port specified
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	startTime := time.Now().Add(nettime.GetTimeOffset())

	result := TLSPayload{
		StartTimestamp: startTime,
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		result.Error = fmt.Sprintf("invalid target: %v", err)
		result.StopTimestamp = time.Now().Add(nettime.GetTimeOffset())
		emitTLSResult(probe, dataChan, result)
		return err
	}

	port := 443
	fmt.Sscanf(portStr, "%d", &port)

	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{
		Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})

	if err != nil {
		result.Error = fmt.Sprintf("tls dial failed: %v", err)
		result.StopTimestamp = time.Now().Add(nettime.GetTimeOffset())
		emitTLSResult(probe, dataChan, result)
		return err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	result.RemoteAddr = conn.RemoteAddr().String()
	result.Protocol = getTLSVersion(state.Version)
	result.TLSVersion = getTLSVersion(state.Version)
	result.TLSCipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		result.Certificate = &CertInfo{
			Subject:         leaf.Subject.String(),
			Issuer:          leaf.Issuer.String(),
			NotBefore:       leaf.NotBefore,
			NotAfter:        leaf.NotAfter,
			DaysUntilExpiry: int(time.Until(leaf.NotAfter).Hours() / 24),
			SANs:            leaf.DNSNames,
		}
		result.DaysUntilExpiry = result.Certificate.DaysUntilExpiry
		result.IsExpired = time.Now().Add(nettime.GetTimeOffset()).After(leaf.NotAfter)
		result.IsExpiringSoon = result.DaysUntilExpiry <= 30 && !result.IsExpired

		result.IssuerOrg = getOrgFromSubject(leaf.Issuer)
		result.CertFingerprint = fingerprint(leaf)

		result.CertType = "leaf"
		if len(state.PeerCertificates) > 1 {
			result.CertType = "leaf+intermediate"
		}

		for i, cert := range state.PeerCertificates {
			chainCert := ChainCert{
				Subject:         cert.Subject.String(),
				Issuer:          cert.Issuer.String(),
				NotBefore:       cert.NotBefore,
				NotAfter:        cert.NotAfter,
				DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
				IssuerOrg:       getOrgFromSubject(cert.Issuer),
				Fingerprint:     fingerprint(cert),
			}
			result.CertificateChain = append(result.CertificateChain, chainCert)

			if i == 0 {
				continue
			}
		}

		if len(state.PeerCertificates) == 1 && isSelfSigned(leaf) {
			result.CertType = "self-signed"
		}
	}

	result.StopTimestamp = time.Now().Add(nettime.GetTimeOffset())

	log.Infof("[tls] %s -> %s, version=%s, cipher=%s, expires_in=%d days",
		target, result.TLSVersion, result.TLSVersion, result.TLSCipherSuite, result.DaysUntilExpiry)

	emitTLSResult(probe, dataChan, result)
	return nil
}

func getOrgFromSubject(issuer pkix.Name) string {
	for _, org := range issuer.Organization {
		return org
	}
	return ""
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func emitTLSResult(probe *Probe, dataChan chan ProbeData, result TLSPayload) {
	raw, err := json.Marshal(result)
	if err != nil {
		log.Errorf("[tls] marshal error: %v", err)
		return
	}

	target := ""
	if len(probe.Targets) > 0 {
		target = probe.Targets[0].Target
	}

	dataChan <- ProbeData{
		ProbeID:         probe.ID,
		Type:            ProbeType_TLS,
		Payload:         raw,
		Target:          target,
		CreatedAt:       time.Now().Add(nettime.GetTimeOffset()),
		SourceInterface: probe.BindInterface,
	}
}

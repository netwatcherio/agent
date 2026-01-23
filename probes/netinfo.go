package probes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackpal/gateway"
	"github.com/showwin/speedtest-go/speedtest"
	log "github.com/sirupsen/logrus"
)

// lookupReverseDNS performs a PTR record lookup for the given IP.
// Returns empty string if lookup fails or no PTR record exists.
func lookupReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Return first PTR record, strip trailing dot
	return strings.TrimSuffix(names[0], ".")
}

// GeoInfo contains geographic and network information.
// This structure is used consistently regardless of the data source (controller or fallback).
type GeoInfo struct {
	City        string  `json:"city,omitempty" bson:"city,omitempty"`
	Region      string  `json:"region,omitempty" bson:"region,omitempty"`
	Country     string  `json:"country,omitempty" bson:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty" bson:"country_code,omitempty"`
	Latitude    float64 `json:"latitude,omitempty" bson:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty" bson:"longitude,omitempty"`
	ASN         uint    `json:"asn,omitempty" bson:"asn,omitempty"`
	ASNOrg      string  `json:"asn_org,omitempty" bson:"asn_org,omitempty"`
	ISP         string  `json:"isp,omitempty" bson:"isp,omitempty"`
	ReverseDNS  string  `json:"reverse_dns,omitempty" bson:"reverse_dns,omitempty"`
}

// NetworkInfoResult contains comprehensive network information for an agent.
// This is the unified structure used for both controller responses and fallback sources.
type NetworkInfoResult struct {
	// Local network info (always from local discovery)
	LocalAddress   string `json:"local_address" bson:"local_address"`
	DefaultGateway string `json:"default_gateway" bson:"default_gateway"`

	// Public network info (from controller or fallback)
	PublicAddress string `json:"public_address" bson:"public_address"`

	// Geographic and network info (normalized from any source)
	Geo *GeoInfo `json:"geo,omitempty" bson:"geo,omitempty"`

	// Legacy fields for backward compatibility (populated from Geo)
	InternetProvider string `json:"internet_provider,omitempty" bson:"internet_provider,omitempty"`
	Lat              string `json:"lat,omitempty" bson:"lat,omitempty"`
	Long             string `json:"long,omitempty" bson:"long,omitempty"`

	// Metadata
	Source    string    `json:"source,omitempty" bson:"source,omitempty"` // "controller" or "speedtest"
	Timestamp time.Time `json:"timestamp" bson:"timestamp"`
}

// ControllerWhoAmIResponse matches the controller's /agent/api/whoami response.
type ControllerWhoAmIResponse struct {
	IP         string    `json:"ip"`
	ReverseDNS string    `json:"reverse_dns,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	GeoIP      *struct {
		City *struct {
			Name        string `json:"name,omitempty"`
			Subdivision string `json:"subdivision,omitempty"`
		} `json:"city,omitempty"`
		Country *struct {
			Code string `json:"code,omitempty"`
			Name string `json:"name,omitempty"`
		} `json:"country,omitempty"`
		ASN *struct {
			Number       uint   `json:"number,omitempty"`
			Organization string `json:"organization,omitempty"`
		} `json:"asn,omitempty"`
		Coordinates *struct {
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		} `json:"coordinates,omitempty"`
	} `json:"geoip,omitempty"`
}

// ControllerConfig holds controller connection info for IP discovery.
type ControllerConfig struct {
	Host        string // e.g., "localhost:8080" or "api.example.com"
	SSL         bool   // Use HTTPS
	WorkspaceID uint
	AgentID     uint
	PSK         string
}

// FetchPublicIPFromController calls the controller's /agent/api/whoami endpoint.
// Returns the public IP and optional GeoIP data without relying on external services.
func FetchPublicIPFromController(ctx context.Context, cfg ControllerConfig) (*ControllerWhoAmIResponse, error) {
	protocol := "http"
	if cfg.SSL {
		protocol = "https"
	}
	url := fmt.Sprintf("%s://%s/agent/api/whoami?quick=false", protocol, cfg.Host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set PSK auth headers
	req.Header.Set("X-Workspace-ID", fmt.Sprintf("%d", cfg.WorkspaceID))
	req.Header.Set("X-Agent-ID", fmt.Sprintf("%d", cfg.AgentID))
	req.Header.Set("X-Agent-PSK", cfg.PSK)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("controller returned %d: %s", resp.StatusCode, string(body))
	}

	var result ControllerWhoAmIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// applyControllerResponse normalizes controller whoami response into NetworkInfoResult.
func applyControllerResponse(n *NetworkInfoResult, whoami *ControllerWhoAmIResponse) {
	n.PublicAddress = whoami.IP
	n.Source = "controller"

	geo := &GeoInfo{
		ReverseDNS: whoami.ReverseDNS,
	}

	if whoami.GeoIP != nil {
		if whoami.GeoIP.City != nil {
			geo.City = whoami.GeoIP.City.Name
			geo.Region = whoami.GeoIP.City.Subdivision
		}
		if whoami.GeoIP.Country != nil {
			geo.Country = whoami.GeoIP.Country.Name
			geo.CountryCode = whoami.GeoIP.Country.Code
		}
		if whoami.GeoIP.ASN != nil {
			geo.ASN = whoami.GeoIP.ASN.Number
			geo.ASNOrg = whoami.GeoIP.ASN.Organization
			geo.ISP = whoami.GeoIP.ASN.Organization // Use ASN org as ISP
		}
		if whoami.GeoIP.Coordinates != nil {
			geo.Latitude = whoami.GeoIP.Coordinates.Latitude
			geo.Longitude = whoami.GeoIP.Coordinates.Longitude
		}
	}

	n.Geo = geo

	// Populate legacy fields for backward compatibility
	n.InternetProvider = geo.ISP
	if geo.Latitude != 0 {
		n.Lat = fmt.Sprintf("%f", geo.Latitude)
	}
	if geo.Longitude != 0 {
		n.Long = fmt.Sprintf("%f", geo.Longitude)
	}
}

// applySpeedtestResponse normalizes speedtest response into NetworkInfoResult.
func applySpeedtestResponse(n *NetworkInfoResult, user *speedtest.User) {
	n.PublicAddress = user.IP
	n.Source = "speedtest"

	geo := &GeoInfo{
		ISP: user.Isp,
	}

	// Parse lat/long if available
	if user.Lat != "" {
		if lat, err := parseFloat(user.Lat); err == nil {
			geo.Latitude = lat
		}
	}
	if user.Lon != "" {
		if lon, err := parseFloat(user.Lon); err == nil {
			geo.Longitude = lon
		}
	}

	n.Geo = geo

	// Populate legacy fields
	n.InternetProvider = user.Isp
	n.Lat = user.Lat
	n.Long = user.Lon
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// NetworkInfoWithController fetches network info, preferring the controller for public IP.
// Falls back to speedtest.FetchUserInfo() if controller is unavailable.
func NetworkInfoWithController(ctx context.Context, cfg *ControllerConfig) (NetworkInfoResult, error) {
	var n NetworkInfoResult
	n.Timestamp = time.Now()

	// Try controller first if configured
	if cfg != nil && cfg.Host != "" && cfg.PSK != "" {
		whoami, err := FetchPublicIPFromController(ctx, *cfg)
		if err == nil && whoami.IP != "" {
			applyControllerResponse(&n, whoami)
			log.Debugf("Public IP from controller: %s", n.PublicAddress)
		} else {
			log.Warnf("Controller whoami failed, falling back to external service: %v", err)
			// Fallback to speedtest
			if err := fetchFromSpeedtest(&n); err != nil {
				return n, err
			}
		}
	} else {
		// No controller config, use speedtest directly
		if err := fetchFromSpeedtest(&n); err != nil {
			return n, err
		}
	}

	// If we have a public IP but no reverse DNS, try to look it up locally
	if n.PublicAddress != "" && (n.Geo == nil || n.Geo.ReverseDNS == "") {
		if rdns := lookupReverseDNS(n.PublicAddress); rdns != "" {
			if n.Geo == nil {
				n.Geo = &GeoInfo{}
			}
			n.Geo.ReverseDNS = rdns
			log.Debugf("Reverse DNS for %s: %s", n.PublicAddress, rdns)
		}
	}

	// Discover local network info
	defaultGateway, err := gateway.DiscoverGateway()
	if err != nil {
		return n, errors.New("could not discover local gateway address")
	}
	n.DefaultGateway = defaultGateway.String()

	localInterface, err := gateway.DiscoverInterface()
	if err != nil {
		return n, errors.New("could not discover local interface address")
	}
	n.LocalAddress = localInterface.String()

	return n, nil
}

// fetchFromSpeedtest uses the speedtest.net API to get public IP info.
func fetchFromSpeedtest(n *NetworkInfoResult) error {
	user, err := speedtest.FetchUserInfo()
	if err != nil {
		return errors.New("unable to fetch general public network information")
	}

	applySpeedtestResponse(n, user)
	return nil
}

// NetworkInfo maintains backward compatibility - uses speedtest like before.
// Use NetworkInfoWithController for new code that has controller config.
func NetworkInfo() (NetworkInfoResult, error) {
	return NetworkInfoWithController(context.Background(), nil)
}

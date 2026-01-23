//go:build windows
// +build windows

package probes

import (
	"bufio"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// DiscoverRoutes returns the routing table on Windows.
// Tries PowerShell first, falls back to netsh.
func DiscoverRoutes() ([]RouteEntry, error) {
	routes, err := discoverRoutesPS()
	if err == nil && len(routes) > 0 {
		return routes, nil
	}

	log.Debugf("PowerShell route discovery failed: %v, trying netsh", err)
	return discoverRoutesNetsh()
}

// discoverRoutesPS uses PowerShell Get-NetRoute cmdlet.
func discoverRoutesPS() ([]RouteEntry, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | ConvertTo-Csv -NoTypeInformation`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var routes []RouteEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header
	if scanner.Scan() {
		// Header line
	}

	for scanner.Scan() {
		line := scanner.Text()
		// CSV format: "DestinationPrefix","NextHop","InterfaceAlias","RouteMetric"
		fields := parseCSVLine(line)
		if len(fields) < 4 {
			continue
		}

		dest := strings.Trim(fields[0], `"`)
		gateway := strings.Trim(fields[1], `"`)
		iface := strings.Trim(fields[2], `"`)
		metricStr := strings.Trim(fields[3], `"`)

		metric, _ := strconv.Atoi(metricStr)

		// Skip link-local and 0.0.0.0 gateways (on-link routes)
		if gateway == "0.0.0.0" && dest != "0.0.0.0/0" {
			continue
		}

		routes = append(routes, RouteEntry{
			Destination: dest,
			Gateway:     gateway,
			Interface:   iface,
			Metric:      metric,
		})
	}

	return routes, nil
}

// parseCSVLine parses a simple CSV line (handles quoted fields).
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case ',':
			if inQuotes {
				current.WriteRune(r)
			} else {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// discoverRoutesNetsh uses netsh as fallback.
func discoverRoutesNetsh() ([]RouteEntry, error) {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "route")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		log.Debugf("netsh route failed: %v, trying route print", err)
		return discoverRoutesRoutePrint()
	}

	var routes []RouteEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Pattern: Metric Prefix Gateway Interface
	// Example: 10    0.0.0.0/0      192.168.1.1    Ethernet
	routeRE := regexp.MustCompile(`^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)\s+(.+?)\s*$`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := routeRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		metric, _ := strconv.Atoi(matches[1])
		dest := matches[2]
		gateway := matches[3]
		iface := strings.TrimSpace(matches[4])

		routes = append(routes, RouteEntry{
			Destination: dest,
			Gateway:     gateway,
			Interface:   iface,
			Metric:      metric,
		})
	}

	if len(routes) == 0 {
		return discoverRoutesRoutePrint()
	}

	return routes, nil
}

// discoverRoutesRoutePrint uses "route print" as final fallback.
func discoverRoutesRoutePrint() ([]RouteEntry, error) {
	cmd := exec.Command("route", "print", "-4")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var routes []RouteEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	inRoutes := false

	// Pattern: Network Destination   Netmask          Gateway       Interface  Metric
	// Example:          0.0.0.0          0.0.0.0      10.0.0.1       10.0.0.2     25
	routeRE := regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()

		// Detect the start of the route table
		if strings.Contains(line, "Network Destination") {
			inRoutes = true
			continue
		}

		// Stop at persistent routes section
		if strings.Contains(line, "Persistent Routes") {
			break
		}

		if !inRoutes {
			continue
		}

		matches := routeRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		dest := matches[1]
		mask := matches[2]
		gateway := matches[3]
		iface := matches[4]
		metric, _ := strconv.Atoi(matches[5])

		// Convert to CIDR notation
		cidr := netmaskToCIDR(mask)
		destCIDR := dest + "/" + cidr

		routes = append(routes, RouteEntry{
			Destination: destCIDR,
			Gateway:     gateway,
			Interface:   iface,
			Metric:      metric,
		})
	}

	log.Debugf("route print found %d routes", len(routes))
	return routes, nil
}

// netmaskToCIDR converts dotted netmask to CIDR prefix length.
func netmaskToCIDR(mask string) string {
	ip := net.ParseIP(mask)
	if ip == nil {
		return "0"
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "0"
	}
	ones, _ := net.IPv4Mask(ip4[0], ip4[1], ip4[2], ip4[3]).Size()
	return strconv.Itoa(ones)
}

// DiscoverDefaultGatewayWindows returns the default gateway IP on Windows.
// This is a direct method when route table parsing fails.
func DiscoverDefaultGatewayWindows() (net.IP, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	ip := strings.TrimSpace(string(output))
	if ip == "" || ip == "0.0.0.0" {
		return nil, ErrNoGateway
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, ErrNoGateway
	}

	return parsed, nil
}

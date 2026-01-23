//go:build !windows
// +build !windows

package probes

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// DiscoverRoutes returns the routing table on Linux/macOS.
func DiscoverRoutes() ([]RouteEntry, error) {
	if runtime.GOOS == "linux" {
		return discoverRoutesLinux()
	}
	return discoverRoutesDarwin()
}

// discoverRoutesLinux reads from /proc/net/route or uses 'ip route'.
func discoverRoutesLinux() ([]RouteEntry, error) {
	// Try /proc/net/route first (most reliable)
	routes, err := discoverRoutesProc()
	if err == nil && len(routes) > 0 {
		return routes, nil
	}

	log.Debugf("/proc/net/route failed: %v, trying ip route", err)
	return discoverRoutesIPCommand()
}

// discoverRoutesProc parses /proc/net/route.
func discoverRoutesProc() ([]RouteEntry, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var routes []RouteEntry
	scanner := bufio.NewScanner(file)

	// Skip header
	if scanner.Scan() {
		// Header: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		iface := fields[0]
		destHex := fields[1]
		gwHex := fields[2]
		maskHex := fields[7]
		metricStr := fields[6]

		dest := hexToIP(destHex)
		gw := hexToIP(gwHex)
		mask := hexToIP(maskHex)
		metric, _ := strconv.Atoi(metricStr)

		// Calculate CIDR prefix
		prefixLen := maskToCIDR(mask)
		destCIDR := dest + "/" + strconv.Itoa(prefixLen)

		routes = append(routes, RouteEntry{
			Destination: destCIDR,
			Gateway:     gw,
			Interface:   iface,
			Metric:      metric,
		})
	}

	return routes, scanner.Err()
}

// hexToIP converts hex IP from /proc/net/route to dotted decimal.
// /proc/net/route stores IPs in little-endian hex format on x86.
func hexToIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}

	// Parse hex as 32-bit value
	val, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return ""
	}

	// Little-endian: first byte in hex is least significant
	// So we read them in reverse order for the IP
	return net.IPv4(
		byte(val&0xFF),
		byte((val>>8)&0xFF),
		byte((val>>16)&0xFF),
		byte((val>>24)&0xFF),
	).String()
}

// maskToCIDR converts a dotted mask to prefix length.
func maskToCIDR(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	ones, _ := net.IPv4Mask(ip4[0], ip4[1], ip4[2], ip4[3]).Size()
	return ones
}

// discoverRoutesIPCommand uses 'ip route show' command.
func discoverRoutesIPCommand() ([]RouteEntry, error) {
	cmd := exec.Command("ip", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var routes []RouteEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Example lines:
	// default via 192.168.1.1 dev eth0 metric 100
	// 10.0.0.0/8 via 10.0.0.1 dev eth0
	// 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		route := RouteEntry{}

		// Parse destination
		if fields[0] == "default" {
			route.Destination = "0.0.0.0/0"
		} else {
			route.Destination = fields[0]
			// Add /32 if no CIDR
			if !strings.Contains(route.Destination, "/") {
				route.Destination += "/32"
			}
		}

		// Parse rest of fields
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					route.Gateway = fields[i+1]
					i++
				}
			case "dev":
				if i+1 < len(fields) {
					route.Interface = fields[i+1]
					i++
				}
			case "metric":
				if i+1 < len(fields) {
					route.Metric, _ = strconv.Atoi(fields[i+1])
					i++
				}
			}
		}

		routes = append(routes, route)
	}

	return routes, nil
}

// discoverRoutesDarwin parses 'netstat -rn' on macOS.
func discoverRoutesDarwin() ([]RouteEntry, error) {
	cmd := exec.Command("netstat", "-rn", "-f", "inet")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var routes []RouteEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header lines until we see "Destination"
	inTable := false
	// Pattern: Destination Gateway Flags Netif Expire
	// Example: default 192.168.1.1 UGScg en0
	routeRE := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Destination") {
			inTable = true
			continue
		}

		if !inTable {
			continue
		}

		matches := routeRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		dest := matches[1]
		gw := matches[2]
		flags := matches[3]
		iface := matches[4]

		// Normalize destination
		if dest == "default" {
			dest = "0.0.0.0/0"
		} else if !strings.Contains(dest, "/") {
			// Add /32 for host routes
			if net.ParseIP(dest) != nil {
				dest += "/32"
			}
		}

		routes = append(routes, RouteEntry{
			Destination: dest,
			Gateway:     gw,
			Interface:   iface,
			Flags:       flags,
		})
	}

	return routes, nil
}

// DiscoverDefaultGatewayWindows is a no-op stub on Unix.
func DiscoverDefaultGatewayWindows() (net.IP, error) {
	return nil, ErrNoGateway
}

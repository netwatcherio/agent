package probes

import (
	"net"
	"strings"
)

// ErrNoGateway is returned when no default gateway can be found.
var ErrNoGateway = &noGatewayError{}

type noGatewayError struct{}

func (e *noGatewayError) Error() string {
	return "no default gateway found"
}

// InterfaceInfo contains detailed information about a network interface.
type InterfaceInfo struct {
	Name      string   `json:"name" bson:"name"`
	Index     int      `json:"index" bson:"index"`
	Type      string   `json:"type" bson:"type"` // ethernet, wifi, loopback, vpn, tunnel, unknown
	MAC       string   `json:"mac,omitempty" bson:"mac,omitempty"`
	MTU       int      `json:"mtu" bson:"mtu"`
	Flags     []string `json:"flags,omitempty" bson:"flags,omitempty"` // up, broadcast, multicast, etc.
	IPv4      []string `json:"ipv4,omitempty" bson:"ipv4,omitempty"`   // CIDRs like "10.0.0.2/24"
	IPv6      []string `json:"ipv6,omitempty" bson:"ipv6,omitempty"`
	Gateway   string   `json:"gateway,omitempty" bson:"gateway,omitempty"` // Default gateway for this interface
	IsDefault bool     `json:"is_default" bson:"is_default"`               // Has the default route
}

// RouteEntry represents a single routing table entry.
type RouteEntry struct {
	Destination string `json:"destination" bson:"destination"` // CIDR like "0.0.0.0/0" or "10.0.0.0/8"
	Gateway     string `json:"gateway" bson:"gateway"`         // Next hop IP
	Interface   string `json:"interface" bson:"interface"`     // Interface name
	Metric      int    `json:"metric" bson:"metric"`
	Flags       string `json:"flags,omitempty" bson:"flags,omitempty"`
}

// DiscoverInterfaces enumerates all network interfaces with their IP addresses.
// This is cross-platform and uses Go's net package.
func DiscoverInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []InterfaceInfo

	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:  iface.Name,
			Index: iface.Index,
			MTU:   iface.MTU,
			Type:  guessInterfaceType(iface.Name, iface.Flags),
		}

		// MAC address
		if len(iface.HardwareAddr) > 0 {
			info.MAC = iface.HardwareAddr.String()
		}

		// Flags
		info.Flags = parseFlags(iface.Flags)

		// IP addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				cidr := ipNet.String()
				if ipNet.IP.To4() != nil {
					info.IPv4 = append(info.IPv4, cidr)
				} else {
					info.IPv6 = append(info.IPv6, cidr)
				}
			}
		}

		// Skip interfaces with no IP addresses (unless loopback)
		if len(info.IPv4) == 0 && len(info.IPv6) == 0 && info.Type != "loopback" {
			continue
		}

		result = append(result, info)
	}

	return result, nil
}

// guessInterfaceType attempts to determine the interface type from its name and flags.
func guessInterfaceType(name string, flags net.Flags) string {
	nameLower := strings.ToLower(name)

	if flags&net.FlagLoopback != 0 {
		return "loopback"
	}

	// Common naming patterns
	switch {
	case strings.HasPrefix(nameLower, "eth"):
		return "ethernet"
	case strings.HasPrefix(nameLower, "en"):
		return "ethernet"
	case strings.HasPrefix(nameLower, "wlan"):
		return "wifi"
	case strings.HasPrefix(nameLower, "wl"):
		return "wifi"
	case strings.HasPrefix(nameLower, "wi-fi"):
		return "wifi"
	case strings.HasPrefix(nameLower, "wifi"):
		return "wifi"
	case strings.HasPrefix(nameLower, "tun"):
		return "tunnel"
	case strings.HasPrefix(nameLower, "tap"):
		return "tunnel"
	case strings.HasPrefix(nameLower, "vpn"):
		return "vpn"
	case strings.HasPrefix(nameLower, "ppp"):
		return "ppp"
	case strings.HasPrefix(nameLower, "docker"):
		return "virtual"
	case strings.HasPrefix(nameLower, "veth"):
		return "virtual"
	case strings.HasPrefix(nameLower, "br"):
		return "bridge"
	case strings.HasPrefix(nameLower, "virbr"):
		return "bridge"
	case strings.Contains(nameLower, "parallels"):
		return "virtual"
	case strings.Contains(nameLower, "vmware"):
		return "virtual"
	case strings.Contains(nameLower, "virtualbox"):
		return "virtual"
	case strings.Contains(nameLower, "hyper-v"):
		return "virtual"
	}

	return "unknown"
}

// parseFlags converts net.Flags to a string slice.
func parseFlags(flags net.Flags) []string {
	var result []string

	if flags&net.FlagUp != 0 {
		result = append(result, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		result = append(result, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		result = append(result, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		result = append(result, "pointtopoint")
	}
	if flags&net.FlagMulticast != 0 {
		result = append(result, "multicast")
	}

	return result
}

// FindDefaultInterface returns the interface that has the default route.
func FindDefaultInterface(interfaces []InterfaceInfo) *InterfaceInfo {
	for i := range interfaces {
		if interfaces[i].IsDefault {
			return &interfaces[i]
		}
	}
	return nil
}

// FindDefaultGateway returns the default gateway from the route table.
func FindDefaultGateway(routes []RouteEntry) string {
	for _, route := range routes {
		if route.Destination == "0.0.0.0/0" || route.Destination == "default" {
			return route.Gateway
		}
	}
	return ""
}

// EnrichInterfacesWithRoutes updates interfaces with gateway info from routes.
func EnrichInterfacesWithRoutes(interfaces []InterfaceInfo, routes []RouteEntry) {
	// Find default route
	var defaultIfaceName string
	for _, route := range routes {
		if route.Destination == "0.0.0.0/0" || route.Destination == "default" {
			defaultIfaceName = route.Interface
			// Set gateway on matching interface
			for i := range interfaces {
				if interfaces[i].Name == route.Interface {
					interfaces[i].Gateway = route.Gateway
					interfaces[i].IsDefault = true
					break
				}
			}
			break
		}
	}

	// Mark default interface even without explicit gateway match
	if defaultIfaceName != "" {
		for i := range interfaces {
			if interfaces[i].Name == defaultIfaceName {
				interfaces[i].IsDefault = true
				break
			}
		}
	}
}

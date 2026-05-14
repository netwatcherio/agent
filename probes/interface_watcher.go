package probes

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// InterfaceSnapshot represents the current state of network interfaces for change detection.
type InterfaceSnapshot struct {
	DefaultGateway string            // Current default gateway IP
	DefaultIface   string            // Name of default interface (e.g., "Ethernet", "Wi-Fi")
	Interfaces     map[string]string // Interface name -> primary IPv4 address
	Timestamp      time.Time
}

// InterfaceChangeEvent is emitted when the network interface state changes.
type InterfaceChangeEvent struct {
	OldSnapshot *InterfaceSnapshot
	NewSnapshot *InterfaceSnapshot
	Reason      string // "gateway_changed", "interface_ip_changed", "interface_added", "interface_removed"
}

// InterfaceChangeHandler is a callback that receives network change events.
type InterfaceChangeHandler func(event InterfaceChangeEvent)

// InterfaceWatcher monitors network interfaces for changes and notifies registered handlers.
// This enables proactive socket invalidation when Windows silently switches interfaces
// (e.g., Wi-Fi→Ethernet, VPN connect/disconnect) without producing explicit socket errors.
type InterfaceWatcher struct {
	handlers     []InterfaceChangeHandler
	handlersMu   sync.RWMutex
	lastSnapshot *InterfaceSnapshot
	snapshotMu   sync.RWMutex
	interval     time.Duration
	stopChan     chan struct{}
	running      bool
	runningMu    sync.Mutex
}

// NewInterfaceWatcher creates a new watcher with the given poll interval.
func NewInterfaceWatcher(interval time.Duration) *InterfaceWatcher {
	return &InterfaceWatcher{
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

// OnChange registers a handler to be called when network interfaces change.
func (w *InterfaceWatcher) OnChange(handler InterfaceChangeHandler) {
	w.handlersMu.Lock()
	defer w.handlersMu.Unlock()
	w.handlers = append(w.handlers, handler)
}

// GetSnapshot returns the current interface snapshot (thread-safe).
func (w *InterfaceWatcher) GetSnapshot() *InterfaceSnapshot {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.lastSnapshot
}

// GetDefaultIP returns the primary IPv4 address of the current default interface.
// Returns "" if no default interface is detected.
func (w *InterfaceWatcher) GetDefaultIP() string {
	snap := w.GetSnapshot()
	if snap == nil {
		return ""
	}
	if ip, ok := snap.Interfaces[snap.DefaultIface]; ok {
		return ip
	}
	return ""
}

// GetIPForInterface returns the primary IPv4 address for a named interface.
// This is useful for binding probes to specific interfaces.
func (w *InterfaceWatcher) GetIPForInterface(ifaceName string) string {
	snap := w.GetSnapshot()
	if snap == nil {
		return ""
	}
	if ip, ok := snap.Interfaces[ifaceName]; ok {
		return ip
	}
	return ""
}

// ResolveBindAddress returns the local IP to bind to for a probe.
// If bindInterface is specified, returns that interface's IP.
// If bindInterface is empty, returns "" (let OS choose, the current default behavior).
// This method is designed to be called when creating UDP/TCP connections,
// enabling future per-probe interface binding.
func (w *InterfaceWatcher) ResolveBindAddress(bindInterface string) string {
	if bindInterface == "" {
		return "" // Let OS choose (current behavior)
	}

	ip := w.GetIPForInterface(bindInterface)
	if ip == "" {
		log.Warnf("[ifwatch] Requested bind to interface %q but no IPv4 address found", bindInterface)
		return ""
	}
	return ip
}

// Start begins the interface monitoring loop.
func (w *InterfaceWatcher) Start() {
	w.runningMu.Lock()
	if w.running {
		w.runningMu.Unlock()
		return
	}
	w.running = true
	w.runningMu.Unlock()

	// Take initial snapshot
	initial := takeSnapshot()
	w.snapshotMu.Lock()
	w.lastSnapshot = initial
	w.snapshotMu.Unlock()

	log.Infof("[ifwatch] Started monitoring %d interfaces (default: %s via %s, poll: %v)",
		len(initial.Interfaces), initial.DefaultIface, initial.DefaultGateway, w.interval)

	go w.watchLoop()
}

// Stop halts the interface monitoring loop.
func (w *InterfaceWatcher) Stop() {
	w.runningMu.Lock()
	defer w.runningMu.Unlock()
	if !w.running {
		return
	}
	w.running = false
	close(w.stopChan)
	log.Info("[ifwatch] Stopped")
}

func (w *InterfaceWatcher) watchLoop() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *InterfaceWatcher) check() {
	newSnap := takeSnapshot()

	w.snapshotMu.RLock()
	oldSnap := w.lastSnapshot
	w.snapshotMu.RUnlock()

	if oldSnap == nil {
		w.snapshotMu.Lock()
		w.lastSnapshot = newSnap
		w.snapshotMu.Unlock()
		return
	}

	// Detect changes
	reason := detectChange(oldSnap, newSnap)
	if reason == "" {
		return // No change
	}

	log.Warnf("[ifwatch] Network change detected: %s (gateway: %s→%s, default: %s→%s)",
		reason, oldSnap.DefaultGateway, newSnap.DefaultGateway,
		oldSnap.DefaultIface, newSnap.DefaultIface)

	// Update snapshot
	w.snapshotMu.Lock()
	w.lastSnapshot = newSnap
	w.snapshotMu.Unlock()

	// Notify handlers
	event := InterfaceChangeEvent{
		OldSnapshot: oldSnap,
		NewSnapshot: newSnap,
		Reason:      reason,
	}

	w.handlersMu.RLock()
	handlers := make([]InterfaceChangeHandler, len(w.handlers))
	copy(handlers, w.handlers)
	w.handlersMu.RUnlock()

	for _, handler := range handlers {
		handler(event)
	}
}

// takeSnapshot captures the current network interface state.
func takeSnapshot() *InterfaceSnapshot {
	snap := &InterfaceSnapshot{
		Interfaces: make(map[string]string),
		Timestamp:  time.Now(),
	}

	ifaces, err := DiscoverInterfaces()
	if err != nil {
		log.Debugf("[ifwatch] DiscoverInterfaces error: %v", err)
		return snap
	}

	routes, err := DiscoverRoutes()
	if err != nil {
		log.Debugf("[ifwatch] DiscoverRoutes error: %v", err)
	} else {
		EnrichInterfacesWithRoutes(ifaces, routes)
		snap.DefaultGateway = FindDefaultGateway(routes)
	}

	for _, iface := range ifaces {
		if len(iface.IPv4) > 0 {
			// Store the first IPv4 address (without CIDR prefix)
			ip := iface.IPv4[0]
			if idx := strings.Index(ip, "/"); idx != -1 {
				ip = ip[:idx]
			}
			snap.Interfaces[iface.Name] = ip
		}
		if iface.IsDefault {
			snap.DefaultIface = iface.Name
		}
	}

	return snap
}

// detectChange compares two snapshots and returns the reason string, or "" if unchanged.
func detectChange(old, new *InterfaceSnapshot) string {
	// Gateway changed
	if old.DefaultGateway != new.DefaultGateway {
		return "gateway_changed"
	}

	// Default interface changed
	if old.DefaultIface != new.DefaultIface {
		return "default_interface_changed"
	}

	// Check if any existing interface changed its IP
	for name, oldIP := range old.Interfaces {
		if newIP, exists := new.Interfaces[name]; exists {
			if oldIP != newIP {
				return "interface_ip_changed"
			}
		}
	}

	// Check for new or removed interfaces (by comparing sorted name lists)
	oldNames := sortedKeys(old.Interfaces)
	newNames := sortedKeys(new.Interfaces)
	if strings.Join(oldNames, ",") != strings.Join(newNames, ",") {
		return "interface_list_changed"
	}

	return "" // No change
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// DialUDPWithBind creates a UDP connection optionally bound to a specific local IP.
// If localIP is empty, it behaves identically to net.DialUDP(udp, nil, raddr).
// This is the central dial function for probes that want interface affinity.
func DialUDPWithBind(localIP string, raddr *net.UDPAddr) (*net.UDPConn, error) {
	var laddr *net.UDPAddr
	if localIP != "" {
		laddr = &net.UDPAddr{
			IP: net.ParseIP(localIP),
		}
	}
	return net.DialUDP("udp", laddr, raddr)
}

// resolveBindIP resolves a network interface name (e.g., "Ethernet", "Wi-Fi", "eth0")
// to its primary IPv4 address. Returns "" if the interface doesn't exist or has no IPv4.
//
// This is the function probes call when they have a BindInterface configured.
// It always queries the live interface list to get the current IP (not cached).
func resolveBindIP(ifaceName string) string {
	if ip, _ := ResolveBindInterface(ifaceName); ip != "" {
		return ip
	}
	return ""
}

// ResolveBindInterface resolves a network interface name to its primary IPv4 address.
// Returns (ip, nil) on success.
// Returns ("", err) if the interface is explicitly configured but not found.
// Returns ("", nil) if the interface exists but has no IPv4 address.
//
// Use this when you need to distinguish between "interface missing" vs "no IPv4".
func ResolveBindInterface(ifaceName string) (string, error) {
	ifaces, err := DiscoverInterfaces()
	if err != nil {
		log.Debugf("[bind] DiscoverInterfaces error: %v", err)
		return "", fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			if len(iface.IPv4) == 0 {
				return "", fmt.Errorf("interface %q exists but has no IPv4 address", ifaceName)
			}
			ip := iface.IPv4[0]
			if idx := strings.Index(ip, "/"); idx != -1 {
				ip = ip[:idx]
			}
			return ip, nil
		}
	}
	return "", fmt.Errorf("interface %q not found", ifaceName)
}

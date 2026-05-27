//go:build windows
// +build windows

package probes

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// setDSCPMarking sets the IP DSCP (ToS) field on the UDP socket
// This implementation is for Windows - DSCP marking via IP_TOS is not directly supported
// on Windows in the same way as Unix. Windows uses a different mechanism (QoS API).
// This is a no-op on Windows with a debug log.
func (ts *TrafficSim) setDSCPMarking(conn *net.UDPConn, dscp int) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}

	if dscp > 0 {
		log.Debugf("[trafficsim] DSCP marking (value %d) not supported on Windows - skipping", dscp)
	}

	return nil
}

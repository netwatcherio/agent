//go:build !windows
// +build !windows

package probes

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// setDSCPMarking sets the IP DSCP (ToS) field on the UDP socket
// DSCP value is left-shifted by 2 to form the ToS byte (low 2 bits are ECN)
// This implementation is for Unix-like systems (Linux, macOS)
func (ts *TrafficSim) setDSCPMarking(conn *net.UDPConn, dscp int) error {
	if conn == nil {
		return fmt.Errorf("nil connection")
	}

	if dscp <= 0 {
		return nil // No DSCP to set
	}

	// Get the underlying raw connection to set socket option
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("getting syscall conn: %w", err)
	}

	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		// IP_TOS is socket option for setting Type of Service byte
		// On Unix: IPPROTO_IP, IP_TOS
		// DSCP is upper 6 bits of ToS byte, lower 2 bits are ECN
		tos := uint8(dscp << 2)
		_, _, err := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd,
			syscall.IPPROTO_IP,
			syscall.IP_TOS,
			uintptr(unsafe.Pointer(&tos)),
			uintptr(1),
			0)
		if err != 0 {
			sysErr = fmt.Errorf("setsockopt IP_TOS: %v", err)
		}
	})
	if err != nil {
		return fmt.Errorf("rawConn.Control: %w", err)
	}
	return sysErr
}

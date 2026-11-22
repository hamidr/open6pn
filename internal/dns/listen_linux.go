package dns

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// freebind lets a socket bind an address the host does not have assigned to
// an interface. The resolver address is such an address on purpose: it is
// only local for packets the datapath has verified (see datapath.setupRouting).
func freebind(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
	}); err != nil {
		return err
	}
	return serr
}

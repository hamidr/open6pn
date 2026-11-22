//go:build !linux

package dns

import "syscall"

func freebind(_, _ string, _ syscall.RawConn) error { return nil }

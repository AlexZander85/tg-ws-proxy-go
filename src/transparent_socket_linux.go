//go:build linux

package main

import (
	"context"
	"net"
	"syscall"
)

const (
	linuxIPTransparent   = 19
	linuxIPv6Transparent = 75
	linuxSOMark          = 36
)

func listenTransparent(address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				level := syscall.SOL_IP
				option := linuxIPTransparent
				if network == "tcp6" {
					level = syscall.SOL_IPV6
					option = linuxIPv6Transparent
				}
				sockErr = syscall.SetsockoptInt(int(fd), level, option, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp", address)
}

func configureUpstreamDialer(d *net.Dialer, mark uint32) {
	if mark == 0 {
		return
	}
	previous := d.Control
	d.Control = func(network, address string, raw syscall.RawConn) error {
		if previous != nil {
			if err := previous(network, address, raw); err != nil {
				return err
			}
		}
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, linuxSOMark, int(mark))
		}); err != nil {
			return err
		}
		return sockErr
	}
}

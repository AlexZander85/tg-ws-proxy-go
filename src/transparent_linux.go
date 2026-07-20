//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

const (
	linuxIPTransparent   = 19
	linuxIPv6Transparent = 75
)

func listenTransparent(address string) (net.Listener, error) {
	network, err := transparentListenNetwork(address)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if network == "tcp6" {
				socketErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, linuxIPv6Transparent, 1)
			} else {
				socketErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, linuxIPTransparent, 1)
			}
		}); err != nil {
			return err
		}
		return socketErr
	}}
	listener, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, fmt.Errorf("transparent listen %s: %w", address, err)
	}
	return listener, nil
}

//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

const (
	linuxIPTransparent   = 19
	linuxIPv6Transparent = 75
)

func listenTransparent(host string, port int) (net.Listener, error) {
	network := "tcp4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "tcp6"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	listenConfig := net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			var sockErr error
			if err := raw.Control(func(fd uintptr) {
				level := syscall.IPPROTO_IP
				option := linuxIPTransparent
				if network == "tcp6" {
					level = syscall.IPPROTO_IPV6
					option = linuxIPv6Transparent
				}
				sockErr = syscall.SetsockoptInt(int(fd), level, option, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	listener, err := listenConfig.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, fmt.Errorf("transparent listen %s: %w", addr, err)
	}
	return listener, nil
}

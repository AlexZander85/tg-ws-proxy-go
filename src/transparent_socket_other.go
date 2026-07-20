//go:build !linux

package main

import (
	"errors"
	"net"
)

func listenTransparent(address string) (net.Listener, error) {
	return nil, errors.New("transparent listener is supported only on Linux")
}

func configureUpstreamDialer(d *net.Dialer, mark uint32) {}

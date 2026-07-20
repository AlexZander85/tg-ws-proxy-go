//go:build !linux

package main

import (
	"errors"
	"net"
)

func listenTransparent(host string, port int) (net.Listener, error) {
	return nil, errors.New("transparent listener is supported only on Linux")
}

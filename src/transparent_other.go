//go:build !linux

package main

import (
	"fmt"
	"net"
)

func listenTransparent(address string) (net.Listener, error) {
	return nil, fmt.Errorf("transparent listener is supported on Linux only")
}

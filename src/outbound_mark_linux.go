//go:build linux

package main

import "syscall"

func validateOutboundMark(mark uint32) error {
	return nil
}

func outboundMarkControl(mark uint32) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return socketErr
	}
}

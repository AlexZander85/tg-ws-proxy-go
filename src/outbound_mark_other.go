//go:build !linux

package main

import (
	"fmt"
	"syscall"
)

func validateOutboundMark(mark uint32) error {
	if mark != 0 {
		return fmt.Errorf("--outbound-mark is supported on Linux only")
	}
	return nil
}

func outboundMarkControl(mark uint32) func(string, string, syscall.RawConn) error {
	return nil
}

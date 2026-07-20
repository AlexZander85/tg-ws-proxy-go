//go:build linux

package main

import (
	"testing"
	"time"
)

func TestConfigureOutboundMark(t *testing.T) {
	defer configuredOutboundMark.Store(0)
	if err := configureOutboundMark(0x8000); err != nil {
		t.Fatal(err)
	}
	if got := configuredOutboundMark.Load(); got != 0x8000 {
		t.Fatalf("configured mark = %#x, want 0x8000", got)
	}
	if newUpstreamDialer(time.Second).Control == nil {
		t.Fatal("marked dialer must have Control hook")
	}
}

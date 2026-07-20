package main

import (
	"crypto/tls"
	"testing"
)

func TestNewUpstreamTLSConfig(t *testing.T) {
	const serverName = "example.com"
	cfg := newUpstreamTLSConfig(serverName)

	if cfg.ServerName != serverName {
		t.Fatalf("ServerName = %q, want %q", cfg.ServerName, serverName)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("upstream TLS certificate verification must be enabled")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
	}
}

package main

import (
	"bytes"
	"net"
)

func validTransparentDC(dc int) bool {
	if dc < 0 {
		dc = -dc
	}
	return (dc >= 1 && dc <= 5) || dc == 203
}

func reservedTransparentPrefix(prefix []byte) bool {
	if len(prefix) < 4 {
		return false
	}
	if reservedFirst[prefix[0]] {
		return true
	}
	for _, reserved := range reservedStart {
		if bytes.Equal(prefix[:4], reserved) {
			return true
		}
	}
	return false
}

func transparentDCForIP(cfg *Config, ip net.IP) (int, bool) {
	if cfg == nil || ip == nil || ip.IsUnspecified() {
		return 0, false
	}

	matches := make(map[int]struct{})
	addMatch := func(dc int, raw string) {
		if parsed := net.ParseIP(raw); parsed != nil && parsed.Equal(ip) {
			matches[dc] = struct{}{}
		}
	}
	for dc, raw := range dcFallbackDefaults {
		addMatch(dc, raw)
	}
	for dc, pool := range cfg.DCPool {
		for _, raw := range pool {
			addMatch(dc, raw)
		}
	}
	for dc, raw := range cfg.DCMap {
		addMatch(dc, raw)
	}

	if len(matches) != 1 {
		return 0, false
	}
	for dc := range matches {
		return dc, true
	}
	return 0, false
}

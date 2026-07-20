package main

import (
	"bytes"
	"net"
)

type transparentDCRange struct {
	network *net.IPNet
	dc      int
}

func parseTransparentDCRanges(entries map[string]int) []transparentDCRange {
	ranges := make([]transparentDCRange, 0, len(entries))
	for cidr, dc := range entries {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			ranges = append(ranges, transparentDCRange{network: network, dc: dc})
		}
	}
	return ranges
}

var transparentDCRanges = parseTransparentDCRanges(map[string]int{
	"149.154.161.0/24":       2,
	"149.154.167.0/24":       2,
	"149.154.165.0/24":       4,
	"149.154.166.0/24":       4,
	"91.108.4.0/22":          4,
	"2001:67c:4e8:f002::/64": 2,
	"2001:67c:4e8:f004::/64": 4,
})

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

func transparentDCForIPRange(ip net.IP) (int, bool) {
	if ip == nil || ip.IsUnspecified() {
		return 0, false
	}
	for _, entry := range transparentDCRanges {
		if entry.network.Contains(ip) {
			return entry.dc, true
		}
	}
	return 0, false
}

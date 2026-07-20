package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func parseTransparentDCRules(items []string) ([]transparentDCRule, error) {
	rules := make([]transparentDCRule, 0, len(items))
	for _, item := range items {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --transparent-dc-map %q: expected DC=IP_OR_CIDR", item)
		}
		dc, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || !validTransparentDC(dc) {
			return nil, fmt.Errorf("invalid DC in --transparent-dc-map %q", item)
		}

		rawNetwork := strings.TrimSpace(parts[1])
		var ip net.IP
		var network *net.IPNet
		if strings.Contains(rawNetwork, "/") {
			ip, network, err = net.ParseCIDR(rawNetwork)
			if err != nil {
				return nil, fmt.Errorf("invalid network in --transparent-dc-map %q: %w", item, err)
			}
			network.IP = ip
		} else {
			ip = net.ParseIP(rawNetwork)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP in --transparent-dc-map %q", item)
			}
			if ip4 := ip.To4(); ip4 != nil {
				network = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			} else {
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		rules = append(rules, transparentDCRule{DC: dc, Network: network})
	}
	return rules, nil
}

func validTransparentDC(dc int) bool {
	return dc >= 1 && dc <= 5 || dc == 203
}

func resolveTransparentDC(cfg *Config, originalIP net.IP, hi *handshakeInfo) (int, string, bool) {
	for _, rule := range cfg.TransparentDCRules {
		if rule.Network != nil && rule.Network.Contains(originalIP) {
			return rule.DC, "configured destination map", true
		}
	}

	for dc, rawIP := range dcFallbackDefaults {
		if ip := net.ParseIP(rawIP); ip != nil && ip.Equal(originalIP) {
			return dc, "known Telegram DC address", true
		}
	}

	if hi != nil && validTransparentDC(hi.DC) {
		return hi.DC, "obfuscated2 handshake", true
	}
	return 0, "", false
}

var transparentStartOnce sync.Once

func startTransparent(cfg *Config) {
	if cfg == nil || cfg.TransparentListen == "" {
		return
	}
	transparentStartOnce.Do(func() {
		setUpstreamSocketMark(cfg.TransparentBypassMark)
		sessionsSem := make(chan struct{}, cfg.MaxConns)
		go func() {
			if err := serveTransparent(cfg, sessionsSem); err != nil {
				log.Fatalf("transparent listener failed: %v", err)
			}
		}()
	})
}

func serveTransparent(cfg *Config, sessionsSem chan struct{}) error {
	ln, err := listenTransparent(cfg.TransparentListen)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("INFO     Transparent:   %s (upstream mark=0x%x, fail-open=%v)", cfg.TransparentListen, cfg.TransparentBypassMark, cfg.TransparentFailOpen)
	acceptBackoff := acceptBackoffMin
	tcpLn, _ := ln.(*net.TCPListener)

	for {
		if tcpLn != nil {
			_ = tcpLn.SetDeadline(time.Now().Add(acceptPollTimeout))
		}
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				acceptBackoff = acceptBackoffMin
				continue
			}
			log.Printf("WARN   transparent accept error: %v", err)
			time.Sleep(acceptBackoff)
			acceptBackoff *= 2
			if acceptBackoff > acceptBackoffMax {
				acceptBackoff = acceptBackoffMax
			}
			continue
		}
		acceptBackoff = acceptBackoffMin
		atomic.AddInt64(&stats.connectionsTotal, 1)

		select {
		case sessionsSem <- struct{}{}:
			go func(client net.Conn) {
				defer func() { <-sessionsSem }()
				defer func() {
					if r := recover(); r != nil {
						_ = client.Close()
						log.Printf("ERROR  [%s] transparent panic recovered: %v", client.RemoteAddr(), r)
					}
				}()
				handleTransparentClient(client, cfg)
			}(conn)
		default:
			log.Printf("WARN   max concurrent sessions reached (%d), dropping transparent client %s", cfg.MaxConns, conn.RemoteAddr())
			_ = conn.Close()
		}
	}
}

func handleTransparentClient(client net.Conn, cfg *Config) {
	atomic.AddInt64(&stats.connectionsActive, 1)
	defer atomic.AddInt64(&stats.connectionsActive, -1)
	defer client.Close()
	_ = setSockOpts(client, cfg.BufKB*1024)

	original, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok || original.IP == nil {
		atomic.AddInt64(&stats.connectionsBad, 1)
		debugf(cfg, "[%s] transparent connection has no original TCP destination", client.RemoteAddr())
		return
	}
	original = &net.TCPAddr{IP: append(net.IP(nil), original.IP...), Port: original.Port, Zone: original.Zone}
	label := fmt.Sprintf("%s -> %s", client.RemoteAddr(), original)

	_ = client.SetReadDeadline(time.Now().Add(clientHandshakeTimeout))
	handshake := make([]byte, handshakeLen)
	n, err := io.ReadFull(client, handshake)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		if n == 0 {
			debugf(cfg, "[%s] transparent client disconnected before handshake", label)
			return
		}
		transparentFailOpen(client, cfg, original, handshake[:n], fmt.Sprintf("short handshake (%d/%d bytes)", n, handshakeLen))
		return
	}

	hi, ok := tryDirectHandshake(handshake)
	if !ok {
		transparentFailOpen(client, cfg, original, handshake, "not a supported direct obfuscated2 handshake")
		return
	}

	dc, source, ok := resolveTransparentDC(cfg, original.IP, hi)
	if !ok {
		transparentFailOpen(client, cfg, original, handshake, fmt.Sprintf("unable to resolve Telegram DC (handshake DC=%d)", hi.DC))
		return
	}
	if hi.DC != 0 && hi.DC != dc {
		debugf(cfg, "[%s] transparent DC mismatch: handshake=DC%d resolved=DC%d via %s", label, hi.DC, dc, source)
	}
	hi.DC = dc
	atomic.AddInt64(&stats.connectionsTransparent, 1)
	debugf(cfg, "[%s] transparent MTProto accepted: DC%d media=%v via %s", label, hi.DC, hi.IsMedia, source)
	handleMTProtoClient(client, cfg, hi, nil, label)
}

func transparentFailOpen(client net.Conn, cfg *Config, original *net.TCPAddr, prefix []byte, reason string) {
	if !cfg.TransparentFailOpen {
		atomic.AddInt64(&stats.connectionsBad, 1)
		debugf(cfg, "[%s -> %s] transparent drop: %s", client.RemoteAddr(), original, reason)
		return
	}

	upstream, err := newUpstreamDialer(tcpDialTimeout).Dial("tcp", original.String())
	if err != nil {
		atomic.AddInt64(&stats.connectionsBad, 1)
		warnf("[%s -> %s] transparent fail-open dial failed after %s: %v", client.RemoteAddr(), original, reason, err)
		return
	}
	defer upstream.Close()

	if len(prefix) > 0 {
		_ = upstream.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		if _, err := upstream.Write(prefix); err != nil {
			warnf("[%s -> %s] transparent fail-open prefix write failed: %v", client.RemoteAddr(), original, err)
			return
		}
		_ = upstream.SetWriteDeadline(time.Time{})
	}

	atomic.AddInt64(&stats.transparentFailOpen, 1)
	debugf(cfg, "[%s -> %s] transparent fail-open: %s", client.RemoteAddr(), original, reason)
	relayTransparentTCP(client, upstream)
}

func relayTransparentTCP(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyDirection := func(dst, src net.Conn, counter *int64) {
		defer func() { done <- struct{}{} }()
		buf := ioBufPool.Get().([]byte)
		defer ioBufPool.Put(buf)
		n, _ := io.CopyBuffer(dst, src, buf)
		atomic.AddInt64(counter, n)
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}

	go copyDirection(upstream, client, &stats.bytesUp)
	go copyDirection(client, upstream, &stats.bytesDown)
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type transparentDCNet struct {
	dc  int
	net *net.IPNet
}

type transparentDCResolver struct {
	nets []transparentDCNet
}

var defaultTransparentDCMap = []string{
	"1:149.154.175.50/32",
	"2:149.154.167.51/32",
	"3:149.154.175.100/32",
	"4:149.154.167.91/32",
	"5:149.154.171.5/32",
	"203:91.105.192.100/32",
	"1:2001:b28:f23d:f001::a/128",
	"2:2001:67c:4e8:f002::a/128",
	"3:2001:b28:f23d:f003::a/128",
	"4:2001:67c:4e8:f004::a/128",
	"5:2001:b28:f23f:f005::a/128",
	"2:149.154.167.0/24",
	"2:149.154.161.0/24",
	"4:149.154.165.0/24",
	"4:149.154.166.0/24",
	"4:91.108.4.0/22",
	"2:2001:67c:4e8:f002::/64",
	"4:2001:67c:4e8:f004::/64",
}

func parseTransparentDCMap(raw string) (transparentDCNet, error) {
	var zero transparentDCNet
	raw = strings.TrimSpace(raw)
	sep := strings.IndexByte(raw, ':')
	if sep <= 0 || sep == len(raw)-1 {
		return zero, fmt.Errorf("expected DC:CIDR, got %q", raw)
	}
	dc, err := strconv.Atoi(strings.TrimSpace(raw[:sep]))
	if err != nil || !validTransparentDC(dc) {
		return zero, fmt.Errorf("invalid Telegram DC in %q", raw)
	}
	cidr := strings.TrimSpace(raw[sep+1:])
	if ip := net.ParseIP(cidr); ip != nil {
		if ip.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return zero, fmt.Errorf("invalid CIDR in %q: %w", raw, err)
	}
	return transparentDCNet{dc: dc, net: network}, nil
}

func validateTransparentDCMappings(values []string) error {
	for _, value := range values {
		if _, err := parseTransparentDCMap(value); err != nil {
			return err
		}
	}
	return nil
}

func newTransparentDCResolver(overrides []string) (*transparentDCResolver, error) {
	values := make([]string, 0, len(overrides)+len(defaultTransparentDCMap))
	values = append(values, overrides...)
	values = append(values, defaultTransparentDCMap...)
	resolver := &transparentDCResolver{nets: make([]transparentDCNet, 0, len(values))}
	for _, value := range values {
		entry, err := parseTransparentDCMap(value)
		if err != nil {
			return nil, err
		}
		resolver.nets = append(resolver.nets, entry)
	}
	return resolver, nil
}

func (r *transparentDCResolver) resolve(ip net.IP, handshakeDC int) (dc int, source string, ok bool) {
	if ip != nil {
		for _, entry := range r.nets {
			if entry.net.Contains(ip) {
				return entry.dc, "destination", true
			}
		}
	}
	if validTransparentDC(handshakeDC) {
		if handshakeDC < 0 {
			handshakeDC = -handshakeDC
		}
		return handshakeDC, "handshake", true
	}
	return 0, "", false
}

func validTransparentDC(dc int) bool {
	if dc < 0 {
		dc = -dc
	}
	return dc >= 1 && dc <= 5 || dc == 203
}

func isReservedTransparentPrefix(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	if head[0] == 0xef || bytes.Equal(head[:4], []byte{0, 0, 0, 0}) {
		return true
	}
	for _, reserved := range reservedStart {
		if bytes.Equal(head[:4], reserved) {
			return true
		}
	}
	return false
}

func originalTransparentDestination(conn net.Conn) (*net.TCPAddr, error) {
	addr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || addr == nil || addr.IP == nil || addr.Port <= 0 {
		return nil, fmt.Errorf("unexpected local address %T %v", conn.LocalAddr(), conn.LocalAddr())
	}
	copyAddr := *addr
	copyAddr.IP = append(net.IP(nil), addr.IP...)
	return &copyAddr, nil
}

func transparentListenNetwork(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid --transparent-listen address %q: %w", address, err)
	}
	if host == "" {
		return "tcp4", nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("--transparent-listen host must be an IP address: %q", host)
	}
	if ip.To4() != nil {
		return "tcp4", nil
	}
	return "tcp6", nil
}

func startTransparentServer(cfg *Config) error {
	resolver, err := newTransparentDCResolver(cfg.TransparentDCMap)
	if err != nil {
		return fmt.Errorf("transparent DC map: %w", err)
	}
	listener, err := listenTransparent(cfg.TransparentListen)
	if err != nil {
		return err
	}
	log.Printf("INFO   Transparent listener on %s (TPROXY, fail-open=%t)", cfg.TransparentListen, cfg.TransparentFailOpen)
	go serveTransparent(listener, cfg, resolver)
	return nil
}

func serveTransparent(listener net.Listener, cfg *Config, resolver *transparentDCResolver) {
	sessionsSem := make(chan struct{}, cfg.MaxConns)
	acceptBackoff := acceptBackoffMin
	for {
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(acceptPollTimeout))
		}
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
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
			go func() {
				defer func() { <-sessionsSem }()
				defer func() {
					if recovered := recover(); recovered != nil {
						_ = conn.Close()
						log.Printf("ERROR  [%s] transparent panic recovered: %v", conn.RemoteAddr(), recovered)
					}
				}()
				handleTransparentClient(conn, cfg, resolver)
			}()
		default:
			log.Printf("WARN   max concurrent transparent sessions reached (%d), dropping %s", cfg.MaxConns, conn.RemoteAddr())
			_ = conn.Close()
		}
	}
}

func handleTransparentClient(client net.Conn, cfg *Config, resolver *transparentDCResolver) {
	atomic.AddInt64(&stats.connectionsActive, 1)
	defer atomic.AddInt64(&stats.connectionsActive, -1)
	defer client.Close()
	_ = setSockOpts(client, cfg.BufKB*1024)

	destination, err := originalTransparentDestination(client)
	if err != nil {
		debugf(cfg, "[%s] transparent destination unavailable: %v", client.RemoteAddr(), err)
		return
	}
	label := fmt.Sprintf("%s -> %s", client.RemoteAddr(), destination)

	_ = client.SetReadDeadline(time.Now().Add(clientHandshakeTimeout))
	handshake := make([]byte, handshakeLen)
	n, err := io.ReadFull(client, handshake[:4])
	if err != nil {
		_ = client.SetReadDeadline(time.Time{})
		if n > 0 {
			transparentFailOpen(client, cfg, destination, handshake[:n], label, "short prefix")
		}
		return
	}
	if isReservedTransparentPrefix(handshake[:4]) {
		_ = client.SetReadDeadline(time.Time{})
		transparentFailOpen(client, cfg, destination, handshake[:4], label, "non-obfuscated transport")
		return
	}
	nRest, err := io.ReadFull(client, handshake[4:])
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		transparentFailOpen(client, cfg, destination, handshake[:4+nRest], label, "short handshake")
		return
	}

	hi, ok := tryDirectHandshake(handshake)
	if !ok {
		transparentFailOpen(client, cfg, destination, handshake, label, "invalid obfuscated2 handshake")
		return
	}
	dc, source, ok := resolver.resolve(destination.IP, hi.DC)
	if !ok {
		transparentFailOpen(client, cfg, destination, handshake, label, "unknown Telegram DC")
		return
	}
	hi.DC = dc
	log.Printf("INFO   [%s] transparent DC%d via %s", label, dc, source)
	handleMTProtoClient(client, cfg, hi, nil, label)
}

func transparentFailOpen(client net.Conn, cfg *Config, destination *net.TCPAddr, prefix []byte, label, reason string) {
	if !cfg.TransparentFailOpen {
		debugf(cfg, "[%s] transparent drop (%s)", label, reason)
		return
	}
	upstream, err := net.DialTimeout("tcp", destination.String(), tcpDialTimeout)
	if err != nil {
		debugf(cfg, "[%s] transparent fail-open dial failed (%s): %v", label, reason, err)
		return
	}
	defer upstream.Close()
	if len(prefix) > 0 {
		if err := writeTransparentFull(upstream, prefix); err != nil {
			debugf(cfg, "[%s] transparent fail-open prefix write failed: %v", label, err)
			return
		}
	}
	debugf(cfg, "[%s] transparent fail-open (%s)", label, reason)
	relayTransparentDirect(client, upstream)
}

func writeTransparentFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func relayTransparentDirect(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOne(upstream, client)
	go copyOne(client, upstream)
	<-done
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	<-done
}

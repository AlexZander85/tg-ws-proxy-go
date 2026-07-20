package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

func serveTransparent(ln net.Listener, cfg *Config, secret []byte, sessionsSem chan struct{}) {
	acceptBackoff := acceptBackoffMin
	tcpLn, _ := ln.(*net.TCPListener)

	for {
		if tcpLn != nil {
			_ = tcpLn.SetDeadline(time.Now().Add(acceptPollTimeout))
		}
		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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
					if recovered := recover(); recovered != nil {
						_ = client.Close()
						log.Printf("ERROR  [%s] transparent panic recovered: %v", client.RemoteAddr(), recovered)
					}
				}()
				handleTransparentClient(client, cfg, secret)
			}(conn)
		default:
			log.Printf("WARN   max concurrent sessions reached (%d), dropping transparent client %s", cfg.MaxConns, conn.RemoteAddr())
			_ = conn.Close()
		}
	}
}

func handleTransparentClient(client net.Conn, cfg *Config, secret []byte) {
	atomic.AddInt64(&stats.connectionsActive, 1)
	atomic.AddInt64(&stats.connectionsTransparent, 1)
	defer atomic.AddInt64(&stats.connectionsActive, -1)
	defer client.Close()

	label := client.RemoteAddr().String()
	_ = setSockOpts(client, cfg.BufKB*1024)

	original, ok := transparentOriginalDestination(client)
	if !ok {
		atomic.AddInt64(&stats.connectionsBad, 1)
		debugf(cfg, "[%s] transparent connection has no original TCP destination", label)
		return
	}

	_ = client.SetReadDeadline(time.Now().Add(clientHandshakeTimeout))
	handshake := make([]byte, handshakeLen)
	n, err := io.ReadFull(client, handshake[:4])
	if err != nil {
		_ = client.SetReadDeadline(time.Time{})
		transparentFailOpenIfEnabled(client, cfg, original, handshake[:n], label, "short transport header")
		return
	}
	if reservedTransparentPrefix(handshake[:4]) {
		_ = client.SetReadDeadline(time.Time{})
		transparentFailOpenIfEnabled(client, cfg, original, handshake[:4], label, "non-obfuscated transport")
		return
	}

	nRest, err := io.ReadFull(client, handshake[4:])
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		transparentFailOpenIfEnabled(client, cfg, original, handshake[:4+nRest], label, "short obfuscated handshake")
		return
	}

	hi, ok := tryDirectHandshake(handshake)
	if !ok {
		atomic.AddInt64(&stats.connectionsBad, 1)
		transparentFailOpenIfEnabled(client, cfg, original, handshake, label, "invalid direct obfuscated2 handshake")
		return
	}

	dc, media, dcSource, ok := resolveTransparentDC(cfg, original.IP, hi.DC, hi.IsMedia)
	if !ok {
		transparentFailOpenIfEnabled(client, cfg, original, handshake, label, fmt.Sprintf("unresolved DC %d", hi.DC))
		return
	}
	hi.DC = dc
	hi.IsMedia = media

	mediaTag := ""
	if hi.IsMedia {
		mediaTag = " media"
	}
	log.Printf("INFO   [%s] transparent original-dst=%s -> DC%d%s (dc-from=%s)", label, original, hi.DC, mediaTag, dcSource)
	handleMTProtoClient(client, cfg, hi, secret, label+" transparent")
}

func transparentOriginalDestination(client net.Conn) (*net.TCPAddr, bool) {
	addr, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok || addr.IP == nil || addr.Port <= 0 {
		return nil, false
	}
	return &net.TCPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}, true
}

func transparentFailOpenIfEnabled(client net.Conn, cfg *Config, original *net.TCPAddr, prefix []byte, label, reason string) {
	if !cfg.TransparentFailOpen {
		debugf(cfg, "[%s] transparent %s; fail-open disabled", label, reason)
		return
	}
	debugf(cfg, "[%s] transparent %s; failing open to %s", label, reason, original)
	if err := transparentFailOpen(client, cfg, original, prefix); err != nil {
		warnf("[%s] transparent fail-open to %s failed: %v", label, original, err)
	}
}

func transparentFailOpen(client net.Conn, cfg *Config, original *net.TCPAddr, prefix []byte) error {
	if original == nil || original.IP == nil || original.IP.IsUnspecified() || original.Port <= 0 {
		return errors.New("invalid original destination")
	}
	if transparentDestinationIsListener(cfg, original) {
		return errors.New("original destination resolves to the transparent listener")
	}

	upstream, err := newUpstreamDialer(tcpDialTimeout).Dial("tcp", net.JoinHostPort(original.IP.String(), strconv.Itoa(original.Port)))
	if err != nil {
		return err
	}
	defer upstream.Close()
	_ = setSockOpts(upstream, cfg.BufKB*1024)

	if len(prefix) > 0 {
		if _, err := io.Copy(upstream, bytes.NewReader(prefix)); err != nil {
			return err
		}
	}
	bridgeTransparentRaw(client, upstream)
	return nil
}

func transparentDestinationIsListener(cfg *Config, destination *net.TCPAddr) bool {
	if cfg == nil || destination == nil || destination.Port != cfg.TransparentPort {
		return false
	}
	bindIP := net.ParseIP(cfg.TransparentHost)
	return bindIP == nil || bindIP.IsUnspecified() || bindIP.Equal(destination.IP) || destination.IP.IsLoopback()
}

func bridgeTransparentRaw(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyOneWay := func(dst, src net.Conn) {
		buf := ioBufPool.Get().([]byte)
		defer ioBufPool.Put(buf)
		_, _ = io.CopyBuffer(dst, src, buf)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOneWay(upstream, client)
	go copyOneWay(client, upstream)
	<-done
	_ = client.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	<-done
}

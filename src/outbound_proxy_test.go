package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildOutboundDialerEmpty(t *testing.T) {
	d, err := buildOutboundDialer("")
	if err != nil {
		t.Fatalf("unexpected error for empty proxy URL: %v", err)
	}
	if d != nil {
		t.Fatalf("expected nil dialer for empty proxy URL, got %v", d)
	}
}

func TestBuildOutboundDialerInvalidScheme(t *testing.T) {
	_, err := buildOutboundDialer("http://127.0.0.1:8080")
	if err == nil {
		t.Fatal("expected error for unsupported scheme (only socks5:// is supported), got nil")
	}
}

func TestBuildOutboundDialerInvalidURL(t *testing.T) {
	_, err := buildOutboundDialer("://not a url")
	if err == nil {
		t.Fatal("expected error for malformed URL, got nil")
	}
}

// minimalSOCKS5Server — достаточный для теста RFC1928-сервер: без
// аутентификации, только CONNECT. Нужен, чтобы доказать, что
// dialUpstream() реально устанавливает TCP-соединение ЧЕРЕЗ SOCKS5, а
// не просто не падает с ошибкой при наличии cfg.OutboundProxy.
func minimalSOCKS5Server(t *testing.T, echoAddr string) (addr string, connectedThrough *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test SOCKS5 listener: %v", err)
	}
	var count int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)

				// greeting: VER NMETHODS METHODS...
				ver, _ := r.ReadByte()
				if ver != 0x05 {
					return
				}
				nmethods, _ := r.ReadByte()
				_, _ = io.CopyN(io.Discard, r, int64(nmethods))
				// no-auth reply
				_, _ = c.Write([]byte{0x05, 0x00})

				// request: VER CMD RSV ATYP ADDR PORT
				header := make([]byte, 4)
				if _, err := io.ReadFull(r, header); err != nil {
					return
				}
				if header[1] != 0x01 { // только CONNECT
					_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				switch header[3] {
				case 0x01: // IPv4
					_, _ = io.CopyN(io.Discard, r, 4)
				case 0x03: // domain
					l, _ := r.ReadByte()
					_, _ = io.CopyN(io.Discard, r, int64(l))
				case 0x04: // IPv6
					_, _ = io.CopyN(io.Discard, r, 16)
				}
				var port uint16
				_ = binary.Read(r, binary.BigEndian, &port)

				// Успех — подключаемся к реальному echo-адресу (тестовому
				// upstream-серверу), игнорируя запрошенный адрес: для
				// теста важно доказать сам факт прохождения через SOCKS5,
				// а не полную адресацию.
				upstream, err := net.Dial("tcp", echoAddr)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()

				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				atomic.AddInt32(&count, 1)

				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, r); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &count
}

func TestDialUpstreamThroughSOCKS5(t *testing.T) {
	// echo-сервер — "настоящий" upstream, к которому в реальности пойдёт
	// запрос tg-ws-proxy (в тесте — просто эхо байт для проверки, что
	// данные реально прошли по цепочке client -> SOCKS5 -> upstream).
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 5)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write(buf)
			}(c)
		}
	}()

	socksAddr, hits := minimalSOCKS5Server(t, echoLn.Addr().String())

	cfg := &Config{OutboundProxy: "socks5://" + socksAddr}
	dialer, err := buildOutboundDialer(cfg.OutboundProxy)
	if err != nil {
		t.Fatalf("buildOutboundDialer failed: %v", err)
	}
	cfg.outboundDialer = dialer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialUpstream(ctx, cfg, "tcp", "203.0.113.1:443", 5*time.Second)
	if err != nil {
		t.Fatalf("dialUpstream via SOCKS5 failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through proxy failed: %v", err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read through proxy failed: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("echo mismatch: got %q", resp)
	}
	if atomic.LoadInt32(hits) < 1 {
		t.Fatal("expected at least one connection to pass through the SOCKS5 server, but none did " +
			"— dialUpstream is not actually routing through the configured proxy")
	}
}

func TestDialUpstreamWithoutProxyIsDirect(t *testing.T) {
	// cfg == nil (или OutboundProxy не задан) — dialUpstream должен
	// вести себя как раньше (прямой TCP), не ломая обратную
	// совместимость для всех, кто не настраивал --outbound-proxy.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo listener: %v", err)
	}
	defer echoLn.Close()
	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 2)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write(buf)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialUpstream(ctx, nil, "tcp", echoLn.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("direct dialUpstream (no cfg) failed: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

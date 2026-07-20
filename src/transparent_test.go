package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"
)

func makeDirectHandshake(t *testing.T, tag []byte, dc int16) []byte {
	t.Helper()
	plain := make([]byte, handshakeLen)
	for i := range plain {
		plain[i] = byte(i + 1)
	}
	plain[0] = 0x11
	copy(plain[protoTagPos:protoTagPos+4], tag)
	binary.LittleEndian.PutUint16(plain[dcIdxPos:dcIdxPos+2], uint16(dc))
	key := plain[skipLen : skipLen+prekeyLen]
	iv := plain[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, handshakeLen)
	stream.XORKeyStream(encrypted, plain)
	frame := append([]byte(nil), plain...)
	copy(frame[protoTagPos:], encrypted[protoTagPos:])
	return frame
}

func TestTryDirectHandshake(t *testing.T) {
	frame := makeDirectHandshake(t, protoTagIntermediate, -4)
	hi, ok := tryDirectHandshake(frame)
	if !ok {
		t.Fatal("direct handshake was rejected")
	}
	if !hi.Direct || hi.DC != 4 || !hi.IsMedia || !bytes.Equal(hi.ProtoTag, protoTagIntermediate) {
		t.Fatalf("unexpected handshake info: %+v", hi)
	}
}

func TestTryDirectHandshakeRejectsMTProxySecretDerivation(t *testing.T) {
	frame := makeDirectHandshake(t, protoTagAbridged, 2)
	if _, ok := tryHandshake(frame, []byte("0123456789abcdef")); ok {
		t.Fatal("direct handshake must not validate as a secret-bound MTProxy handshake")
	}
}

func TestBuildDirectCiphersClientDirection(t *testing.T) {
	frame := makeDirectHandshake(t, protoTagSecure, 2)
	hi, ok := tryDirectHandshake(frame)
	if !ok {
		t.Fatal("direct handshake was rejected")
	}
	relayInit := generateRelayInit(hi.ProtoTag, 2)
	cltDec, _, _, _, err := buildDirectCiphers(hi.ClientDecI, relayInit)
	if err != nil {
		t.Fatal(err)
	}

	key := hi.ClientDecI[:prekeyLen]
	iv := hi.ClientDecI[prekeyLen:]
	block, _ := aes.NewCipher(key)
	clientSend := cipher.NewCTR(block, iv)
	advance := make([]byte, handshakeLen)
	clientSend.XORKeyStream(advance, advance)
	plain := []byte("telegram payload")
	encrypted := make([]byte, len(plain))
	clientSend.XORKeyStream(encrypted, plain)
	cltDec.XORKeyStream(encrypted, encrypted)
	if !bytes.Equal(encrypted, plain) {
		t.Fatalf("decrypted payload = %q, want %q", encrypted, plain)
	}
}

func TestTransparentDCResolver(t *testing.T) {
	resolver, err := newTransparentDCResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip         string
		handshake  int
		wantDC     int
		wantSource string
	}{
		{"149.154.167.91", 2, 4, "destination"},
		{"149.154.167.42", 0, 2, "destination"},
		{"91.108.5.1", 0, 4, "destination"},
		{"203.0.113.1", 5, 5, "handshake"},
	}
	for _, tc := range cases {
		dc, source, ok := resolver.resolve(net.ParseIP(tc.ip), tc.handshake)
		if !ok || dc != tc.wantDC || source != tc.wantSource {
			t.Fatalf("resolve(%s,%d) = (%d,%q,%v), want (%d,%q,true)", tc.ip, tc.handshake, dc, source, ok, tc.wantDC, tc.wantSource)
		}
	}
}

func TestTransparentDCOverrideWins(t *testing.T) {
	resolver, err := newTransparentDCResolver([]string{"3:149.154.167.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	dc, _, ok := resolver.resolve(net.ParseIP("149.154.167.91"), 0)
	if !ok || dc != 3 {
		t.Fatalf("override resolved to DC%d, ok=%v; want DC3", dc, ok)
	}
}

func TestParseTransparentDCMapIPv6(t *testing.T) {
	entry, err := parseTransparentDCMap("2:2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	if entry.dc != 2 || !entry.net.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatalf("unexpected mapping: %+v", entry)
	}
}

func TestReservedTransparentPrefix(t *testing.T) {
	for _, head := range [][]byte{[]byte("GET "), []byte("POST"), {0, 0, 0, 0}, {0xef, 1, 2, 3}} {
		if !isReservedTransparentPrefix(head) {
			t.Fatalf("prefix %x should be reserved", head)
		}
	}
	if isReservedTransparentPrefix([]byte{1, 2, 3, 4}) {
		t.Fatal("random prefix should not be reserved")
	}
}

func TestTransparentListenNetwork(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:12345": "tcp4",
		"[::]:12345":    "tcp6",
		":12345":        "tcp4",
	}
	for addr, want := range cases {
		got, err := transparentListenNetwork(addr)
		if err != nil || got != want {
			t.Fatalf("network(%q) = %q, %v; want %q", addr, got, err, want)
		}
	}
}

func TestParseTransparentFlags(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--secret", "00112233445566778899aabbccddeeff",
		"--transparent-listen", "0.0.0.0:1444",
		"--transparent-fail-open=false",
		"--transparent-dc-map", "3:203.0.113.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TransparentListen) != 1 || cfg.TransparentListen[0] != "0.0.0.0:1444" || cfg.TransparentFailOpen {
		t.Fatalf("unexpected transparent config: %+v", cfg)
	}
	if len(cfg.TransparentDCMap) != 1 || cfg.TransparentDCMap[0] != "3:203.0.113.0/24" {
		t.Fatalf("transparent DC map = %v", cfg.TransparentDCMap)
	}
}

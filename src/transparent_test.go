package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
)

func craftDirectHandshake(t *testing.T, protoTag []byte, dcIdx int16) []byte {
	t.Helper()
	handshake := make([]byte, handshakeLen)
	if _, err := rand.Read(handshake[:protoTagPos]); err != nil {
		t.Fatal(err)
	}

	key := handshake[skipLen : skipLen+prekeyLen]
	iv := handshake[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.NewCTR(block, iv)
	keystream := make([]byte, handshakeLen)
	stream.XORKeyStream(keystream, handshake)

	desired := make([]byte, 8)
	copy(desired[:4], protoTag)
	binary.LittleEndian.PutUint16(desired[4:6], uint16(dcIdx))
	for i := 0; i < len(desired); i++ {
		handshake[protoTagPos+i] = desired[i] ^ keystream[protoTagPos+i]
	}
	return handshake
}

func TestTryDirectHandshake(t *testing.T) {
	handshake := craftDirectHandshake(t, protoTagIntermediate, -4)
	hi, ok := tryDirectHandshake(handshake)
	if !ok {
		t.Fatal("expected valid direct obfuscated2 handshake")
	}
	if hi.DC != 4 || !hi.IsMedia {
		t.Fatalf("DC=%d media=%v, want DC=4 media", hi.DC, hi.IsMedia)
	}
	if !hi.Direct {
		t.Fatal("direct handshake must be marked as direct")
	}
	if !bytes.Equal(hi.ProtoTag, protoTagIntermediate) {
		t.Fatalf("proto tag=%x", hi.ProtoTag)
	}

	bad := craftDirectHandshake(t, []byte{1, 2, 3, 4}, 2)
	if _, ok := tryDirectHandshake(bad); ok {
		t.Fatal("unsupported transport tag must be rejected")
	}
}

func TestBuildDirectCiphersTranscodeRoundTrip(t *testing.T) {
	clientDecI := make([]byte, prekeyLen+ivLen)
	relayInit := make([]byte, handshakeLen)
	_, _ = rand.Read(clientDecI)
	_, _ = rand.Read(relayInit)

	cltDec, _, tgEnc, _, err := buildCiphers(clientDecI, relayInit, nil)
	if err != nil {
		t.Fatal(err)
	}
	peerCltDec, _, peerTgEnc, _, err := buildDirectCiphers(clientDecI, relayInit)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("transparent MTProto payload")
	encoded := make([]byte, len(plain))
	peerCltDec.XORKeyStream(encoded, plain)
	cltDec.XORKeyStream(encoded, encoded)
	tgEnc.XORKeyStream(encoded, encoded)
	peerTgEnc.XORKeyStream(encoded, encoded)
	if !bytes.Equal(encoded, plain) {
		t.Fatalf("transcode mismatch: got %x want %x", encoded, plain)
	}
}

func TestParseTransparentDCRules(t *testing.T) {
	rules, err := parseTransparentDCRules([]string{
		"2=149.154.167.0/24",
		"4=2001:67c:4e8:f004::/64",
		"203=91.105.192.100",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("len=%d, want 3", len(rules))
	}
	if !rules[0].Network.Contains(net.ParseIP("149.154.167.91")) {
		t.Fatal("IPv4 rule does not contain expected address")
	}
	if !rules[1].Network.Contains(net.ParseIP("2001:67c:4e8:f004::a")) {
		t.Fatal("IPv6 rule does not contain expected address")
	}
	if !rules[2].Network.Contains(net.ParseIP("91.105.192.100")) || rules[2].Network.Contains(net.ParseIP("91.105.192.101")) {
		t.Fatal("single-IP rule must be an exact match")
	}

	for _, invalid := range []string{"2:149.154.167.0/24", "9=149.154.167.0/24", "2=not-an-ip"} {
		if _, err := parseTransparentDCRules([]string{invalid}); err == nil {
			t.Fatalf("expected error for %q", invalid)
		}
	}
}

func TestResolveTransparentDC(t *testing.T) {
	rules, err := parseTransparentDCRules([]string{"4=149.154.166.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{TransparentDCRules: rules}
	hi := &handshakeInfo{DC: 2}

	dc, source, ok := resolveTransparentDC(cfg, net.ParseIP("149.154.166.10"), hi)
	if !ok || dc != 4 || source != "configured destination map" {
		t.Fatalf("mapped result=(%d,%q,%v), want DC4 configured map", dc, source, ok)
	}

	dc, source, ok = resolveTransparentDC(cfg, net.ParseIP("203.0.113.5"), hi)
	if !ok || dc != 2 || source != "obfuscated2 handshake" {
		t.Fatalf("handshake result=(%d,%q,%v), want DC2 handshake", dc, source, ok)
	}

	if _, _, ok := resolveTransparentDC(cfg, net.ParseIP("203.0.113.5"), &handshakeInfo{DC: 99}); ok {
		t.Fatal("unknown destination and invalid handshake DC must not resolve")
	}
}

func TestParseFlagsTransparent(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--secret", "0123456789abcdef0123456789abcdef",
		"--transparent-listen", "0.0.0.0:16080",
		"--transparent-bypass-mark", "0x4100",
		"--transparent-dc-map", "2=149.154.167.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TransparentListen != "0.0.0.0:16080" || cfg.TransparentBypassMark != 0x4100 || !cfg.TransparentFailOpen {
		t.Fatalf("unexpected transparent config: %+v", cfg)
	}
	if len(cfg.TransparentDCRules) != 1 {
		t.Fatalf("transparent DC rules=%d, want 1", len(cfg.TransparentDCRules))
	}

	if _, err := parseFlags([]string{
		"--secret", "0123456789abcdef0123456789abcdef",
		"--transparent-listen", "bad-address",
	}); err == nil {
		t.Fatal("invalid transparent listen address must be rejected")
	}
}

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"
)

func makeDirectHandshake(t *testing.T, protoTag []byte, dcIdx int16) []byte {
	t.Helper()

	plain := make([]byte, handshakeLen)
	for i := range plain {
		plain[i] = byte(i + 1)
	}
	copy(plain[protoTagPos:protoTagPos+4], protoTag)
	binary.LittleEndian.PutUint16(plain[dcIdxPos:dcIdxPos+2], uint16(dcIdx))

	key := plain[skipLen : skipLen+prekeyLen]
	iv := plain[skipLen+prekeyLen : skipLen+prekeyLen+ivLen]
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, handshakeLen)
	stream.XORKeyStream(encrypted, plain)

	result := append([]byte(nil), plain...)
	copy(result[protoTagPos:], encrypted[protoTagPos:])
	return result
}

func TestTryDirectHandshake(t *testing.T) {
	hs := makeDirectHandshake(t, protoTagIntermediate, -4)
	hi, ok := tryDirectHandshake(hs)
	if !ok {
		t.Fatal("expected valid direct obfuscated2 handshake")
	}
	if !hi.Direct {
		t.Fatal("direct handshake must set Direct")
	}
	if hi.DC != 4 || !hi.IsMedia {
		t.Fatalf("DC=%d media=%v, want DC=4 media", hi.DC, hi.IsMedia)
	}
	if !bytes.Equal(hi.ProtoTag, protoTagIntermediate) {
		t.Fatalf("proto tag = %x, want %x", hi.ProtoTag, protoTagIntermediate)
	}
}

func TestTryDirectHandshakeRejectsSecretHandshake(t *testing.T) {
	secret := []byte("0123456789abcdef")
	hs := craftHandshake(t, secret, protoTagIntermediate, 2)
	if _, ok := tryDirectHandshake(hs); ok {
		t.Fatal("direct decoder must reject a secret-derived MTProxy handshake")
	}
}

func TestDirectClientCipherRoundTrip(t *testing.T) {
	hs := makeDirectHandshake(t, protoTagSecure, 2)
	hi, ok := tryDirectHandshake(hs)
	if !ok {
		t.Fatal("expected valid direct handshake")
	}

	relayInit := generateRelayInit(hi.ProtoTag, signedDC(hi.DC, hi.IsMedia))
	serverDec, serverEnc, _, _, err := buildDirectCiphers(hi.ClientDecI, relayInit)
	if err != nil {
		t.Fatal(err)
	}

	clientKey := hi.ClientDecI[:prekeyLen]
	clientIV := hi.ClientDecI[prekeyLen:]
	block, err := aes.NewCipher(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientSend := cipher.NewCTR(block, clientIV)
	clientSend.XORKeyStream(make([]byte, handshakeLen), make([]byte, handshakeLen))

	upPlain := []byte("direct Telegram payload")
	upEncrypted := make([]byte, len(upPlain))
	clientSend.XORKeyStream(upEncrypted, upPlain)
	serverDec.XORKeyStream(upEncrypted, upEncrypted)
	if !bytes.Equal(upEncrypted, upPlain) {
		t.Fatalf("client-to-proxy round trip = %q, want %q", upEncrypted, upPlain)
	}

	reversed := reverseBytes(hi.ClientDecI)
	clientRecvBlock, err := aes.NewCipher(reversed[:prekeyLen])
	if err != nil {
		t.Fatal(err)
	}
	clientRecv := cipher.NewCTR(clientRecvBlock, reversed[prekeyLen:])

	downPlain := []byte("Telegram response")
	downEncrypted := make([]byte, len(downPlain))
	serverEnc.XORKeyStream(downEncrypted, downPlain)
	clientRecv.XORKeyStream(downEncrypted, downEncrypted)
	if !bytes.Equal(downEncrypted, downPlain) {
		t.Fatalf("proxy-to-client round trip = %q, want %q", downEncrypted, downPlain)
	}
}

func TestTransparentDCForIP(t *testing.T) {
	cfg := &Config{
		DCMap: map[int]string{4: "149.154.167.91"},
		DCPool: map[int][]string{
			4: {"149.154.167.91"},
		},
	}

	dc, ok := transparentDCForIP(cfg, net.ParseIP("149.154.167.91"))
	if !ok || dc != 4 {
		t.Fatalf("transparentDCForIP = (%d, %v), want (4, true)", dc, ok)
	}

	cfg.DCPool[2] = []string{"149.154.167.91"}
	if dc, ok := transparentDCForIP(cfg, net.ParseIP("149.154.167.91")); ok {
		t.Fatalf("ambiguous destination resolved to DC%d", dc)
	}
}

func TestTransparentDCForIPRange(t *testing.T) {
	cases := []struct {
		ip   string
		dc   int
		want bool
	}{
		{ip: "149.154.167.222", dc: 2, want: true},
		{ip: "149.154.166.121", dc: 4, want: true},
		{ip: "91.108.4.140", dc: 4, want: true},
		{ip: "2001:67c:4e8:f002::a", dc: 2, want: true},
		{ip: "149.154.162.123", want: false},
		{ip: "8.8.8.8", want: false},
	}
	for _, tc := range cases {
		dc, ok := transparentDCForIPRange(net.ParseIP(tc.ip))
		if ok != tc.want || (ok && dc != tc.dc) {
			t.Errorf("transparentDCForIPRange(%s) = (%d, %v), want (%d, %v)", tc.ip, dc, ok, tc.dc, tc.want)
		}
	}
}

func TestReservedTransparentPrefix(t *testing.T) {
	for _, prefix := range [][]byte{
		[]byte("HEAD"),
		[]byte("POST"),
		[]byte("GET "),
		{0xee, 0xee, 0xee, 0xee},
		{0xef, 0x01, 0x02, 0x03},
	} {
		if !reservedTransparentPrefix(prefix) {
			t.Errorf("prefix %x should be reserved", prefix)
		}
	}
	if reservedTransparentPrefix([]byte{1, 2, 3, 4}) {
		t.Fatal("ordinary obfuscated prefix marked reserved")
	}
}

func TestValidTransparentDC(t *testing.T) {
	for _, dc := range []int{1, 2, 3, 4, 5, -4, 203} {
		if !validTransparentDC(dc) {
			t.Errorf("DC%d should be valid", dc)
		}
	}
	for _, dc := range []int{0, 6, 202, 204} {
		if validTransparentDC(dc) {
			t.Errorf("DC%d should be invalid", dc)
		}
	}
}

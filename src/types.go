package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Host                         string
	Port                         int
	PrintCapabilities            bool
	NoMTProxyListener            bool
	OutboundMark                 uint32
	SecretHex                    string
	GenSecret                    bool
	PrintLink                    bool
	FakeTLSDomain                string
	DCMap                        map[int]string
	DCPool                       map[int][]string
	FallbackCFProxy              bool
	FallbackCFProxyPriority      bool
	FallbackCFProxyDomain        string
	FallbackCFProxyUserDomain    bool
	FallbackCFProxyRefresh       bool
	FallbackCFProxyDomainsURL    string
	FallbackCFProxyDomains       []string
	FallbackCFProxyWorkerDomains []string
	FallbackCFProxyActive        string
	FallbackCFProxyPerDCActive   map[int]string
	Verbose                      bool
	BufKB                        int
	PoolSize                     int
	MaxConns                     int
	LogFile                      string
	LogMaxMB                     float64
	LogBackups                   int
	PprofListen                  string
	TransparentListen            []string
	TransparentFailOpen          bool
	TransparentDCMap             []string
	cfproxyMu                    sync.RWMutex
	cfproxyFailUntil             map[string]time.Time
}

type Stats struct {
	connectionsTotal       int64
	connectionsActive      int64
	connectionsTransparent int64
	connectionsWS          int64
	connectionsTCP         int64
	connectionsCF          int64
	connectionsFront       int64
	connectionsBad         int64
	wsErrors               int64
	bytesUp                int64
	bytesDown              int64
	poolHits               int64
	poolMisses             int64
}

func (s *Stats) summary() string {
	hits := atomic.LoadInt64(&s.poolHits)
	misses := atomic.LoadInt64(&s.poolMisses)
	poolTotal := hits + misses
	poolS := "n/a"
	if poolTotal > 0 {
		poolS = fmt.Sprintf("%d/%d", hits, poolTotal)
	}
	return fmt.Sprintf(
		"total=%d active=%d transparent=%d ws=%d tcp_fb=%d cf=%d front=%d bad=%d err=%d pool=%s up=%s down=%s",
		atomic.LoadInt64(&s.connectionsTotal),
		atomic.LoadInt64(&s.connectionsActive),
		atomic.LoadInt64(&s.connectionsTransparent),
		atomic.LoadInt64(&s.connectionsWS),
		atomic.LoadInt64(&s.connectionsTCP),
		atomic.LoadInt64(&s.connectionsCF),
		atomic.LoadInt64(&s.connectionsFront),
		atomic.LoadInt64(&s.connectionsBad),
		atomic.LoadInt64(&s.wsErrors),
		poolS,
		humanBytes(atomic.LoadInt64(&s.bytesUp)),
		humanBytes(atomic.LoadInt64(&s.bytesDown)),
	)
}

type handshakeInfo struct {
	DC         int
	IsMedia    bool
	ProtoTag   []byte
	ClientDecI []byte
	Direct     bool
}

type dcKey struct {
	DC      int
	IsMedia bool
}

type dcMapItem struct {
	dc int
	ip string
}

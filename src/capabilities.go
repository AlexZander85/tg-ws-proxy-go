package main

import (
	"encoding/json"
	"io"
	"runtime"
)

const capabilitiesSchemaVersion = 1

type capabilityFeatures struct {
	TransparentMTProtoBridge  bool `json:"transparent_mtproto_bridge"`
	TransparentMultiListener  bool `json:"transparent_multi_listener"`
	TransparentFailOpen       bool `json:"transparent_fail_open"`
	TransparentDCMapOverrides bool `json:"transparent_dc_map_overrides"`
	OptionalMTProxyListener   bool `json:"optional_mtproxy_listener"`
	OutboundSocketMark        bool `json:"outbound_so_mark"`
}

type capabilityDocument struct {
	Schema      int                `json:"schema"`
	Program     string             `json:"program"`
	GOOS        string             `json:"goos"`
	Features    capabilityFeatures `json:"features"`
	Flags       []string           `json:"flags"`
	Transparent struct {
		DefaultDCMap []string `json:"default_dc_map"`
	} `json:"transparent"`
}

func currentCapabilities() capabilityDocument {
	linux := runtime.GOOS == "linux"
	doc := capabilityDocument{
		Schema:  capabilitiesSchemaVersion,
		Program: "tg-ws-proxy",
		GOOS:    runtime.GOOS,
		Features: capabilityFeatures{
			TransparentMTProtoBridge:  linux,
			TransparentMultiListener:  linux,
			TransparentFailOpen:       linux,
			TransparentDCMapOverrides: linux,
			OptionalMTProxyListener:   true,
			OutboundSocketMark:        linux,
		},
		Flags: []string{
			"--capabilities",
			"--transparent-listen",
			"--transparent-fail-open",
			"--transparent-dc-map",
			"--no-mtproxy-listener",
			"--outbound-mark",
		},
	}
	doc.Transparent.DefaultDCMap = append([]string(nil), defaultTransparentDCMap...)
	return doc
}

func writeCapabilities(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(currentCapabilities())
}

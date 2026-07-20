package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

func TestCapabilitiesJSON(t *testing.T) {
	var out bytes.Buffer
	if err := writeCapabilities(&out); err != nil {
		t.Fatal(err)
	}
	var doc capabilityDocument
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid capabilities JSON: %v", err)
	}
	if doc.Schema != capabilitiesSchemaVersion || doc.Program != "tg-ws-proxy" {
		t.Fatalf("unexpected capabilities header: %+v", doc)
	}
	if doc.GOOS != runtime.GOOS {
		t.Fatalf("goos = %q, want %q", doc.GOOS, runtime.GOOS)
	}
	linux := runtime.GOOS == "linux"
	if doc.Features.TransparentMTProtoBridge != linux || doc.Features.OutboundSocketMark != linux {
		t.Fatalf("platform capabilities = %+v, linux=%v", doc.Features, linux)
	}
	if !doc.Features.OptionalMTProxyListener {
		t.Fatal("optional MTProxy listener capability is missing")
	}
	if len(doc.Transparent.DefaultDCMap) != len(defaultTransparentDCMap) {
		t.Fatalf("default DC map length = %d, want %d", len(doc.Transparent.DefaultDCMap), len(defaultTransparentDCMap))
	}
	if len(doc.Flags) == 0 || doc.Flags[0] != "--capabilities" {
		t.Fatalf("unexpected flags: %v", doc.Flags)
	}
}

func TestCapabilitiesDefaultDCMapIsCopied(t *testing.T) {
	doc := currentCapabilities()
	doc.Transparent.DefaultDCMap[0] = "changed"
	if defaultTransparentDCMap[0] == "changed" {
		t.Fatal("capabilities mutated the package default DC map")
	}
}

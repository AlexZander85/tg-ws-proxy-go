package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// maxMB tiny -> clamped to 32KB minimum.
	w := newRotatingWriter(f, path, 0.001, 2)
	defer func() { _ = w.f.Close() }() // release handle so Windows TempDir cleanup can unlink

	line := make([]byte, 2000)
	for i := 0; i < 200; i++ { // ~400KB, rotation checked every 32 writes
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated backup %s.1 to exist: %v", path, err)
	}
	// Current log file must still exist and be smaller than total written.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() >= 400000 {
		t.Errorf("active log not rotated, size=%d", st.Size())
	}
}

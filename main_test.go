package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestUsage(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	usage()

	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Usage:") {
		t.Errorf("usage output missing 'Usage:', got %q", output)
	}
	if !strings.Contains(output, "-u") {
		t.Errorf("usage output missing flags, got %q", output)
	}
}

func TestUsageContainsCreateFlags(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	usage()

	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	for _, flag := range []string{"-c", "--create", "-cs", "--size", "-ck", "--create-key-file", "-cks", "--key-size"} {
		if !strings.Contains(output, flag) {
			t.Errorf("usage output missing %q", flag)
		}
	}
}

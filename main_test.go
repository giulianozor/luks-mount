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

	for _, flag := range []string{"-c", "--create", "-cs", "--size", "-ck", "--create-key-file", "-cks", "--key-size", "-k"} {
		if !strings.Contains(output, flag) {
			t.Errorf("usage output missing %q", flag)
		}
	}

	// The create example must document both key options: a generated key file
	// (-ck) and an existing key (-k), which the create path accepts.
	var createLines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "lmount -c <name>") {
			createLines = append(createLines, line)
		}
	}
	if len(createLines) != 1 {
		t.Fatalf("expected one create example line, got %v", createLines)
	}
	if !strings.Contains(createLines[0], "-k <keyfile>") {
		t.Errorf("create example should document the -k alternative, got %q", createLines[0])
	}
}

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

func TestLinuxOnlyError(t *testing.T) {
	oldGOOS := goos
	defer func() { goos = oldGOOS }()

	goos = "linux"
	if err := linuxOnlyError(); err != nil {
		t.Errorf("linuxOnlyError() on linux = %v, want nil", err)
	}

	goos = "darwin"
	err := linuxOnlyError()
	if err == nil {
		t.Fatal("linuxOnlyError() on darwin = nil, want an error")
	}
	if !strings.Contains(err.Error(), "Linux-only") || !strings.Contains(err.Error(), "darwin") {
		t.Errorf("linuxOnlyError() should name the OS and Linux-only, got %v", err)
	}
}

// captureStderr runs fn with os.Stderr redirected and returns what fn wrote to
// stderr, restoring the original descriptor afterwards.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	return captureFd(t, &os.Stderr, fn)
}

// captureStdout runs fn with os.Stdout redirected and returns what fn wrote to
// stdout, restoring the original descriptor afterwards.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	return captureFd(t, &os.Stdout, fn)
}

func captureFd(t *testing.T, fd **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := *fd
	*fd = w
	defer func() { *fd = old }()
	fn()
	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

// TestRunMain exercises runMain's argument validation entirely before any
// operation runs, so no privileged command (sudo cryptsetup, mount, dd) is ever
// reached. A runMain call accepts args only to the point of returning.
func TestRunMain(t *testing.T) {
	// runMain's validation only runs on Linux; lmount is Linux-only and
	// linuxOnlyError() would otherwise short-circuit every branch.
	oldGOOS := goos
	goos = "linux"
	defer func() { goos = oldGOOS }()

	tests := []struct {
		name        string
		args        []string
		code        int
		want        string
		wantsStdout bool
	}{
		{"help short", []string{"-h"}, 0, "Usage:", true},
		{"help long", []string{"--help"}, 0, "Usage:", true},
		{"no operation shows usage", []string{}, 1, "Usage:", false},
		{"unknown flag", []string{"-bogus"}, 1, "flag provided but not defined", false},
		{"two operations", []string{"-s", "/dev/x", "-u", "/dev/x"}, 1, "only one of", false},
		{"mount without source", []string{"-m", "/mnt"}, 1, "only valid with -s/--source", false},
		{"size without create", []string{"-cs", "100M"}, 1, "only valid with -c/--create", false},
		{"create-key-file without create", []string{"-ck", "/key"}, 1, "only valid with -c/--create", false},
		{"key-size without create", []string{"-cks", "1024"}, 1, "only valid with -c/--create", false},
		{"key-size without create-key-file", []string{"-c", "img", "-cs", "32M", "-cks", "1024"}, 1, "only valid with -ck", false},
		{"long key-size without create-key-file", []string{"-c", "img", "-cs", "32M", "--key-size", "1024"}, 1, "only valid with -ck", false},
		{"create without size", []string{"-c", "img"}, 1, "required with -c/--create", false},
		{"expand-size without expand", []string{"-xs", "1G"}, 1, "only valid with -x/--expand", false},
		{"expand without size", []string{"-x", "/tmp/x.img"}, 1, "required with -x/--expand", false},
		{"create key conflicts", []string{"-c", "img", "-cs", "32M", "-k", "/k", "-ck", "/k2"}, 1, "cannot be used together", false},
		{"umount with key rejected", []string{"-u", "/dev/x", "-k", "/k"}, 1, "not valid with -u/--umount", false},
		// These reach expand/umount but fail on the missing path before any
		// privileged probe or command runs.
		{"expand missing container", []string{"-x", "/nonexistent/lmount-test.img", "-xs", "1G"}, 1, "stat /nonexistent/lmount-test.img", false},
		{"umount missing source", []string{"-u", "/nonexistent/lmount-test.img"}, 1, "does not exist", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capture := captureStderr
			if tc.wantsStdout {
				capture = captureStdout
			}
			got := capture(t, func() {
				code := runMain(tc.args)
				if code != tc.code {
					t.Errorf("runMain(%v) = %d, want %d", tc.args, code, tc.code)
				}
			})
			if !strings.Contains(got, tc.want) {
				t.Errorf("runMain(%v) output missing %q, got %q", tc.args, tc.want, got)
			}
		})
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

func TestUsageDocumentsKeySizeRequiresCreateKeyFile(t *testing.T) {
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

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "-cks, --key-size") {
			if !strings.Contains(line, "only with -ck") {
				t.Errorf("-cks help should say it needs -ck, got %q", line)
			}
			return
		}
	}
	t.Error("usage output does not document -cks/--key-size at all")
}

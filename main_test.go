package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
	if !strings.Contains(output, "-no-passphrase") {
		t.Errorf("usage output must advertise -no-passphrase, got %q", output)
	}
	if !strings.Contains(output, "requires -ck or -k") {
		t.Errorf("usage output must state the -no-passphrase key requirement, got %q", output)
	}
	if !strings.Contains(output, "minimum 32M") {
		t.Errorf("usage output must advertise the 32M container minimum, got %q", output)
	}
	if !strings.Contains(output, "max 8192") {
		t.Errorf("usage output must advertise the 8192-byte key cap, got %q", output)
	}
	if !strings.Contains(output, "127 bytes") {
		t.Errorf("usage output must advertise the 127-byte mapping-name limit, got %q", output)
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
		notWant     string
	}{
		{"help short", []string{"-h"}, 0, "Usage:", true, ""},
		{"help long", []string{"--help"}, 0, "Usage:", true, ""},
		{"help wins over an operation", []string{"-c", "img", "-cs", "32M", "-h"}, 0, "Usage:", true, ""},
		{"long help wins over an operation", []string{"-s", "/dev/x", "-m", "/mnt", "--help"}, 0, "Usage:", true, ""},
		{"no operation shows usage", []string{}, 1, "Usage:", false, ""},
		{"unknown flag", []string{"-bogus"}, 1, "flag provided but not defined", false, ""},
		{"two operations", []string{"-s", "/dev/x", "-u", "/dev/x"}, 1, "only one of", false, ""},
		{"mount without source", []string{"-m", "/mnt"}, 1, "only valid with -s/--source", false, ""},
		{"empty short mount with source", []string{"-s", "/dev/x", "-m", ""}, 1, "-m/--mount must not be empty", false, ""},
		{"empty long mount with source", []string{"-s", "/dev/x", "--mount", ""}, 1, "-m/--mount must not be empty", false, ""},
		{"empty mount without source", []string{"-m", ""}, 1, "-m/--mount must not be empty", false, ""},
		{"size without create", []string{"-cs", "100M"}, 1, "only valid with -c/--create", false, ""},
		{"create-key-file without create", []string{"-ck", "/key"}, 1, "only valid with -c/--create", false, ""},
		{"key-size without create", []string{"-cks", "1024"}, 1, "only valid with -c/--create", false, ""},
		{"key-size without create-key-file", []string{"-c", "img", "-cs", "32M", "-cks", "1024"}, 1, "only valid with -ck", false, ""},
		{"long key-size without create-key-file", []string{"-c", "img", "-cs", "32M", "--key-size", "1024"}, 1, "only valid with -ck", false, ""},
		{"create without size", []string{"-c", "img"}, 1, "required with -c/--create", false, ""},
		{"long create without size", []string{"--create", "img"}, 1, "required with -c/--create", false, ""},
		{"long size without create", []string{"--size", "100M"}, 1, "only valid with -c/--create", false, ""},
		{"expand-size without expand", []string{"-xs", "1G"}, 1, "only valid with -x/--expand", false, ""},
		{"key-size nothing", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "100"}, 1, "must be a positive multiple of 8", false, ""},
		{"zero key-size", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "0"}, 1, "must be a positive multiple of 8", false, ""},
		{"negative key-size", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "-8"}, 1, "must be a positive multiple of 8", false, ""},
		{"key-size overflows an int", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "99999999999999999999"}, 1, "invalid value", false, ""},
		{"long key-size nothing", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "--key-size", "100"}, 1, "must be a positive multiple of 8", false, ""},
		{"key-size above the cryptsetup read limit", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "9216"}, 1, "at most 8192 bytes", false, ""},
		{"long key-size above the cryptsetup read limit", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "--key-size", "8193"}, 1, "at most 8192 bytes", false, ""},
		{"expand without size", []string{"-x", "/tmp/x.img"}, 1, "required with -x/--expand", false, ""},
		{"long expand without size", []string{"--expand", "/tmp/x.img"}, 1, "required with -x/--expand", false, ""},
		{"long mount without source", []string{"--mount", "/mnt/x"}, 1, "only valid with -s/--source", false, ""},
		{"mount with key on source only", []string{"-s", "/dev/__test_dev__", "--key", "/k"}, 1, "not LUKS; -k/--key is not valid", false, ""},
		{"create key conflicts", []string{"-c", "img", "-cs", "32M", "-k", "/k", "-ck", "/k2"}, 1, "cannot be used together", false, ""},
		{"no-passphrase without create", []string{"-x", "/tmp/x.img", "-xs", "1G", "-no-passphrase"}, 1, "only valid with -c/--create", false, ""},
		{"no-passphrase with umount", []string{"-u", "/dev/x", "-no-passphrase"}, 1, "only valid with -c/--create", false, ""},
		{"no-passphrase without a key file", []string{"-c", "img", "-cs", "32M", "-no-passphrase"}, 1, "requires -ck/--create-key-file or -k/--key", false, ""},
		{"long no-passphrase without a key file", []string{"-c", "img", "-cs", "32M", "--no-passphrase"}, 1, "requires -ck/--create-key-file or -k/--key", false, ""},
		{"umount with key rejected", []string{"-u", "/dev/x", "-k", "/k"}, 1, "not valid with -u/--umount", false, ""},
		// -m/--mount is rejected for every non-mount operation, not just when
		// it appears alone: create/expand/umount never read it, so a silent
		// drop would discard the user's intent without a trace.
		{"mount point with create rejected", []string{"-c", "img", "-cs", "32M", "-m", "/mnt"}, 1, "only valid with -s/--source", false, ""},
		{"mount point with expand rejected", []string{"-x", "/tmp/x.img", "-xs", "1G", "-m", "/mnt"}, 1, "only valid with -s/--source", false, ""},
		{"long mount point with umount rejected", []string{"-u", "/dev/x", "--mount", "/mnt"}, 1, "only valid with -s/--source", false, ""},
		// -cks demands its own -ck even when a -k key is present.
		{"key-size with a -k key but no -ck rejected", []string{"-c", "img", "-cs", "32M", "-k", "/k", "-cks", "256"}, 1, "only valid with -ck", false, ""},
		// These reach expand/umount but fail on the missing path before any
		// privileged probe or command runs.
		{"expand missing container", []string{"-x", "/nonexistent/lmount-test.img", "-xs", "1G"}, 1, "stat /nonexistent/lmount-test.img", false, ""},
		{"umount missing source", []string{"-u", "/nonexistent/lmount-test.img"}, 1, "does not exist", false, ""},
		{"mount missing source", []string{"-s", "/nonexistent/lmount-test.img"}, 1, "source /nonexistent/lmount-test.img does not exist", false, ""},
		// A positional argument aborts the operation entirely: the "unexpected
		// positional" error is emitted instead of the operation running.
		{"expand with positional argument", []string{"-x", "/nonexistent/lmount-test.img", "-xs", "1G", "extra"}, 1, "unexpected positional argument", false, "stat /nonexistent"},
		{"create with positional argument", []string{"-c", "img", "-cs", "32M", "extra"}, 1, "unexpected positional argument", false, ""},
		{"mount with positional argument", []string{"-s", "/dev/__test_dev__", "extra"}, 1, "unexpected positional argument", false, "stat /dev/__test_dev__"},
		{"umount with positional argument", []string{"-u", "/dev/nope", "extra"}, 1, "unexpected positional argument", false, "source /dev/nope does not exist"},
		{"create with an invalid container name", []string{"-c", "bad name.txt", "-cs", "32M"}, 1, "invalid device-mapper name", false, ""},
		{"create with a leading-dash container name", []string{"-c", "-evil.img", "-cs", "32M"}, 1, "invalid device-mapper name", false, ""},
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
			if tc.notWant != "" && strings.Contains(got, tc.notWant) {
				t.Errorf("runMain(%v) output should not contain %q, got %q", tc.args, tc.notWant, got)
			}
		})
	}
}

func TestRunMainOperationWiring(t *testing.T) {
	oldGOOS := goos
	goos = "linux"
	defer func() { goos = oldGOOS }()

	oldExpand, oldCreate, oldUmount, oldMount := expandOperation, createOperation, umountOperation, mountOperation
	defer func() {
		expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
	}()

	okExpand := func(runSudo, runDirect func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), filename, size, keyFile string) error {
		return nil
	}
	okCreate := func(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int, noPassphrase bool) error {
		return nil
	}
	okUmount := func(checkMapped func(string) bool, runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
		return nil
	}
	okMount := func(runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source, keyFile, mountPoint string) error {
		return nil
	}
	boom := errors.New("boom")
	boomExpand := func(runSudo, runDirect func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), filename, size, keyFile string) error {
		return boom
	}
	boomCreate := func(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int, noPassphrase bool) error {
		return boom
	}
	boomUmount := func(checkMapped func(string) bool, runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
		return boom
	}
	boomMount := func(runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source, keyFile, mountPoint string) error {
		return boom
	}

	success := []struct {
		name string
		args []string
	}{
		{"expand", []string{"-x", "/tmp/lmount-test.img", "-xs", "1G"}},
		{"expand with key", []string{"-x", "/tmp/lmount-test.img", "-xs", "1G", "-k", "/tmp/lmount-key"}},
		{"expand long-form flags", []string{"--expand", "/tmp/lmount-test.img", "--expand-size", "1G", "--key", "/tmp/lmount-key"}},
		{"create", []string{"-c", "/tmp/lmount-test.img", "-cs", "32M"}},
		{"create with key", []string{"-c", "/tmp/lmount-test.img", "-cs", "32M", "-ck", "/tmp/lmount-key"}},
		{"create no-passphrase", []string{"-c", "/tmp/lmount-test.img", "-cs", "32M", "-no-passphrase", "-ck", "/tmp/lmount-key"}},
		{"create with key-size at the cryptsetup read limit", []string{"-c", "/tmp/lmount-test.img", "-cs", "32M", "-ck", "/tmp/lmount-key", "-cks", "8192"}},
		{"create long-form flags", []string{"--create", "/tmp/lmount-test.img", "--size", "32M", "--create-key-file", "/tmp/lmount-key", "--key-size", "256"}},
		{"create long-form key-only", []string{"--create", "/tmp/lmount-test.img", "--size", "32M", "--no-passphrase", "--key", "/tmp/lmount-key"}},
		{"mount", []string{"-s", "/dev/__test_dev__", "-m", "/mnt/x"}},
		{"mount long-form flags", []string{"--source", "/dev/__test_dev__", "--mount", "/mnt/x", "--key", "/tmp/lmount-key"}},
		{"umount", []string{"-u", "/dev/__test_dev__"}},
		{"umount long-form", []string{"--umount", "/dev/__test_dev__"}},
	}
	for _, tc := range success {
		t.Run("success/"+tc.name, func(t *testing.T) {
			expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
			if code := runMain(tc.args); code != 0 {
				t.Errorf("runMain(%v) = %d, want 0", tc.args, code)
			}
		})
	}

	t.Run("success/create forwards no-passphrase", func(t *testing.T) {
		var seenNoPassphrase []bool
		expandOperation, umountOperation, mountOperation = okExpand, okUmount, okMount
		createOperation = func(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int, noPassphrase bool) error {
			seenNoPassphrase = append(seenNoPassphrase, noPassphrase)
			return nil
		}
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()
		if code := runMain([]string{"-c", "/tmp/lmount-test.img", "-cs", "32M", "-no-passphrase", "-ck", "/tmp/lmount-key"}); code != 0 {
			t.Errorf("runMain(no-passphrase create) = %d, want 0", code)
		}
		if code := runMain([]string{"-c", "/tmp/lmount-test.img", "-cs", "32M", "-ck", "/tmp/lmount-key"}); code != 0 {
			t.Errorf("runMain(passphrase create) = %d, want 0", code)
		}
		if len(seenNoPassphrase) != 2 || seenNoPassphrase[0] != true || seenNoPassphrase[1] != false {
			t.Errorf("createOperation invoked with noPassphrase = %v, want [true false]", seenNoPassphrase)
		}
	})

	t.Run("expand's differently-named-mapping probe runs through the privileged seam", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		var gotRunOutput func(name string, args ...string) ([]byte, error)
		expandOperation = func(runSudo, runDirect func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), filename, size, keyFile string) error {
			gotRunOutput = runOutput
			return nil
		}
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()
		if code := runMain([]string{"-x", "/tmp/lmount-test.img", "-xs", "1G"}); code != 0 {
			t.Fatalf("runMain(expand) = %d, want 0", code)
		}
		if gotRunOutput == nil {
			t.Fatal("expandOperation did not receive a runOutput seam")
		}
		// The differently-named-mapping probe reads the dm-slave backing
		// devices' LUKS headers (/dev/loopN), which a user outside the "disk"
		// group cannot open; it must be routed through the privileged runOutput
		// (sudo) seam like umount's, never the unprivileged runOutputDirect
		// reserved for findmnt. An unprivileged probe would silently fail and
		// expand would grow a file still open under a differently-named mapping.
		if reflect.ValueOf(gotRunOutput).Pointer() == reflect.ValueOf(runOutputDirect).Pointer() {
			t.Error("expand's mapping probe must not run through the unprivileged runOutputDirect seam")
		}
		if reflect.ValueOf(gotRunOutput).Pointer() != reflect.ValueOf(runOutput).Pointer() {
			t.Error("expand's mapping probe must run through the privileged runOutput (sudo) seam")
		}
	})

	t.Run("warning on conflicting key-size spellings", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		code := runMain([]string{"-c", "/tmp/lmount-test.img", "-cs", "32M", "-ck", "/tmp/k", "-cks", "128", "--key-size", "256"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if !strings.Contains(buf.String(), "conflict") {
			t.Errorf("expected a -cks/--key-size conflict warning, got %q", buf.String())
		}
		if !strings.Contains(buf.String(), "using -cks (128)") {
			t.Errorf("expected the warning to state the effective -cks value, got %q", buf.String())
		}
	})

	t.Run("warning on conflicting short/long path spellings", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		code := runMain([]string{"-c", "/tmp/lmount-test.img", "--create", "/tmp/other.img", "-cs", "32M"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if !strings.Contains(buf.String(), "-c (/tmp/lmount-test.img) and --create (/tmp/other.img) conflict; using -c (/tmp/lmount-test.img)") {
			t.Errorf("expected a -c/--create conflict warning, got %q", buf.String())
		}
	})

	t.Run("no warning when short and long spellings agree", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		code := runMain([]string{"-c", "/tmp/lmount-test.img", "--create", "/tmp/lmount-test.img", "-cs", "32M"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if strings.Contains(buf.String(), "conflict") {
			t.Errorf("agreement must not warn, got %q", buf.String())
		}
	})

	t.Run("no warning when spellings differ only by normalization", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		code := runMain([]string{"-c", "/tmp/lmount-test.img", "--create", "/tmp/lmount-test.img/", "-cs", "32M"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if strings.Contains(buf.String(), "conflict") {
			t.Errorf("a trailing-separator variant must not warn, got %q", buf.String())
		}
	})

	t.Run("warning when spellings differ only by whitespace", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		code := runMain([]string{"-c", " /tmp/lmount-test.img", "--create", "/tmp/lmount-test.img", "-cs", "32M"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if !strings.Contains(buf.String(), "-c ( /tmp/lmount-test.img) and --create (/tmp/lmount-test.img) conflict; using -c ( /tmp/lmount-test.img)") {
			// The tool resolves the short spelling verbatim (" /tmp/..."),
			// so a whitespace difference is a real conflict, not a styling
			// difference of the same path.
			t.Errorf("expected a whitespace difference to warn, got %q", buf.String())
		}
	})

	t.Run("no warning when a tilde spelling and its expanded mirror agree", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		home := t.TempDir()
		oldHome, hadHome := os.LookupEnv("HOME")
		if err := os.Setenv("HOME", home); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if hadHome {
				os.Setenv("HOME", oldHome)
			} else {
				os.Unsetenv("HOME")
			}
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		// "-c ~/img" and "--create <home>/img" resolve to the same path once
		// home is expanded, so they are not a conflict. The warning must not
		// pretend the two spellings differ just because one uses ~/.
		code := runMain([]string{"-c", "~/lmount-test.img", "--create", filepath.Join(home, "lmount-test.img"), "-cs", "32M"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if strings.Contains(buf.String(), "conflict") {
			t.Errorf("expected no conflict warning for a ~/ spelling matching its expanded mirror, got %q", buf.String())
		}
	})

	t.Run("no warning for size spellings differing only by whitespace", func(t *testing.T) {
		expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
		defer func() {
			expandOperation, createOperation, umountOperation, mountOperation = oldExpand, oldCreate, oldUmount, oldMount
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(&buf, r)
		}()

		// parseSize trims surrounding whitespace, so "-cs 32M" and "--size
		// 32M" (with the space) select the exact same size; warning would be
		// noise, unlike the path flags whose winner is used verbatim.
		code := runMain([]string{"-c", "/tmp/lmount-test.img", "-cs", " 32M", "--size", "32M"})
		os.Stderr = oldStderr
		w.Close()
		<-done
		if code != 0 {
			t.Errorf("runMain = %d, want 0", code)
		}
		if strings.Contains(buf.String(), "conflict") {
			t.Errorf("a whitespace-only size difference must not warn, got %q", buf.String())
		}
	})

	failures := []struct {
		name string
		args []string
	}{
		{"expand", []string{"-x", "/tmp/lmount-test.img", "-xs", "1G"}},
		{"create", []string{"-c", "/tmp/lmount-test.img", "-cs", "32M"}},
		{"umount", []string{"-u", "/dev/__test_dev__"}},
		{"mount", []string{"-s", "/dev/__test_dev__", "-m", "/mnt/x"}},
	}
	for _, tc := range failures {
		t.Run("failure/"+tc.name, func(t *testing.T) {
			switch tc.name {
			case "expand":
				expandOperation, createOperation, umountOperation, mountOperation = boomExpand, okCreate, okUmount, okMount
			case "create":
				expandOperation, createOperation, umountOperation, mountOperation = okExpand, boomCreate, okUmount, okMount
			case "umount":
				expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, boomUmount, okMount
			case "mount":
				expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, boomMount
			}
			got := captureStderr(t, func() {
				if code := runMain(tc.args); code != 1 {
					t.Errorf("runMain(%v) = %d, want 1", tc.args, code)
				}
			})
			if !strings.Contains(got, "Error: boom") {
				t.Errorf("expected the operation error on stderr, got %q", got)
			}
		})
	}

	t.Run("source tilde expansion fails when HOME is unset", func(t *testing.T) {
		oldHome, hadHome := os.LookupEnv("HOME")
		if err := os.Unsetenv("HOME"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if hadHome {
				os.Setenv("HOME", oldHome)
			} else {
				os.Unsetenv("HOME")
			}
		}()

		got := captureStderr(t, func() {
			if code := runMain([]string{"-s", "~/data.img"}); code != 1 {
				t.Errorf("runMain with unset HOME = %d, want 1", code)
			}
		})
		if !strings.Contains(got, "home directory") {
			t.Errorf("expected a home-directory expansion error, got %q", got)
		}
	})
}

func TestRunMainNonLinuxExits(t *testing.T) {
	oldGOOS := goos
	goos = "darwin"
	defer func() { goos = oldGOOS }()

	code := captureStderr(t, func() {
		if got := runMain([]string{"-s", "/dev/x"}); got != 1 {
			t.Errorf("runMain on darwin = %d, want 1", got)
		}
	})
	if !strings.Contains(code, "Linux-only") {
		t.Errorf("expected a Linux-only error, got %q", code)
	}
}

func TestRunMainExpandsMountPointHome(t *testing.T) {
	oldGOOS := goos
	goos = "linux"
	defer func() { goos = oldGOOS }()

	oldHome, hadHome := os.LookupEnv("HOME")
	if err := os.Unsetenv("HOME"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if hadHome {
			os.Setenv("HOME", oldHome)
		} else {
			os.Unsetenv("HOME")
		}
	}()

	code := captureStderr(t, func() {
		if got := runMain([]string{"-s", "/nonexistent/lmount-test.img", "-m", "~/data"}); got != 1 {
			t.Errorf("runMain with unset HOME = %d, want 1", got)
		}
	})
	if !strings.Contains(code, "expanding") || !strings.Contains(code, "home directory") {
		t.Errorf("expected a home-directory expansion error, got %q", code)
	}
}

func TestRunMainExpandsHomeForAllPathFlags(t *testing.T) {
	oldGOOS := goos
	goos = "linux"
	defer func() { goos = oldGOOS }()

	home := t.TempDir()
	oldHome, hadHome := os.LookupEnv("HOME")
	if err := os.Setenv("HOME", home); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if hadHome {
			os.Setenv("HOME", oldHome)
		} else {
			os.Unsetenv("HOME")
		}
	}()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"expand", []string{"-x", "~/ghost.img", "-xs", "1G"}, filepath.Join(home, "ghost.img")},
		{"umount", []string{"-u", "~/ghost"}, filepath.Join(home, "ghost")},
		{"source", []string{"-s", "~/ghost"}, filepath.Join(home, "ghost")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStderr(t, func() {
				if code := runMain(tc.args); code != 1 {
					t.Errorf("runMain(%v) = %d, want 1 (missing file)", tc.args, code)
				}
			})
			if !strings.Contains(out, tc.want) {
				t.Errorf("runMain(%v) output should name the expanded path %q, got %q", tc.args, tc.want, out)
			}
			if strings.Contains(out, "~/") || strings.Contains(out, "~"+string(filepath.Separator)) {
				t.Errorf("runMain(%v) output still contains an unexpanded ~ path: %q", tc.args, out)
			}
		})
	}
}

func TestUsageDocumentsTildeExpansion(t *testing.T) {
	out := captureStdout(t, func() { usageTo(os.Stdout) })
	for _, want := range []string{"Notes:", "leading ~/"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %q", want)
		}
	}
}

func TestUsageFlagColumnAlignment(t *testing.T) {
	out := captureStdout(t, func() { usageTo(os.Stdout) })
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "  -") {
			continue
		}
		// Every flag line is "  " + <flag field, 29 wide> + " " + description,
		// so byte 31 is the separating space and the description starts at 32
		// for every flag (the longest flag field is exactly 29).
		if len(line) < 33 || line[31] != ' ' || line[32] == ' ' {
			t.Errorf("usage flag column misaligned for line %q", line)
		}
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

func TestRunMainStreamRouting(t *testing.T) {
	oldGOOS := goos
	goos = "linux"
	defer func() { goos = oldGOOS }()

	captureBoth := func(fn func()) (string, string) {
		t.Helper()
		rOut, wOut, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		rErr, wErr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldOut, oldErr := os.Stdout, os.Stderr
		os.Stdout, os.Stderr = wOut, wErr
		defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
		fn()
		wOut.Close()
		wErr.Close()
		var so, se bytes.Buffer
		so.ReadFrom(rOut)
		se.ReadFrom(rErr)
		return so.String(), se.String()
	}

	t.Run("help goes to stdout only", func(t *testing.T) {
		stdout, stderr := captureBoth(func() {
			if code := runMain([]string{"-h"}); code != 0 {
				t.Errorf("runMain(-h) = %d, want 0", code)
			}
		})
		if !strings.Contains(stdout, "Usage:") {
			t.Errorf("help usage not on stdout, got %q", stdout)
		}
		if stderr != "" {
			t.Errorf("help must not touch stderr, got %q", stderr)
		}
	})

	t.Run("no arguments shows usage on stderr only", func(t *testing.T) {
		stdout, stderr := captureBoth(func() {
			if code := runMain([]string{}); code != 1 {
				t.Errorf("runMain() = %d, want 1", code)
			}
		})
		if stdout != "" {
			t.Errorf("no-args usage must not touch stdout, got %q", stdout)
		}
		if !strings.Contains(stderr, "Usage:") {
			t.Errorf("no-args usage not on stderr, got %q", stderr)
		}
		if !strings.Contains(stderr, "no operation specified") {
			t.Errorf("no-args must explain why, got %q", stderr)
		}
	})

	t.Run("flag errors go to stderr only", func(t *testing.T) {
		stdout, stderr := captureBoth(func() {
			if code := runMain([]string{"-bogus"}); code != 1 {
				t.Errorf("runMain(-bogus) = %d, want 1", code)
			}
		})
		if stdout != "" {
			t.Errorf("flag error must not touch stdout, got %q", stdout)
		}
		if !strings.Contains(stderr, "flag provided but not defined") {
			t.Errorf("flag error not on stderr, got %q", stderr)
		}
	})
}

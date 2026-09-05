package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
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
		notWant     string
	}{
		{"help short", []string{"-h"}, 0, "Usage:", true, ""},
		{"help long", []string{"--help"}, 0, "Usage:", true, ""},
		{"no operation shows usage", []string{}, 1, "Usage:", false, ""},
		{"unknown flag", []string{"-bogus"}, 1, "flag provided but not defined", false, ""},
		{"two operations", []string{"-s", "/dev/x", "-u", "/dev/x"}, 1, "only one of", false, ""},
		{"mount without source", []string{"-m", "/mnt"}, 1, "only valid with -s/--source", false, ""},
		{"size without create", []string{"-cs", "100M"}, 1, "only valid with -c/--create", false, ""},
		{"create-key-file without create", []string{"-ck", "/key"}, 1, "only valid with -c/--create", false, ""},
		{"key-size without create", []string{"-cks", "1024"}, 1, "only valid with -c/--create", false, ""},
		{"key-size without create-key-file", []string{"-c", "img", "-cs", "32M", "-cks", "1024"}, 1, "only valid with -ck", false, ""},
		{"long key-size without create-key-file", []string{"-c", "img", "-cs", "32M", "--key-size", "1024"}, 1, "only valid with -ck", false, ""},
		{"create without size", []string{"-c", "img"}, 1, "required with -c/--create", false, ""},
		{"long create without size", []string{"--create", "img"}, 1, "required with -c/--create", false, ""},
		{"long size without create", []string{"--size", "100M"}, 1, "only valid with -c/--create", false, ""},
		{"expand-size without expand", []string{"-xs", "1G"}, 1, "only valid with -x/--expand", false, ""},
		{"key-size nothing", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "100"}, 1, "must be a multiple of 8", false, ""},
		{"zero key-size", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "0"}, 1, "must be a positive multiple of 8", false, ""},
		{"negative key-size", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "-cks", "-8"}, 1, "must be a positive multiple of 8", false, ""},
		{"long key-size nothing", []string{"-c", "img", "-cs", "32M", "-ck", "/k", "--key-size", "100"}, 1, "must be a multiple of 8", false, ""},
		{"expand without size", []string{"-x", "/tmp/x.img"}, 1, "required with -x/--expand", false, ""},
		{"long expand without size", []string{"--expand", "/tmp/x.img"}, 1, "required with -x/--expand", false, ""},
		{"long mount without source", []string{"--mount", "/mnt/x"}, 1, "only valid with -s/--source", false, ""},
		{"mount with key on source only", []string{"-s", "/dev/__test_dev__", "--key", "/k"}, 1, "not LUKS; -k/--key is not valid", false, ""},
		{"create key conflicts", []string{"-c", "img", "-cs", "32M", "-k", "/k", "-ck", "/k2"}, 1, "cannot be used together", false, ""},
		{"umount with key rejected", []string{"-u", "/dev/x", "-k", "/k"}, 1, "not valid with -u/--umount", false, ""},
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

	okExpand := func(runSudo, runDirect func(name string, args ...string) error, filename, size, keyFile string) error {
		return nil
	}
	okCreate := func(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int) error {
		return nil
	}
	okUmount := func(checkMapped func(string) bool, runCmd func(name string, args ...string) error, runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
		return nil
	}
	okMount := func(runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source, keyFile, mountPoint string) error {
		return nil
	}
	boom := errors.New("boom")
	boomExpand := func(runSudo, runDirect func(name string, args ...string) error, filename, size, keyFile string) error {
		return boom
	}
	boomCreate := func(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int) error {
		return boom
	}
	boomUmount := func(checkMapped func(string) bool, runCmd func(name string, args ...string) error, runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
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
		{"create", []string{"-c", "/tmp/lmount-test.img", "-cs", "32M"}},
		{"mount", []string{"-s", "/dev/__test_dev__", "-m", "/mnt/x"}},
		{"umount", []string{"-u", "/dev/__test_dev__"}},
	}
	for _, tc := range success {
		t.Run("success/"+tc.name, func(t *testing.T) {
			expandOperation, createOperation, umountOperation, mountOperation = okExpand, okCreate, okUmount, okMount
			if code := runMain(tc.args); code != 0 {
				t.Errorf("runMain(%v) = %d, want 0", tc.args, code)
			}
		})
	}

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

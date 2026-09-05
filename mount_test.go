package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// makeSocket creates a unix socket file and returns a cleanup function.
// Sockets (and FIFOs) are non-regular entries that can never be a mount
// source, and a FIFO even blocks a read-open forever. The socket is placed
// directly under os.TempDir() because a unix socket path is length-limited
// (~104 bytes) and deep test dirs would fail to bind.
func makeSocket(t *testing.T) string {
	t.Helper()
	path := filepath.Join(os.TempDir(), fmt.Sprintf("lmount-test-%d.sock", os.Getpid()))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		l.Close()
		os.Remove(path)
	})
	return path
}

// makeFIFO creates a named pipe and returns a cleanup function. A FIFO key
// file would block cryptsetup forever waiting for a writer, so it must be
// rejected before any mapping is opened.
func makeFIFO(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseFindmntTargets(t *testing.T) {
	tests := []struct {
		name string
		out  []byte
		want []string
	}{
		{"no output yields no targets", []byte(""), []string{}},
		{"trailing newline is trimmed", []byte("/mnt/a\n"), []string{"/mnt/a"}},
		{"a single target", []byte("/mnt/a"), []string{"/mnt/a"}},
		{"multiple targets keep their order", []byte("/mnt/a\n/mnt/b\n"), []string{"/mnt/a", "/mnt/b"}},
		{"CRLF line endings are normalized", []byte("/mnt/a\r\n/mnt/b\r\n"), []string{"/mnt/a", "/mnt/b"}},
		{"indented lines are trimmed", []byte("  /mnt/a\n\t/mnt/b\n"), []string{"/mnt/a", "/mnt/b"}},
		{"empty lines are skipped", []byte("\n/mnt/a\n\n/mnt/b\n"), []string{"/mnt/a", "/mnt/b"}},
		{"duplicate targets are deduped", []byte("/mnt/a\n/mnt/a\n/mnt/b\n/mnt/b\n"), []string{"/mnt/a", "/mnt/b"}},
		{"duplicates with whitespace variants collide", []byte("/mnt/a\n /mnt/a\n"), []string{"/mnt/a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFindmntTargets(tt.out)
			if len(got) != len(tt.want) {
				t.Fatalf("parseFindmntTargets(%q) = %v, want %v", tt.out, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("parseFindmntTargets(%q) = %v, want %v", tt.out, got, tt.want)
				}
			}
		})
	}
}

func TestCheckKeyFile(t *testing.T) {
	t.Run("accepts a regular non-empty file", func(t *testing.T) {
		kf := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(kf, []byte("not-empty"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkKeyFile(kf, "key file"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects a socket key file", func(t *testing.T) {
		sock := makeSocket(t)
		err := checkKeyFile(sock, "key file")
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("expected a not-a-regular-file error, got %v", err)
		}
	})

	t.Run("rejects a FIFO key file", func(t *testing.T) {
		fifo := makeFIFO(t)
		err := checkKeyFile(fifo, "key file")
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("expected a not-a-regular-file error, got %v", err)
		}
	})

	t.Run("rejects a directory", func(t *testing.T) {
		err := checkKeyFile(t.TempDir(), "key file")
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory error, got %v", err)
		}
	})

	t.Run("rejects an empty regular file", func(t *testing.T) {
		kf := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(kf, nil, 0600); err != nil {
			t.Fatal(err)
		}
		err := checkKeyFile(kf, "key file")
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("expected an empty-file error, got %v", err)
		}
	})
}

func TestOpenAndMount_luks(t *testing.T) {
	t.Run("success default mount", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		home := t.TempDir()
		orig := userHomeDir
		userHomeDir = func() (string, error) { return home, nil }
		t.Cleanup(func() { userHomeDir = orig })

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(home, "__test_dev__")); os.IsNotExist(statErr) {
			t.Error("default mountpoint was not created under the home directory")
		}
	})

	t.Run("rejects a relative inferred mountpoint (empty HOME)", func(t *testing.T) {
		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		orig := userHomeDir
		userHomeDir = func() (string, error) { return "", nil }
		t.Cleanup(func() { userHomeDir = orig })

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "")
		if err == nil || !strings.Contains(err.Error(), "absolute mount point") {
			t.Errorf("expected an absolute-mountpoint inference error, got %v", err)
		}
		if !calledClose {
			t.Error("LUKS mapping should be closed on a mountpoint inference error")
		}
	})

	t.Run("a failed luksClose on an early error path is surfaced", func(t *testing.T) {
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close fail")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		orig := userHomeDir
		userHomeDir = func() (string, error) { return "", nil }
		t.Cleanup(func() { userHomeDir = orig })

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "")
		if err == nil || !strings.Contains(err.Error(), "absolute mount point") {
			t.Fatalf("expected an absolute-mountpoint inference error, got %v", err)
		}
		if !strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("a luksClose failure on the inference error path must be reported, got %v", err)
		}
	})

	t.Run("success with mountpoint", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(mp); os.IsNotExist(err) {
			t.Error("mountpoint was not created")
		}
	})

	t.Run("mountpoint path exists as file", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		blocker := filepath.Join(dir, "mnt")
		if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", blocker)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(blocker + ".mnt"); os.IsNotExist(err) {
			t.Error("mountpoint was not created at <path>.mnt")
		}
	})

	t.Run("file-collision fallback to .mnt is announced", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		blocker := filepath.Join(dir, "mnt")
		if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
			t.Fatal(err)
		}

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", blocker)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "is a file; using") || !strings.Contains(out, blocker+".mnt") {
			t.Errorf("expected the .mnt fallback to be announced, got %q", out)
		}
	})

	t.Run("mountpoint collides repeatedly with files", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		base := filepath.Join(dir, "mnt")
		// Both the base path and its .mnt fallback exist as files.
		if err := os.WriteFile(base, []byte("block"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(base+".mnt", []byte("block"), 0644); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", base)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(base + ".mnt.mnt"); os.IsNotExist(err) {
			t.Error("mountpoint was not created at <path>.mnt.mnt")
		}
	})

	t.Run("mount point collisions are bounded, not unbounded", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		base := filepath.Join(dir, "mnt")
		// base, mnt.mnt, mnt.mnt.mnt, ... up to one past the cap all exist as
		// files, so the loop must stop and error instead of generating names
		// forever.
		for i := 0; i <= 16; i++ {
			p := base + strings.Repeat(".mnt", i)
			if err := os.WriteFile(p, []byte("block"), 0644); err != nil {
				t.Fatal(err)
			}
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", base)
		if err == nil || !strings.Contains(err.Error(), "no free mount point") {
			t.Fatalf("expected a bounded-collision error, got %v", err)
		}
	})

	t.Run("mount point stat error surfaces clearly and closes mapping", func(t *testing.T) {
		var closed bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closed = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		restricted := filepath.Join(dir, "restricted")
		os.MkdirAll(restricted, 0000)
		t.Cleanup(func() { os.Chmod(restricted, 0755) })
		mp := filepath.Join(restricted, "mnt")

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil || !strings.Contains(err.Error(), "checking mount point") {
			t.Fatalf("expected clear mount point stat error, got %v", err)
		}
		if strings.Contains(err.Error(), "creating mountpoint") {
			t.Error("permission error should not be masked as a mkdir error")
		}
		if !closed {
			t.Error("LUKS mapping should be closed after a mount point probe error")
		}
	})

	t.Run("success with keyfile", func(t *testing.T) {
		var capturedArgs []string
		var callCount int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && callCount == 0 {
				capturedArgs = args
			}
			callCount++
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		kf := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(kf, []byte("keymaterial"), 0600); err != nil {
			t.Fatal(err)
		}
		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", kf, mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(capturedArgs) < 5 || capturedArgs[1] != "--key-file" || capturedArgs[2] != kf {
			t.Errorf("key-file not passed: %v", capturedArgs)
		}
	})

	t.Run("accepts a trailing-slash key file path", func(t *testing.T) {
		var luksOpenArgs []string
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenArgs = args
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		kf := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(kf, []byte("keymaterial"), 0600); err != nil {
			t.Fatal(err)
		}
		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", kf+string(filepath.Separator), mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(luksOpenArgs) < 3 || luksOpenArgs[2] != kf {
			t.Errorf("trailing-slash key file not normalized in --key-file, got %v", luksOpenArgs)
		}
	})

	t.Run("sniffs a LUKS-magic file without probing cryptsetup", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "luks.img")
		if err := os.WriteFile(src, []byte("LUKS\xba\xbe\x00\x02padding"), 0644); err != nil {
			t.Fatal(err)
		}

		var cryptCalls, luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, errors.New("not luks")
		}

		err := openAndMount(runCmd, runOutput, src, "", filepath.Join(dir, "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup must not be probed for a readable LUKS-magic file, got %d calls", cryptCalls)
		}
		if luksOpenCalls != 1 {
			t.Errorf("expected exactly one luksOpen, got %d", luksOpenCalls)
		}
	})

	t.Run("rejects a directory key file for a LUKS source before opening", func(t *testing.T) {
		var luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dirKey := filepath.Join(t.TempDir(), "keydir")
		if err := os.MkdirAll(dirKey, 0755); err != nil {
			t.Fatal(err)
		}
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", dirKey, filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-key-file error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen should not be attempted with a directory key, got %d calls", luksOpenCalls)
		}
	})

	t.Run("rejects an empty key file for a LUKS source before opening", func(t *testing.T) {
		var luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		emptyKey := filepath.Join(t.TempDir(), "empty.key")
		if err := os.WriteFile(emptyKey, nil, 0600); err != nil {
			t.Fatal(err)
		}
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", emptyKey, filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("expected an empty-key-file error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen should not be attempted with an empty key, got %d calls", luksOpenCalls)
		}
	})

	t.Run("rejects a missing key file for a LUKS source before opening", func(t *testing.T) {
		var luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		missing := filepath.Join(t.TempDir(), "nokey")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", missing, filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' key file error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen should not be attempted with a missing key, got %d calls", luksOpenCalls)
		}
	})

	t.Run("reports a source that is already open instead of luksOpen", func(t *testing.T) {
		var luksOpenCalls, luksCloseCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				luksCloseCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		orig := mapperProbe
		mapperProbe = func(string) bool { return true }
		t.Cleanup(func() { mapperProbe = orig })

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "already open") {
			t.Errorf("expected an already-open error, got %v", err)
		}
		if !strings.Contains(err.Error(), "/dev/mapper/__test_dev__") {
			t.Errorf("expected the mapping path in the error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen should not be attempted for an already-open source, got %d calls", luksOpenCalls)
		}
		if luksCloseCalls != 0 {
			t.Errorf("luksClose must not be attempted on a mapping that another session owns, got %d calls", luksCloseCalls)
		}
	})

	t.Run("rejects an unmappable source name before luksOpen", func(t *testing.T) {
		var luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		// The source basename becomes the /dev/mapper name; a space in it could
		// never be addressed as a single mapping, so it must fail up front.
		err := openAndMount(runCmd, runOutput, "/dev/__bad name__", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "invalid device-mapper name") {
			t.Errorf("expected an invalid device-mapper name error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen should not be attempted for an unmappable name, got %d calls", luksOpenCalls)
		}
	})

	t.Run("cryptsetup error", func(t *testing.T) {
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" {
				return errors.New("fail")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "cryptsetup luksOpen failed") {
			t.Errorf("expected cryptsetup error, got %v", err)
		}
	})

	t.Run("rejects a key file that is the source itself", func(t *testing.T) {
		var luksOpenCalls, luksCloseCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				luksCloseCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		// A magic-prefixed file the sniff detects as LUKS; passing it as its
		// own key would make cryptsetup read a LUKS header as a key.
		src := filepath.Join(t.TempDir(), "container.img")
		if err := os.WriteFile(src, []byte("LUKS\xba\xbe"), 0600); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, src, src, filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected a key-file/source collision error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen must not be attempted for a colliding key file, got %d calls", luksOpenCalls)
		}
		if luksCloseCalls != 0 {
			t.Errorf("luksClose must not be attempted before any mapping was opened, got %d calls", luksCloseCalls)
		}
	})

	t.Run("mount error", func(t *testing.T) {
		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				return errors.New("mount fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil || !strings.Contains(err.Error(), "mount failed") {
			t.Errorf("expected mount error, got %v", err)
		}
		if !strings.Contains(err.Error(), "/dev/mapper/__test_dev__") || !strings.Contains(err.Error(), mp) {
			t.Errorf("mount error should name the device and target, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called — cleanup should run on mount error")
		}
		if _, statErr := os.Stat(mp); !os.IsNotExist(statErr) {
			t.Error("freshly-created mountpoint should be removed on mount failure")
		}
	})

	t.Run("mount point under a file is rejected up front", func(t *testing.T) {
		var mountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		file := filepath.Join(t.TempDir(), "afile")
		if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		mp := filepath.Join(file, "child")

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil {
			t.Fatal("expected an error when the mount point parent is a file")
		}
		if !strings.Contains(err.Error(), "checking mount point") {
			t.Errorf("expected a checking-mount-point error, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount must not be attempted under a file, got %d calls", mountCalls)
		}
	})

	t.Run("mount failure warns when the created mount point cannot be removed", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "ro")
		if err := os.MkdirAll(parent, 0755); err != nil {
			t.Fatal(err)
		}
		mp := filepath.Join(parent, "mnt")

		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				// Make the just-created mount point unremovable before the
				// cleanup runs, then fail so cleanup is triggered.
				if err := os.Chmod(parent, 0555); err != nil {
					t.Fatal(err)
				}
				return errors.New("mount fail")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		r, w, err2 := os.Pipe()
		if err2 != nil {
			t.Fatal(err2)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		defer func() { os.Stderr = oldStderr }()

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil || !strings.Contains(err.Error(), "mount failed") {
			t.Fatalf("expected a mount failure, got %v", err)
		}

		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		t.Cleanup(func() { os.Chmod(parent, 0755) })
		if !strings.Contains(buf.String(), "Warning: removing mount point") {
			t.Errorf("expected a cleanup warning on stderr, got %q", buf.String())
		}
	})

	t.Run("refuses to mount at the filesystem root", func(t *testing.T) {
		var mountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "/")
		if err == nil || !strings.Contains(err.Error(), "filesystem root") {
			t.Errorf("expected a root-mount refusal, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount must not be attempted at the root, got %d calls", mountCalls)
		}
	})

	t.Run("refuses to mount at the root for a slash-collapsing spelling", func(t *testing.T) {
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				t.Error("mount must not be attempted at the root")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "//")
		if err == nil || !strings.Contains(err.Error(), "filesystem root") {
			t.Errorf("expected a root-mount refusal for //, got %v", err)
		}
	})

	t.Run("mount error surfaces a luksClose failure", func(t *testing.T) {
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				return errors.New("mount fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close fail")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "mount failed") || !strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("expected a mount failure hinting at the open mapping, got %v", err)
		}
	})

	t.Run("mount error keeps pre-existing mountpoint", func(t *testing.T) {
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				return errors.New("mount fail")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		mp := filepath.Join(t.TempDir(), "mnt")
		if err := os.MkdirAll(mp, 0755); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil || !strings.Contains(err.Error(), "mount failed") {
			t.Fatalf("expected mount error, got %v", err)
		}
		if _, statErr := os.Stat(mp); os.IsNotExist(statErr) {
			t.Error("pre-existing mountpoint should not be removed on mount failure")
		}
	})

	t.Run("empty source closes LUKS when mountpoint inferred", func(t *testing.T) {
		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "", "", "")
		if err == nil || !strings.Contains(err.Error(), "cannot infer mount point name") {
			t.Fatalf("expected mountpoint inference error, got %v", err)
		}
		// luksOpen was mocked as successful (runOutput returns nil => isLuks true),
		// so luksClose must be called on this error path to avoid a leak.
		if !calledClose {
			t.Error("luksClose was not called when mountpoint inference failed after LUKS open")
		}
	})

	t.Run("chown warning does not fail", func(t *testing.T) {
		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "chown" {
				return errors.New("chown fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("expected success despite chown warning, got %v", err)
		}
		if calledClose {
			t.Error("luksClose was called — cleanup should not run on success")
		}
	})

	t.Run("does not chown a pre-existing mount point", func(t *testing.T) {
		var chownCalls int
		runCmd := func(name string, args ...string) error {
			if name == "chown" {
				chownCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		mp := filepath.Join(t.TempDir(), "existing")
		if err := os.MkdirAll(mp, 0755); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if chownCalls != 0 {
			t.Errorf("chown must not retarget a pre-existing directory, got %d calls", chownCalls)
		}
	})
}

func TestOpenAndMount_nonLuks(t *testing.T) {
	t.Run("rejects the filesystem root as a source", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "/", "", "")
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-source error for the root, got %v", err)
		}
	})

	t.Run("mounts source directly", func(t *testing.T) {
		var mountArgs []string
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountArgs = append(mountArgs, args...)
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mountArgs) < 1 || mountArgs[0] != "/dev/__test_dev__" {
			t.Errorf("expected mount source /dev/__test_dev__, got %v", mountArgs)
		}
	})

	t.Run("sniffs a plain file without probing cryptsetup", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "plain.img")
		if err := os.WriteFile(src, []byte("not luks"), 0644); err != nil {
			t.Fatal(err)
		}

		var cryptCalls int
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, errors.New("not luks")
		}

		err := openAndMount(runCmd, runOutput, src, "", filepath.Join(dir, "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup must not be probed for a readable non-LUKS file, got %d calls", cryptCalls)
		}
	})

	t.Run("normalizes a trailing slash on the source before probing", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "plain.img")
		if err := os.WriteFile(src, []byte("not luks"), 0644); err != nil {
			t.Fatal(err)
		}

		var mountArgs []string
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountArgs = append(mountArgs, args...)
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		// A trailing slash would make os.Stat/open treat the file as a
		// directory (ENOTDIR); the normalized source must be mounted instead.
		err := openAndMount(runCmd, runOutput, src+"/", "", filepath.Join(dir, "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mountArgs) < 1 || mountArgs[0] != src {
			t.Errorf("expected mount source %q (slash normalized), got %v", src, mountArgs)
		}
	})

	t.Run("rejects a directory source before mounting", func(t *testing.T) {
		var mountCalls, cryptCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, errors.New("not luks")
		}

		dir := t.TempDir()
		err := openAndMount(runCmd, runOutput, dir, "", "")
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-source error, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount should not be attempted for a directory source, got %d calls", mountCalls)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup should not be probed for a directory source, got %d calls", cryptCalls)
		}
	})

	t.Run("rejects an empty file source before mounting", func(t *testing.T) {
		var mountCalls, cryptCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, errors.New("not luks")
		}

		empty := filepath.Join(t.TempDir(), "empty.img")
		if err := os.WriteFile(empty, nil, 0644); err != nil {
			t.Fatal(err)
		}
		err := openAndMount(runCmd, runOutput, empty, "", "")
		if err == nil || !strings.Contains(err.Error(), "empty file") {
			t.Errorf("expected an empty-file error, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount should not be attempted for an empty file source, got %d calls", mountCalls)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup should not be probed for an empty file source, got %d calls", cryptCalls)
		}
	})

	t.Run("rejects a nonexistent plain file source before mounting", func(t *testing.T) {
		var mountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		missing := filepath.Join(t.TempDir(), "nope.img")
		err := openAndMount(runCmd, runOutput, missing, "", "")
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' error for missing source, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount should not be attempted for a missing source, got %d calls", mountCalls)
		}
	})

	t.Run("rejects a socket source instead of probing or mounting", func(t *testing.T) {
		sock := makeSocket(t)

		var mountCalls, cryptCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, errors.New("not luks")
		}

		err := openAndMount(runCmd, runOutput, sock, "", "")
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("expected a not-a-regular-file error, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount should not be attempted for a socket source, got %d calls", mountCalls)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup should not be probed for a socket source, got %d calls", cryptCalls)
		}
	})

	t.Run("does not probe cryptsetup for a missing non-device source", func(t *testing.T) {
		var cryptCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		missing := filepath.Join(t.TempDir(), "nope.img")
		err := openAndMount(runCmd, runOutput, missing, "", "")
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' error for missing source, got %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup must not be probed on a missing source, got %d calls", cryptCalls)
		}
	})

	t.Run("missing source with -k reports did-not-exist, not not-LUKS", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		missing := filepath.Join(t.TempDir(), "nope.img")
		err := openAndMount(runCmd, runOutput, missing, "/path/to/key", "")
		if err == nil {
			t.Fatal("expected an error, got none")
		}
		if strings.Contains(err.Error(), "not LUKS") {
			t.Errorf("missing source should report 'does not exist', not 'not LUKS': %v", err)
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' error, got %v", err)
		}
	})

	t.Run("skips cryptsetup calls", func(t *testing.T) {
		var cryptCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("expected 0 cryptsetup calls, got %d", cryptCalls)
		}
	})

	t.Run("rejects -k for a non-LUKS source", func(t *testing.T) {
		var mountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "/path/to/key", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "not LUKS") {
			t.Errorf("expected a 'not LUKS' error when -k is passed for a plain source, got %v", err)
		}
		if mountCalls != 0 {
			t.Errorf("mount should not be attempted when -k is invalid for the source, got %d calls", mountCalls)
		}
	})

	t.Run("mountpoint path exists as file", func(t *testing.T) {
		var chownArgs []string
		runCmd := func(name string, args ...string) error {
			if name == "chown" {
				chownArgs = args
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, errors.New("not luks") }

		dir := t.TempDir()
		blocker := filepath.Join(dir, "mnt")
		if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", blocker)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(blocker + ".mnt"); os.IsNotExist(err) {
			t.Error("mountpoint was not created at <path>.mnt")
		}
		// The .mnt directory was created by lmount, so it must be chowned to
		// the invoking user (the file blocker itself must be left alone).
		if len(chownArgs) == 0 || chownArgs[len(chownArgs)-1] != blocker+".mnt" {
			t.Errorf("expected chown on the fallback mount point %q, got %v", blocker+".mnt", chownArgs)
		}
	})
}

func TestUmountAndClose_luks(t *testing.T) {
	t.Run("no mounts", func(t *testing.T) {
		var called bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				called = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Error("luksClose was not called")
		}
	})

	t.Run("with mounts", func(t *testing.T) {
		dir := t.TempDir()
		mp1 := filepath.Join(dir, "mp1")
		mp2 := filepath.Join(dir, "mp2")
		os.MkdirAll(mp1, 0755)
		os.MkdirAll(mp2, 0755)

		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp1 + "\n" + mp2), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(mp1); !os.IsNotExist(err) {
			t.Error("mp1 was not removed")
		}
		if _, err := os.Stat(mp2); !os.IsNotExist(err) {
			t.Error("mp2 was not removed")
		}
	})

	t.Run("umount error", func(t *testing.T) {
		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "umount" {
				return errors.New("umount fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(filepath.Join(t.TempDir(), "mnt")), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "__test_dev__")
		if err == nil || !strings.Contains(err.Error(), "umount") {
			t.Errorf("expected umount error, got %v", err)
		}
		if calledClose {
			t.Error("luksClose must NOT be called while a filesystem is still mounted")
		}
		if !strings.Contains(err.Error(), "left open") || !strings.Contains(err.Error(), "__test_dev__") {
			t.Errorf("expected the error to name the mapping left open, got %v", err)
		}
	})

	t.Run("closes the mapping even when the mount directory cannot be removed", func(t *testing.T) {
		ro := filepath.Join(t.TempDir(), "ro")
		if err := os.MkdirAll(ro, 0755); err != nil {
			t.Fatal(err)
		}
		mnt := filepath.Join(ro, "mnt")
		if err := os.Mkdir(mnt, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(ro, 0755) })

		// After a successful umount the empty directory stays behind but its
		// parent is no longer writable, so the cleanup rmdir fails (EACCES).
		// The filesystem is unmounted, so the LUKS mapping must still close.
		if err := os.Chmod(ro, 0555); err != nil {
			t.Fatal(err)
		}

		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mnt), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "__test_dev__")
		if err == nil || !strings.Contains(err.Error(), "rmdir") {
			t.Errorf("expected a cleanup error naming the rmdir, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose should still run once the filesystem is unmounted")
		}
	})

	t.Run("rejects the filesystem root as a source", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/")
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-source error for the root, got %v", err)
		}
	})

	t.Run("skip removal when not empty", func(t *testing.T) {
		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		os.MkdirAll(mp, 0755)
		os.WriteFile(filepath.Join(mp, "leftover"), []byte("x"), 0644)

		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "__test_dev__")
		if err != nil {
			t.Fatalf("expected no error for non-empty mount point, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called")
		}
		if _, err := os.Stat(mp); os.IsNotExist(err) {
			t.Error("non-empty mount point should not have been removed")
		}
	})

	t.Run("luksClose error", func(t *testing.T) {
		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		os.MkdirAll(mp, 0755)

		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && args[0] == "luksClose" {
				return errors.New("close fail")
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutput, "__test_dev__")
		if err == nil || !strings.Contains(err.Error(), "luksClose __test_dev__") {
			t.Errorf("expected a luksClose error naming the mapping, got %v", err)
		}
	})
}

func TestUmountAndClose_nonLuks(t *testing.T) {
	t.Run("skips cryptsetup calls", func(t *testing.T) {
		var cryptCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/dev/__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("expected 0 cryptsetup calls, got %d", cryptCalls)
		}
	})

	t.Run("resolves source path before searching", func(t *testing.T) {
		dir := t.TempDir()
		srcFile := filepath.Join(dir, "sdc1")
		os.WriteFile(srcFile, nil, 0644)

		var searchArg string
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "findmnt" {
				searchArg = strings.Join(args, " ")
			}
			return nil, nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, srcFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(searchArg, srcFile) {
			t.Errorf("expected findmnt to search on resolved path %q, got %q", srcFile, searchArg)
		}
	})

	t.Run("normalizes a trailing slash on the source for the search", func(t *testing.T) {
		dir := t.TempDir()
		srcFile := filepath.Join(dir, "sdc1")
		os.WriteFile(srcFile, nil, 0644)

		var searchArg string
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "findmnt" {
				searchArg = strings.Join(args, " ")
			}
			return nil, nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, srcFile+"/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(searchArg, srcFile+"/") {
			t.Errorf("findmnt search should not carry a trailing slash, got %q", searchArg)
		}
		if !strings.Contains(searchArg, srcFile) {
			t.Errorf("expected findmnt to search on the normalized path %q, got %q", srcFile, searchArg)
		}
	})

	t.Run("reports a nonexistent plain file source instead of silently succeeding", func(t *testing.T) {
		dir := t.TempDir()
		missing := filepath.Join(dir, "nope.img")

		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, missing)
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' error for missing source, got %v", err)
		}
	})

	t.Run("rejects a directory source instead of misdetecting a mapping", func(t *testing.T) {
		var calledClose bool
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return true }

		// An injected probe that blindly reports "mapped" would previously mark
		// "." as an open LUKS mapping (via /dev/mapper/. == /dev/mapper) and run
		// a pointless luksClose; the directory rejection must win.
		err := umountAndClose(checkMapped, runCmd, runOutput, ".")
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Fatalf("expected a directory-source error, got %v", err)
		}
		if calledClose {
			t.Error("luksClose must not run for a directory source")
		}
	})

	t.Run("rejects an absolute path pointing at a directory", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		dir := t.TempDir()
		err := umountAndClose(checkMapped, runCmd, runOutput, dir)
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-source error, got %v", err)
		}
	})

	t.Run("detaches an open mapping whose backing file was deleted", func(t *testing.T) {
		var closeName string
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" && len(args) > 1 {
				closeName = args[1]
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return true }

		// The source path no longer exists, but the mapping named after its
		// basename is still open; the mapping must be found and closed, not
		// dismissed with a "does not exist" error.
		missing := filepath.Join(t.TempDir(), "gone.img")
		err := umountAndClose(checkMapped, runCmd, runOutput, missing)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if closeName != "gone.img" {
			t.Errorf("expected luksClose of the mapping 'gone.img', got %q", closeName)
		}
	})

	t.Run("absolute path for bare relative file, not /dev/", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "sdc1"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		oldWd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer os.Chdir(oldWd)

		var searchArg string
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "findmnt" {
				searchArg = strings.Join(args, " ")
			}
			return nil, nil
		}
		checkMapped := func(name string) bool { return false }

		err = umountAndClose(checkMapped, runCmd, runOutput, "sdc1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(searchArg, "/dev/sdc1") {
			t.Errorf("bare relative file must not be rewritten to /dev/sdc1, got %q", searchArg)
		}
		if !strings.Contains(searchArg, filepath.Join(dir, "sdc1")) {
			t.Errorf("expected findmnt to search on absolute path %q, got %q", filepath.Join(dir, "sdc1"), searchArg)
		}
	})

	t.Run("searches mounts on source", func(t *testing.T) {
		var searchArg string
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			searchArg = strings.Join(args, " ")
			return nil, nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/dev/__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(searchArg, "/dev/__test_dev__") {
			t.Errorf("expected findmnt to search on source, got %q", searchArg)
		}
		if strings.Contains(searchArg, "/dev/mapper/") {
			t.Errorf("unexpected mapper path in findmnt search: %q", searchArg)
		}
	})

	t.Run("reports findmnt failure as an error, not success", func(t *testing.T) {
		var umountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "umount" {
				umountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("boom")
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/dev/__test_dev__")
		if err == nil {
			t.Fatalf("expected an error when findmnt fails")
		}
		if !strings.Contains(fmt.Sprintf("%v", err), "findmnt failed") {
			t.Errorf("expected findmnt failure to be reported, got %v", err)
		}
		if !strings.Contains(fmt.Sprintf("%v", err), "/dev/__test_dev__") {
			t.Errorf("expected the search spec in the findmnt error, got %v", err)
		}
		if umountCalls != 0 {
			t.Errorf("expected no umount calls when findmnt fails, got %d", umountCalls)
		}
	})

	t.Run("does not close a LUKS mapping when findmnt fails", func(t *testing.T) {
		var closes, umounts int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closes++
			}
			if name == "umount" {
				umounts++
			}
			return nil
		}
		runOutputDirect := func(name string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("boom")
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, runOutputDirect, "/dev/__test_dev__")
		if err == nil || !strings.Contains(fmt.Sprintf("%v", err), "findmnt failed") {
			t.Errorf("expected a findmnt failure, got %v", err)
		}
		if !strings.Contains(fmt.Sprintf("%v", err), "/dev/mapper/__test_dev__") {
			t.Errorf("expected the search spec in the findmnt error, got %v", err)
		}
		if closes != 0 {
			t.Errorf("must not luksClose when the mount probe failed, got %d close(s)", closes)
		}
		if umounts != 0 {
			t.Errorf("must not umount when the mount probe failed, got %d umount(s)", umounts)
		}
	})

	t.Run("dedupes repeated findmnt targets", func(t *testing.T) {
		dir := t.TempDir()
		mp1 := filepath.Join(dir, "mp1")

		var umounts []string
		runCmd := func(name string, args ...string) error {
			if name == "umount" && len(args) > 0 {
				umounts = append(umounts, args[0])
			}
			return nil
		}
		// findmnt lists the same target twice (stacked/bind mounts).
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp1 + "\n" + mp1), nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/dev/__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(umounts) != 1 {
			t.Errorf("expected a single umount for a duplicated target, got %d: %v", len(umounts), umounts)
		}
	})

	t.Run("trims whitespace and CRLF from findmnt targets", func(t *testing.T) {
		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		if err := os.MkdirAll(mp, 0755); err != nil {
			t.Fatal(err)
		}

		var umounts []string
		runCmd := func(name string, args ...string) error {
			if name == "umount" && len(args) > 0 {
				umounts = append(umounts, args[0])
			}
			return nil
		}
		// A \r-padded and an indented line must be cleaned before use.
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp + "\r\n\t" + mp + "2"), nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/dev/__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(umounts) != 2 {
			t.Fatalf("expected 2 umount calls, got %d: %v", len(umounts), umounts)
		}
		cleaned := map[string]bool{umounts[0]: true, umounts[1]: true}
		if !cleaned[mp] || !cleaned[mp+"2"] {
			t.Errorf("umount targets should be trimmed to %q and %q, got %v", mp, mp+"2", umounts)
		}
	})

	t.Run("unmounts nested targets before parents", func(t *testing.T) {
		// findmnt returns mounts in arbitrary order; the deepest (child) target
		// must be unmounted before its parent, or the parent fails as busy.
		var targets []string
		runCmd := func(name string, args ...string) error {
			if name == "umount" && len(args) > 0 {
				targets = append(targets, args[0])
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte("/mnt\n/mnt/b\n/mnt/b/c"), nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, runOutput, "/dev/__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(targets) != 3 {
			t.Fatalf("expected 3 umount calls, got %d: %v", len(targets), targets)
		}
		want := []string{"/mnt/b/c", "/mnt/b", "/mnt"}
		for i, m := range targets {
			if m != want[i] {
				t.Errorf("umount order: index %d = %q, want %q", i, m, want[i])
			}
		}
	})
}

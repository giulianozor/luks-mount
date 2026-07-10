package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSrcName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/dev/sda1", "sda1"},
		{"sda1", "sda1"},
		{"/path/to/file.img", "file.img"},
		{"file.img", "file.img"},
		{"/", "/"},
		{"", ""},
	}
	for _, tt := range tests {
		got := srcName(tt.path)
		if got != tt.want {
			t.Errorf("srcName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestResolveSource(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		fp := resolveSource("")
		if fp != "" {
			t.Errorf("expected empty, got %q", fp)
		}
	})

	t.Run("existing file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		if err := os.WriteFile(f, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		fp := resolveSource(f)
		if fp != f {
			t.Errorf("got %q, want %q", fp, f)
		}
	})

	t.Run("nonexistent falls back", func(t *testing.T) {
		fp := resolveSource("nonexistent")
		if fp != "nonexistent" {
			t.Errorf("got %q, want %q", fp, "nonexistent")
		}
	})
}

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

func TestOpenAndMount_luks(t *testing.T) {
	savedIsLuks := isLuks
	isLuks = func(string) bool { return true }
	defer func() { isLuks = savedIsLuks }()

	t.Run("success default mount", func(t *testing.T) {
		saved := runCmd
		runCmd = func(name string, args ...string) error { return nil }
		defer func() { runCmd = saved }()

		err := openAndMount("/dev/sda1", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("success with mountpoint", func(t *testing.T) {
		saved := runCmd
		runCmd = func(name string, args ...string) error { return nil }
		defer func() { runCmd = saved }()

		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		err := openAndMount("/dev/sda1", "", mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(mp); os.IsNotExist(err) {
			t.Error("mountpoint was not created")
		}
	})

	t.Run("success with keyfile", func(t *testing.T) {
		var capturedArgs []string
		var callCount int
		saved := runCmd
		runCmd = func(name string, args ...string) error {
			if name == "cryptsetup" && callCount == 0 {
				capturedArgs = args
			}
			callCount++
			return nil
		}
		defer func() { runCmd = saved }()

		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount("/dev/sda1", "/path/to/key", mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(capturedArgs) < 5 || capturedArgs[1] != "--key-file" || capturedArgs[2] != "/path/to/key" {
			t.Errorf("key-file not passed: %v", capturedArgs)
		}
	})

	t.Run("cryptsetup error", func(t *testing.T) {
		saved := runCmd
		runCmd = func(name string, args ...string) error {
			if name == "cryptsetup" {
				return errors.New("fail")
			}
			return nil
		}
		defer func() { runCmd = saved }()

		err := openAndMount("/dev/sda1", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "cryptsetup luksOpen failed") {
			t.Errorf("expected cryptsetup error, got %v", err)
		}
	})

	t.Run("mount error", func(t *testing.T) {
		var calledClose bool
		saved := runCmd
		runCmd = func(name string, args ...string) error {
			if name == "mount" {
				return errors.New("mount fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		defer func() { runCmd = saved }()

		err := openAndMount("/dev/sda1", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "mount failed") {
			t.Errorf("expected mount error, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called — deferred cleanup should run on mount error")
		}
	})

	t.Run("chown warning does not fail", func(t *testing.T) {
		var calledClose bool
		saved := runCmd
		runCmd = func(name string, args ...string) error {
			if name == "chown" {
				return errors.New("chown fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		defer func() { runCmd = saved }()

		err := openAndMount("/dev/sda1", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("expected success despite chown warning, got %v", err)
		}
		if calledClose {
			t.Error("luksClose was called — deferred cleanup should not run on success")
		}
	})
}

func TestOpenAndMount_nonLuks(t *testing.T) {
	savedIsLuks := isLuks
	isLuks = func(string) bool { return false }
	defer func() { isLuks = savedIsLuks }()

	t.Run("mounts source directly", func(t *testing.T) {
		var mountArgs []string
		saved := runCmd
		runCmd = func(name string, args ...string) error {
			if name == "mount" {
				mountArgs = append(mountArgs, args...)
			}
			return nil
		}
		defer func() { runCmd = saved }()

		err := openAndMount("/dev/sda1", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mountArgs) < 1 || mountArgs[0] != "/dev/sda1" {
			t.Errorf("expected mount source /dev/sda1, got %v", mountArgs)
		}
	})

	t.Run("skips cryptsetup calls", func(t *testing.T) {
		var cryptCalls int
		saved := runCmd
		runCmd = func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		defer func() { runCmd = saved }()

		err := openAndMount("/dev/sda1", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("expected 0 cryptsetup calls, got %d", cryptCalls)
		}
	})
}

func TestUmountAndClose_luks(t *testing.T) {
	savedMapped := checkMapped
	checkMapped = func(string) bool { return true }
	defer func() { checkMapped = savedMapped }()

	t.Run("no mounts", func(t *testing.T) {
		savedCmd := runCmd
		savedOut := runOutput
		runOutput = func(name string, args ...string) ([]byte, error) { return nil, nil }
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		var cmdLog []string
		runCmd = func(name string, args ...string) error {
			cmdLog = append(cmdLog, fmt.Sprintf("%s %s", name, strings.Join(args, " ")))
			return nil
		}

		err := umountAndClose("sda1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cmdLog) != 1 || !strings.Contains(cmdLog[0], "luksClose") {
			t.Errorf("expected luksClose, got %v", cmdLog)
		}
	})

	t.Run("with mounts", func(t *testing.T) {
		savedCmd := runCmd
		savedOut := runOutput
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		dir := t.TempDir()
		mp1 := filepath.Join(dir, "mp1")
		mp2 := filepath.Join(dir, "mp2")
		os.MkdirAll(mp1, 0755)
		os.MkdirAll(mp2, 0755)

		runOutput = func(name string, args ...string) ([]byte, error) {
			return []byte(mp1 + "\n" + mp2), nil
		}
		runCmd = func(name string, args ...string) error {
			return nil
		}

		err := umountAndClose("sda1")
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
		savedCmd := runCmd
		savedOut := runOutput
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		runOutput = func(name string, args ...string) ([]byte, error) {
			return []byte(filepath.Join(t.TempDir(), "mnt")), nil
		}
		runCmd = func(name string, args ...string) error {
			if name == "umount" {
				return errors.New("umount fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		err := umountAndClose("sda1")
		if err == nil || !strings.Contains(err.Error(), "umount") {
			t.Errorf("expected umount error, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called despite umount error")
		}
	})

	t.Run("rmdir error", func(t *testing.T) {
		savedCmd := runCmd
		savedOut := runOutput
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		os.MkdirAll(mp, 0755)
		os.WriteFile(filepath.Join(mp, "leftover"), []byte("x"), 0644)

		var calledClose bool
		runOutput = func(name string, args ...string) ([]byte, error) {
			return []byte(mp), nil
		}
		runCmd = func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				calledClose = true
			}
			return nil
		}
		err := umountAndClose("sda1")
		if err == nil || !strings.Contains(err.Error(), "rmdir") {
			t.Errorf("expected rmdir error, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called despite rmdir error")
		}
	})

	t.Run("luksClose error", func(t *testing.T) {
		savedCmd := runCmd
		savedOut := runOutput
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		os.MkdirAll(mp, 0755)

		runOutput = func(name string, args ...string) ([]byte, error) {
			return []byte(mp), nil
		}
		runCmd = func(name string, args ...string) error {
			if name == "cryptsetup" && args[0] == "luksClose" {
				return errors.New("close fail")
			}
			return nil
		}
		err := umountAndClose("sda1")
		if err == nil || !strings.Contains(err.Error(), "luksClose") {
			t.Errorf("expected luksClose error, got %v", err)
		}
	})
}

func TestUmountAndClose_nonLuks(t *testing.T) {
	savedMapped := checkMapped
	checkMapped = func(string) bool { return false }
	defer func() { checkMapped = savedMapped }()

	t.Run("skips cryptsetup calls", func(t *testing.T) {
		var cryptCalls int
		savedCmd := runCmd
		savedOut := runOutput
		runOutput = func(name string, args ...string) ([]byte, error) { return nil, nil }
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		runCmd = func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}

		err := umountAndClose("/dev/sda1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("expected 0 cryptsetup calls, got %d", cryptCalls)
		}
	})

	t.Run("resolves source path before searching", func(t *testing.T) {
		savedCmd := runCmd
		savedOut := runOutput
		runCmd = func(name string, args ...string) error { return nil }
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		dir := t.TempDir()
		srcFile := filepath.Join(dir, "sdc1")
		os.WriteFile(srcFile, nil, 0644)

		var searchArg string
		runOutput = func(name string, args ...string) ([]byte, error) {
			if name == "findmnt" {
				searchArg = strings.Join(args, " ")
			}
			return nil, nil
		}

		err := umountAndClose(srcFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(searchArg, srcFile) {
			t.Errorf("expected findmnt to search on resolved path %q, got %q", srcFile, searchArg)
		}
	})

	t.Run("searches mounts on source", func(t *testing.T) {
		var searchArg string
		savedCmd := runCmd
		savedOut := runOutput
		runCmd = func(name string, args ...string) error { return nil }
		defer func() { runCmd = savedCmd; runOutput = savedOut }()

		runOutput = func(name string, args ...string) ([]byte, error) {
			searchArg = strings.Join(args, " ")
			return nil, nil
		}

		err := umountAndClose("/dev/sda1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(searchArg, "/dev/sda1") {
			t.Errorf("expected findmnt to search on source, got %q", searchArg)
		}
		if strings.Contains(searchArg, "/dev/mapper/") {
			t.Errorf("unexpected mapper path in findmnt search: %q", searchArg)
		}
	})
}

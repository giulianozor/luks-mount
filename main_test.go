package main

import (
	"bytes"
	"errors"
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
		{"/dev/__test_dev__", "__test_dev__"},
		{"__test_dev__", "__test_dev__"},
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
	t.Run("success default mount", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(filepath.Join(home, "__test_dev__")) })

		err = openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
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

		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "/path/to/key", mp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(capturedArgs) < 5 || capturedArgs[1] != "--key-file" || capturedArgs[2] != "/path/to/key" {
			t.Errorf("key-file not passed: %v", capturedArgs)
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

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "mount failed") {
			t.Errorf("expected mount error, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called — cleanup should run on mount error")
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
}

func TestOpenAndMount_nonLuks(t *testing.T) {
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

	t.Run("mountpoint path exists as file", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
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
		if !calledClose {
			t.Error("luksClose was not called despite umount error")
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
		if err == nil || !strings.Contains(err.Error(), "luksClose") {
			t.Errorf("expected luksClose error, got %v", err)
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
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
		err   bool
	}{
		{"100M", 100 * 1024 * 1024, false},
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"1M", 1 * 1024 * 1024, false},
		{"256M", 256 * 1024 * 1024, false},
		{"", 0, true},
		{"M", 0, true},
		{"100", 0, true},
		{"100K", 0, true},
		{"-1M", 0, true},
		{"abcM", 0, true},
		{"0M", 0, true},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("parseSize(%q) expected error, got %d", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseSize(%q) unexpected error: %v", tt.input, err)
			} else if got != tt.want {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		}
	}
}

type cmdCall struct {
	name string
	args []string
}

func TestCreateContainer(t *testing.T) {
	t.Run("success without key file", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		err := createContainer(run, run, "test_container", "256M", "", 512)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(calls) != 5 {
			t.Fatalf("expected 5 calls, got %d: %v", len(calls), calls)
		}

		if calls[0].name != "dd" {
			t.Errorf("call 0: expected dd, got %s", calls[0].name)
		}
		if calls[1].name != "cryptsetup" || len(calls[1].args) < 2 || calls[1].args[0] != "luksFormat" || calls[1].args[1] != "--batch-mode" {
			t.Errorf("call 1: expected cryptsetup luksFormat --batch-mode, got %v", calls[1])
		}
		if calls[2].name != "cryptsetup" || len(calls[2].args) < 1 || calls[2].args[0] != "luksOpen" {
			t.Errorf("call 2: expected cryptsetup luksOpen, got %v", calls[2])
		}
		if calls[3].name != "mkfs.ext4" {
			t.Errorf("call 3: expected mkfs.ext4, got %s", calls[3].name)
		}
		if calls[4].name != "cryptsetup" || len(calls[4].args) < 1 || calls[4].args[0] != "luksClose" {
			t.Errorf("call 4: expected cryptsetup luksClose, got %v", calls[4])
		}
	})

	t.Run("success with key file", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		err := createContainer(run, run, "test_container", "256M", "keyfile", 512)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(calls) != 7 {
			t.Fatalf("expected 7 calls, got %d: %v", len(calls), calls)
		}

		if calls[0].name != "dd" || len(calls[0].args) < 1 || calls[0].args[0] != "if=/dev/urandom" {
			t.Errorf("call 0: expected dd urandom key file, got %v", calls[0])
		}
		if calls[1].name != "dd" || len(calls[1].args) < 1 || calls[1].args[0] != "if=/dev/zero" {
			t.Errorf("call 1: expected dd zero container, got %v", calls[1])
		}
		if calls[2].name != "cryptsetup" || len(calls[2].args) < 2 || calls[2].args[0] != "luksFormat" || calls[2].args[1] != "--batch-mode" {
			t.Errorf("call 2: expected cryptsetup luksFormat --batch-mode, got %v", calls[2])
		}
		if calls[3].name != "cryptsetup" || calls[3].args[0] != "luksAddKey" {
			t.Errorf("call 3: expected cryptsetup luksAddKey, got %v", calls[3])
		}
		if calls[4].name != "cryptsetup" || calls[4].args[0] != "luksOpen" {
			t.Errorf("call 4: expected cryptsetup luksOpen, got %v", calls[4])
		}
		if calls[5].name != "mkfs.ext4" {
			t.Errorf("call 5: expected mkfs.ext4, got %s", calls[5].name)
		}
		if calls[6].name != "cryptsetup" || calls[6].args[0] != "luksClose" {
			t.Errorf("call 6: expected cryptsetup luksClose, got %v", calls[6])
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := createContainer(run, run, "test", "invalid", "", 512)
		if err == nil {
			t.Error("expected error for invalid size, got nil")
		}
	})

	t.Run("size below minimum", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := createContainer(run, run, "test", "16M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "minimum container size is 32M") {
			t.Errorf("expected minimum size error, got %v", err)
		}
		err = createContainer(run, run, "test", "31M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "minimum container size is 32M") {
			t.Errorf("expected minimum size error for 31M, got %v", err)
		}
	})

	t.Run("dd container fails", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "dd" {
				return errors.New("dd failed")
			}
			return nil
		}
		err := createContainer(run, run, "test", "256M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "creating container") {
			t.Errorf("expected container creation error, got %v", err)
		}
	})

	t.Run("luksFormat fails", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksFormat" {
				return errors.New("luksFormat failed")
			}
			return nil
		}
		err := createContainer(run, run, "test", "256M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "luksFormat failed") {
			t.Errorf("expected luksFormat error, got %v", err)
		}
	})

	t.Run("luksOpen fails", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				return errors.New("luksOpen failed")
			}
			return nil
		}
		err := createContainer(run, run, "test", "256M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "luksOpen failed") {
			t.Errorf("expected luksOpen error, got %v", err)
		}
	})

	t.Run("mkfs fails cleans up luksClose", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "mkfs.ext4" {
				return errors.New("mkfs failed")
			}
			return nil
		}
		err := createContainer(run, run, "test", "256M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "mkfs.ext4 failed") {
			t.Errorf("expected mkfs.ext4 error, got %v", err)
		}
		found := false
		for _, c := range calls {
			if c.name == "cryptsetup" && len(c.args) > 0 && c.args[0] == "luksClose" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected luksClose cleanup after mkfs failure, calls: %v", calls)
		}
	})

	t.Run("luksClose fails", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, "test", "256M", "", 512)
		if err == nil || !strings.Contains(err.Error(), "luksClose failed") {
			t.Errorf("expected luksClose error, got %v", err)
		}
	})
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

func TestCreateContainerBlockSize(t *testing.T) {
	tests := []struct {
		size      string
		wantBS    string
		wantCount string
	}{
		{"50M", "32M", "2"},
		{"256M", "32M", "8"},
		{"1G", "32M", "32"},
		{"2G", "256M", "8"},
		{"10G", "256M", "40"},
		{"50G", "512M", "100"},
		{"200G", "1024M", "200"},
	}
	for _, tt := range tests {
		t.Run(tt.size, func(t *testing.T) {
			var calls []cmdCall
			run := func(name string, args ...string) error {
				calls = append(calls, cmdCall{name, args})
				return nil
			}
			createContainer(run, run, "test", tt.size, "", 512)

			if len(calls) < 1 || calls[0].name != "dd" {
				t.Fatal("expected dd as first call")
			}

			var foundBS, foundCount string
			for _, a := range calls[0].args {
				if bs, ok := strings.CutPrefix(a, "bs="); ok {
					foundBS = bs
				}
				if cnt, ok := strings.CutPrefix(a, "count="); ok {
					foundCount = cnt
				}
			}
			if foundBS != tt.wantBS {
				t.Errorf("bs=%q, want %q", foundBS, tt.wantBS)
			}
			if foundCount != tt.wantCount {
				t.Errorf("count=%q, want %q", foundCount, tt.wantCount)
			}
		})
	}
}

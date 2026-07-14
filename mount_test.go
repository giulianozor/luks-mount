package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

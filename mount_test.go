package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

		mp := filepath.Join(t.TempDir(), "mnt")
		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", mp)
		if err == nil || !strings.Contains(err.Error(), "mount failed") {
			t.Errorf("expected mount error, got %v", err)
		}
		if !calledClose {
			t.Error("luksClose was not called — cleanup should run on mount error")
		}
		if _, statErr := os.Stat(mp); !os.IsNotExist(statErr) {
			t.Error("freshly-created mountpoint should be removed on mount failure")
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
		if umountCalls != 0 {
			t.Errorf("expected no umount calls when findmnt fails, got %d", umountCalls)
		}
	})
}

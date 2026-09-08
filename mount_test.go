package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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

// exitStatus runs a tiny child process that exits with the requested code so
// the returned error is a genuine *exec.ExitError, indistinguishable from the
// one findmnt's own exit status produces via exec.Command.
func exitStatus(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an *exec.ExitError, got %#v", err)
	}
	if got := exitErr.ExitCode(); got != code {
		t.Fatalf("child exit code = %d, want %d", got, code)
	}
	return err
}

func TestProbeIsLuks(t *testing.T) {
	ok := func(name string, args ...string) ([]byte, error) { return nil, nil }
	fail := func(err error) func(string, ...string) ([]byte, error) {
		return func(name string, args ...string) ([]byte, error) { return nil, err }
	}

	tests := []struct {
		name    string
		run     func(string, ...string) ([]byte, error)
		want    bool
		wantErr bool
	}{
		{"cryptsetup exit 0 means LUKS", ok, true, false},
		{"cryptsetup exit 1 means not LUKS", fail(exitStatus(t, 1)), false, false},
		{"a plain error is a probe error", fail(errors.New("not luks")), false, true},
		{"a missing cryptsetup is a probe error", fail(fmt.Errorf("exec: %q: %w", "cryptsetup", exec.ErrNotFound)), false, true},
		{"another cryptsetup exit code is a probe error", fail(exitStatus(t, 4)), false, true},
		// cryptsetup 2.8+ reports a device it cannot open (a missing node, or
		// one the probe cannot access) as exit 4 plus this diagnostic, which
		// older cryptsetup versions called "not LUKS" via exit 1. Such a device
		// cannot be LUKS, so it must be a clean not-LUKS verdict, not a probe
		// error.
		{"cryptsetup cannot open the device and it is not LUKS", fail(fmt.Errorf("Device /dev/__test_dev__ does not exist or access denied.\n%w", exitStatus(t, 4))), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := probeIsLuks(tt.run, "/dev/__test_dev__")
			if got != tt.want {
				t.Errorf("probeIsLuks = %v, want %v", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("probeIsLuks err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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
		{"paths containing spaces are preserved whole", []byte("/mnt/my data\n"), []string{"/mnt/my data"}},
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

func TestCheckSourceMode(t *testing.T) {
	dir := t.TempDir()
	run := func(name, source string) {
		t.Helper()
		fi, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkSourceMode(fi, source); err != nil {
			t.Errorf("checkSourceMode(%q) = %v, want nil", source, err)
		}
	}
	reject := func(name, source, want string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			fi, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			err = checkSourceMode(fi, source)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("expected %q in error, got %v", want, err)
			}
		})
	}

	t.Run("accepts a regular non-empty file", func(t *testing.T) {
		f := filepath.Join(dir, "img")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		run("regular", f)
	})

	reject("directory", dir, "is a directory")
	reject("FIFO", makeFIFO(t), "not a regular file")
	reject("socket", makeSocket(t), "not a regular file")
	// A character device (e.g. /dev/tty) also carries os.ModeDevice like a
	// block device, so it must be rejected by type before the LUKS sniff opens
	// it -- reading one can block until a writer or event appears.
	t.Run("character device", func(t *testing.T) {
		if fi, err := os.Stat("/dev/zero"); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			t.Skip("/dev/zero is not a character device on this host")
		}
		fi, err := os.Stat("/dev/zero")
		if err != nil {
			t.Fatal(err)
		}
		err = checkSourceMode(fi, "/dev/zero")
		if err == nil || !strings.Contains(err.Error(), "not a regular file or block device") {
			t.Errorf("expected a char-device rejection, got %v", err)
		}
	})
	reject("empty file", func() string {
		f := filepath.Join(dir, "empty")
		if err := os.WriteFile(f, nil, 0644); err != nil {
			t.Fatal(err)
		}
		return f
	}(), "empty file")
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

	t.Run("rejects a character device key", func(t *testing.T) {
		if fi, err := os.Stat("/dev/zero"); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			t.Skip("/dev/zero is not a character device on this host")
		}
		err := checkKeyFile("/dev/zero", "key file")
		if err == nil || !strings.Contains(err.Error(), "character device") {
			t.Errorf("expected a character-device error, got %v", err)
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

	t.Run("permission-locked path surfaces the stat error", func(t *testing.T) {
		dir := t.TempDir()
		restricted := filepath.Join(dir, "restricted")
		if err := os.MkdirAll(filepath.Join(restricted, "key"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(restricted, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(restricted, 0755) })

		err := checkKeyFile(filepath.Join(restricted, "key"), "key file")
		if err == nil || !strings.Contains(err.Error(), "checking key file") {
			t.Errorf("expected a checking-key-file error, got %v", err)
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
		recordMountPointsForTest(t)

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mp := filepath.Join(home, "__test_dev__")
		if _, statErr := os.Stat(mp); os.IsNotExist(statErr) {
			t.Error("default mountpoint was not created under the home directory")
		}
		// The freshly created mount point must be recorded so a later unmount
		// knows it may clean it up. It is stored canonically (findmnt's target
		// resolution, e.g. /private/var on macOS), so look up the canonical
		// spelling of the home-relative mount point.
		set, setErr := loadMountPoints()
		if setErr != nil {
			t.Fatalf("unexpected error reading state: %v", setErr)
		}
		canonMP, canonErr := filepath.EvalSymlinks(mp)
		if canonErr != nil {
			t.Fatalf("resolving canonical mount point: %v", canonErr)
		}
		if _, ok := set[canonMP]; !ok {
			t.Errorf("created mount point was not recorded (canonical %q): %v", canonMP, set)
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

	t.Run("a home-directory lookup failure surfaces clearly", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		orig := userHomeDir
		userHomeDir = func() (string, error) { return "", errors.New("no home") }
		t.Cleanup(func() { userHomeDir = orig })

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "")
		if err == nil || !strings.Contains(err.Error(), "getting home directory") {
			t.Errorf("expected a home-directory lookup error, got %v", err)
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

	t.Run("an explicit relative mount point is normalized to absolute", func(t *testing.T) {
		// findmnt and the recorded/cleanup paths compare the mount target as an
		// absolute path; a literal relative "-m tmp/data" would never equal the
		// absolute path mount(2) actually uses, so a later unmount could not
		// match (or clean up) it. Run from a dedicated working directory so the
		// relative name resolves deterministically to a fresh absolute path.
		dir := t.TempDir()
		oldWd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chdir(oldWd) })

		var target string
		runCmd := func(name string, args ...string) error {
			if name == "mount" && len(args) >= 2 {
				target = args[len(args)-1]
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err = openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", "rel-mounted-dir")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target == "" {
			t.Fatal("mount was not invoked; cannot verify the normalized target")
		}
		// openAndMount resolves a relative mount point with filepath.Abs against
		// the process working directory; compute the same expectation here.
		want, _ := filepath.Abs("rel-mounted-dir")
		if target != want {
			t.Errorf("mount target = %q, want the absolute path %q", target, want)
		}
		// The directory must be created at that absolute target (not at a
		// literal relative path in some other working directory).
		if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
			t.Errorf("mount point directory %q should have been created (err=%v)", target, err)
		}
	})

	t.Run("records the canonical mount point so cleanup matches findmnt", func(t *testing.T) {
		// openAndMount mounts at the literal (symlink) spelling, but findmnt
		// reports a mount target by its resolved canonical path. The record must
		// store the canonical path so a later unmount, which looks up findmnt's
		// reported target in the record, can still recognize and clean it up.
		recordMountPointsForTest(t)

		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		if err := os.MkdirAll(real, 0755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "alias")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		// Mount at a path through the symlink (a freshly created target, so
		// createdMountpoint is true and the record is written).
		realTarget := filepath.Join(real, "mnt")
		linkTarget := filepath.Join(link, "mnt")
		if err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", linkTarget); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// The canonical record is what EvalSymlinks reports for the created
		// target (on macOS /var resolves to /private/var, changing the prefix);
		// resolve the expected path the same way so the comparison is exact.
		want, werr := filepath.EvalSymlinks(realTarget)
		if werr != nil {
			t.Fatalf("resolving expected canonical path: %v", werr)
		}

		set, err := loadMountPoints()
		if err != nil {
			t.Fatalf("unexpected error reading state: %v", err)
		}
		if _, ok := set[want]; !ok {
			t.Errorf("record should store the canonical path %q; got %v", want, set)
		}
		if _, ok := set[linkTarget]; ok {
			t.Errorf("record should not store the literal symlink spelling %q; got %v", linkTarget, set)
		}
	})

	t.Run("mountpoint creation failure is surfaced", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		locked := filepath.Join(dir, "locked")
		if err := os.MkdirAll(locked, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(locked, 0755) })

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(locked, "child"))
		if err == nil || !strings.Contains(err.Error(), "creating mountpoint") {
			t.Errorf("expected a creating-mountpoint error, got %v", err)
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

	t.Run("closes an open mapping when mount point collisions run out", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "c.img")
		if err := os.WriteFile(src, []byte("LUKS\xba\xbe\x00\x02padding"), 0644); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "mnt")
		for i := 0; i <= 16; i++ {
			p := base + strings.Repeat(".mnt", i)
			if err := os.WriteFile(p, []byte("block"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		var opens, closes int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 {
				switch args[0] {
				case "luksOpen":
					opens++
				case "luksClose":
					closes++
				}
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, src, "", base)
		if err == nil || !strings.Contains(err.Error(), "no free mount point") {
			t.Fatalf("expected a bounded-collision error, got %v", err)
		}
		if opens != 1 {
			t.Fatalf("expected the mapping to be opened, got %d luksOpen calls", opens)
		}
		if closes != 1 {
			t.Errorf("an open mapping must be closed when the collisions run out, got %d luksClose calls", closes)
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
			return nil, exitStatus(t, 1)
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

	t.Run("warns when the mapping node does not appear after luksOpen", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "luks.img")
		if err := os.WriteFile(src, []byte("LUKS\xba\xbe\x00\x02padding"), 0644); err != nil {
			t.Fatal(err)
		}
		var luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		origDevStat := devStat
		devStat = func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		}
		t.Cleanup(func() { devStat = origDevStat })
		origTries := waitForDeviceTries
		waitForDeviceTries = 3
		t.Cleanup(func() { waitForDeviceTries = origTries })

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		defer func() { os.Stderr = oldStderr }()

		err = openAndMount(runCmd, runOutput, src, "", filepath.Join(dir, "mnt"))
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		out := buf.String()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if luksOpenCalls != 1 {
			t.Errorf("expected exactly one luksOpen, got %d", luksOpenCalls)
		}
		if !strings.Contains(out, "not found after luksOpen") {
			t.Errorf("expected a settling-hint warning, stderr=%q", out)
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

	t.Run("rejects a key file hard-linked to the source", func(t *testing.T) {
		var luksOpenCalls int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		dir := t.TempDir()
		src := filepath.Join(dir, "container.img")
		if err := os.WriteFile(src, []byte("LUKS\xba\xbe"), 0600); err != nil {
			t.Fatal(err)
		}
		// A distinct name for the same inode cannot be caught by the
		// path/symlink comparison, only by comparing file identities.
		key := filepath.Join(dir, "container.img.hardlink")
		if err := os.Link(src, key); err != nil {
			// Some filesystems (e.g. FAT) have no hardlink support; skip rather
			// than fail the suite for the platform's storage choice.
			t.Skipf("hardlinks unavailable: %v", err)
		}

		err := openAndMount(runCmd, runOutput, src, key, filepath.Join(dir, "mnt"))
		if err == nil || !strings.Contains(err.Error(), "same file") {
			t.Errorf("expected a same-file error, got %v", err)
		}
		if luksOpenCalls != 0 {
			t.Errorf("luksOpen must not be attempted for a hard-linked key, got %d calls", luksOpenCalls)
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
		var mountCalls, luksOpenCalls, luksCloseCalls int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountCalls++
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenCalls++
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				luksCloseCalls++
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
		// luksOpen succeeded before the mount point probe; the mapping must be
		// closed again or the error path leaks it.
		if luksOpenCalls != 1 || luksCloseCalls != 1 {
			t.Errorf("expected one open and one close (open=%d, close=%d)", luksOpenCalls, luksCloseCalls)
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

	t.Run("closes an open mapping when refusing the root mount point", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "c.img")
		if err := os.WriteFile(src, []byte("LUKS\xba\xbe\x00\x02padding"), 0644); err != nil {
			t.Fatal(err)
		}
		var opens, closes int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 {
				switch args[0] {
				case "luksOpen":
					opens++
				case "luksClose":
					closes++
				}
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, src, "", "/")
		if err == nil || !strings.Contains(err.Error(), "filesystem root") {
			t.Fatalf("expected a root-mount refusal, got %v", err)
		}
		if opens != 1 {
			t.Fatalf("expected the mapping to be opened, got %d luksOpen calls", opens)
		}
		if closes != 1 {
			t.Errorf("an open mapping must be closed after the root refusal, got %d luksClose calls", closes)
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
		// Even though the mapping could not be closed, the mount point lmount
		// created is lmount's to clean up; a double failure must not leak it.
		if _, statErr := os.Stat(mp); !os.IsNotExist(statErr) {
			t.Errorf("created mount point leaked after a double failure (stat err: %v)", statErr)
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

		origProbe := mountPointInUse
		mountPointInUse = func(path string) (bool, error) { return false, nil }
		defer func() { mountPointInUse = origProbe }()

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

	t.Run("empty source is rejected before any probe or open", func(t *testing.T) {
		var opens int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				opens++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }

		err := openAndMount(runCmd, runOutput, "", "", "")
		if err == nil || !strings.Contains(err.Error(), "cannot determine name from empty source") {
			t.Fatalf("expected an empty-source error, got %v", err)
		}
		// Nothing was opened, so nothing may be closed either; the up-front
		// rejection makes a leaked LUKS mapping impossible for an empty source.
		if opens != 0 {
			t.Error("no luksOpen may run for an empty source")
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

		origProbe := mountPointInUse
		mountPointInUse = func(path string) (bool, error) { return false, nil }
		defer func() { mountPointInUse = origProbe }()

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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", filepath.Join(t.TempDir(), "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mountArgs) < 1 || mountArgs[0] != "/dev/__test_dev__" {
			t.Errorf("expected mount source /dev/__test_dev__, got %v", mountArgs)
		}
	})

	t.Run("resolves a bare source name to an existing /dev node", func(t *testing.T) {
		// The bare name "fd" does not exist relative to the working directory,
		// but /dev/fd does on any real system (Linux and macOS). openAndMount
		// should resolve it before continuing.
		if _, err := os.Stat("/dev/fd"); err != nil {
			t.Skip("/dev/fd unavailable")
		}
		// /dev/fd is a directory, so the resolved source must be mode-checked
		// like an explicit source and rejected as a directory. This confirms the
		// resolution happened (the bare name is not a relative file) while
		// exercising the same validation an explicit "-s /dev/fd" would get.
		runCmd := func(name string, args ...string) error {
			t.Errorf("no command should run for a resolved /dev/ directory, got %s %v", name, args)
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			t.Errorf("no privileged probe should run for a resolved /dev/ directory, got %s %v", name, args)
			return nil, exitStatus(t, 1)
		}

		err := openAndMount(runCmd, runOutput, "fd", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory rejection for the resolved source /dev/fd, got %v", err)
		}
	})

	t.Run("rejects a bare source resolving to a character device", func(t *testing.T) {
		// A bare "zero" resolves to /dev/zero, a character device that can never
		// back a mount. It must be mode-checked (like an explicit "-s /dev/zero"
		// is) and rejected with a clear message rather than failing cryptically
		// at mount after resolving the /dev/ node.
		if _, err := os.Stat("/dev/zero"); err != nil {
			t.Skip("/dev/zero unavailable")
		}
		runCmd := func(name string, args ...string) error {
			t.Errorf("no command should run for a rejected resolved char device, got %s %v", name, args)
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			t.Errorf("no privileged probe should run for a rejected resolved char device, got %s %v", name, args)
			return nil, exitStatus(t, 1)
		}

		err := openAndMount(runCmd, runOutput, "zero", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil || !strings.Contains(err.Error(), "not a regular file or block device") {
			t.Errorf("expected a char-device rejection for the resolved source /dev/zero, got %v", err)
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
			return nil, exitStatus(t, 1)
		}

		err := openAndMount(runCmd, runOutput, src, "", filepath.Join(dir, "mnt"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("expected 0 cryptsetup calls, got %d", cryptCalls)
		}
	})

	t.Run("says when a plain source is not mounted", func(t *testing.T) {
		var runs []cmdCall
		runCmd := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		src := filepath.Join(t.TempDir(), "plain.img")
		os.WriteFile(src, []byte("x"), 0644)

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = umountAndClose(checkMapped, runCmd, noProbe, runOutput, src)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if !strings.Contains(buf.String(), "Nothing mounted") {
			t.Errorf("expected a nothing-mounted note, got %q", buf.String())
		}
		if len(runs) != 0 {
			t.Errorf("no commands should run for an unmounted plain source, got %v", runs)
		}
	})

	t.Run("does not hang probing a FIFO source", func(t *testing.T) {
		var runs []cmdCall
		runCmd := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		fifo := makeFIFO(t)

		// The "Nothing mounted" hint probes the source for the LUKS magic by
		// opening it for reading; a FIFO open for reading would block forever
		// waiting for a writer. The probe must skip non-regular entries.
		done := make(chan error, 1)
		go func() {
			done <- umountAndClose(checkMapped, runCmd, noProbe, runOutput, fifo)
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("umountAndClose blocked probing a FIFO source")
		}
		if len(runs) != 0 {
			t.Errorf("no commands should run for an unmounted FIFO, got %v", runs)
		}
	})

	t.Run("rejects a missing bare source name instead of a cryptic findmnt failure", func(t *testing.T) {
		var runs []cmdCall
		runCmd := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "definitely-not-a-device")
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a does-not-exist error, got %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("no commands should run for a missing source, got %v", runs)
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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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
			return nil, exitStatus(t, 1)
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
			return nil, exitStatus(t, 1)
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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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
			return nil, exitStatus(t, 1)
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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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

	t.Run("missing bare source name is rejected, not probed", func(t *testing.T) {
		var cryptCalls int
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, exitStatus(t, 1)
		}

		err := openAndMount(runCmd, runOutput, "no-such-device-node", "", filepath.Join(t.TempDir(), "mnt"))
		if err == nil {
			t.Fatal("expected an error, got none")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' error for a missing bare name, got %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("a missing bare source must not trigger a privileged probe, got %d cryptsetup calls", cryptCalls)
		}
	})

	t.Run("rejects a source nested under a file without probing cryptsetup", func(t *testing.T) {
		// ENOTDIR: "…/plainfile/sub" can never back a mount, and os.Stat has
		// already said so. Reject it clearly instead of surrendering a sudo
		// prompt to a cryptsetup probe on a path that can only fail cryptically.
		var cryptCalls int
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, exitStatus(t, 1)
		}

		file := filepath.Join(t.TempDir(), "plainfile")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := openAndMount(runCmd, runOutput, filepath.Join(file, "sub"), "", "")
		if err == nil || !strings.Contains(err.Error(), "cannot be accessed") {
			t.Errorf("expected a 'cannot be accessed' error for an ENOTDIR source, got %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup must not be probed on an ENOTDIR source, got %d calls", cryptCalls)
		}
	})

	t.Run("rejects a symbolic-link loop source without probing cryptsetup", func(t *testing.T) {
		// ELOOP: a self-referential symlink can never name a mount source; do
		// not waste a privileged probe on it.
		var cryptCalls int
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil, exitStatus(t, 1)
		}

		loop := filepath.Join(t.TempDir(), "loop")
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
		err := openAndMount(runCmd, runOutput, loop, "", "")
		if err == nil || !strings.Contains(err.Error(), "cannot be accessed") {
			t.Errorf("expected a 'cannot be accessed' error for an ELOOP source, got %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup must not be probed on an ELOOP source, got %d calls", cryptCalls)
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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

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

func TestOpenAndMountBusyMountPoint(t *testing.T) {
	type probeFn func(path string) (bool, error)
	let := func(p probeFn) {
		orig := mountPointInUse
		mountPointInUse = p
		t.Cleanup(func() { mountPointInUse = orig })
	}

	t.Run("refuses a target that is already an active mount", func(t *testing.T) {
		let(func(path string) (bool, error) { return true, nil })
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		busy := filepath.Join(t.TempDir(), "busy")
		if err := os.MkdirAll(busy, 0755); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", busy)
		if err == nil || !strings.Contains(err.Error(), "refusing to mount over") {
			t.Fatalf("expected a busy-mount-point refusal, got %v", err)
		}
		if !strings.Contains(err.Error(), "already mounted") {
			t.Errorf("expected the refusal to name the busy target, got %v", err)
		}
	})

	t.Run("closes an opened LUKS mapping when refusing a busy target", func(t *testing.T) {
		let(func(path string) (bool, error) { return true, nil })
		var closes int
		runCmd := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closes++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		busy := filepath.Join(t.TempDir(), "busy")
		if err := os.MkdirAll(busy, 0755); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", busy)
		if err == nil {
			t.Fatal("expected a refusal for a busy mount point")
		}
		if closes == 0 {
			t.Error("the opened LUKS mapping must be closed after the refusal")
		}
	})

	t.Run("mounts when the directory is not a mount point", func(t *testing.T) {
		var probed string
		let(func(path string) (bool, error) { probed = path; return false, nil })
		var mountArgs []string
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mountArgs = append(mountArgs, args...)
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		free := filepath.Join(t.TempDir(), "free")
		if err := os.MkdirAll(free, 0755); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", free)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mountArgs) < 2 || mountArgs[1] != free {
			t.Errorf("expected the mount to target %q, got %v", free, mountArgs)
		}
		if probed != free {
			t.Errorf("probe was asked about %q, want %q", probed, free)
		}
	})

	t.Run("surfaces a probe failure instead of mounting", func(t *testing.T) {
		let(func(path string) (bool, error) {
			return false, errors.New("findmnt exploded")
		})
		var mounts int
		runCmd := func(name string, args ...string) error {
			if name == "mount" {
				mounts++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		unknown := filepath.Join(t.TempDir(), "unknown")
		if err := os.MkdirAll(unknown, 0755); err != nil {
			t.Fatal(err)
		}

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", unknown)
		if err == nil || !strings.Contains(err.Error(), "already mounted: findmnt exploded") {
			t.Fatalf("expected the probe failure to surface, got %v", err)
		}
		if mounts != 0 {
			t.Error("no mount may proceed when the busy check cannot be answered")
		}
	})

	t.Run("skips the probe for a freshly created mount point", func(t *testing.T) {
		var called bool
		let(func(path string) (bool, error) { called = true; return true, nil })
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		fresh := filepath.Join(t.TempDir(), "fresh")

		err := openAndMount(runCmd, runOutput, "/dev/__test_dev__", "", fresh)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if called {
			t.Error("a freshly created mount point cannot already be mounted; the probe must be skipped")
		}
	})
}

func TestProbeMountPointInUse(t *testing.T) {
	t.Run("queries findmnt by target (-T), not source (-S)", func(t *testing.T) {
		// The busy-mount check is about whether the path is a mount *target*,
		// so findmnt must filter by -T. Filtering by -S (source) would search
		// by the backing device and never match a target directory, silently
		// bypassing the busy-mount refusal for every regular mount.
		var usedTarget, usedSource bool
		lookupDir := filepath.Join(t.TempDir(), "mnt")
		probe := func(name string, args ...string) ([]byte, error) {
			for _, a := range args {
				if a == "-T" {
					usedTarget = true
				}
				if a == "-S" {
					usedSource = true
				}
				if a == lookupDir {
					return []byte(lookupDir), nil
				}
			}
			return []byte{}, nil
		}
		busy, err := probeMountPointInUse(probe, lookupDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !busy {
			t.Error("expected the target to be reported as busy")
		}
		if !usedTarget {
			t.Error("findmnt must be queried with -T (target) to detect a busy mount point")
		}
		if usedSource {
			t.Error("findmnt must not be queried with -S (source) for a target-directory check")
		}
	})

	t.Run("exit 1 is a clean no-match, not an error", func(t *testing.T) {
		probe := func(name string, args ...string) ([]byte, error) { return []byte{}, exitStatus(t, 1) }
		busy, err := probeMountPointInUse(probe, "/some/absent/path")
		if err != nil {
			t.Fatalf("exit 1 (no match) must not be an error: %v", err)
		}
		if busy {
			t.Error("a no-match target must not be reported busy")
		}
	})

	t.Run("a genuine failure is surfaced", func(t *testing.T) {
		probe := func(name string, args ...string) ([]byte, error) { return nil, errors.New("findmnt exploded") }
		if _, err := probeMountPointInUse(probe, "/some/path"); err == nil {
			t.Error("expected a probe failure to surface")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Error("luksClose was not called")
		}
	})

	t.Run("a directory sharing the source's name does not block detaching an open mapping", func(t *testing.T) {
		// The default mount point for a source is ~/<basename>, so a user
		// running "lmount -u <basename>" from their home (where the mount
		// point directory of that basename exists) must still be able to
		// unmount: the open mapping is what identifies the detach, and the
		// same-named directory is nothing to reject as a source. Without the
		// encrypted override this returns a misleading "is a directory"
		// error instead of unmounting.
		dir := t.TempDir()
		src := filepath.Join(dir, "container")
		if err := os.MkdirAll(src, 0755); err != nil {
			t.Fatal(err)
		}
		mp := filepath.Join(dir, "mp")
		recordMountPointsForTest(t)

		var unmountCalls, luksCloseCalls int
		runCmd := func(name string, args ...string) error {
			if name == "umount" {
				unmountCalls++
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				luksCloseCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, src)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if unmountCalls != 1 {
			t.Errorf("expected one unmount for the found target, got %d", unmountCalls)
		}
		if luksCloseCalls != 1 {
			t.Errorf("expected one luksClose, got %d", luksCloseCalls)
		}
	})

	t.Run("with mounts", func(t *testing.T) {
		dir := t.TempDir()
		mp1 := filepath.Join(dir, "mp1")
		mp2 := filepath.Join(dir, "mp2")
		os.MkdirAll(mp1, 0755)
		os.MkdirAll(mp2, 0755)
		// The targets were created by an earlier mount, so record them as
		// lmount-created; only recorded directories may be cleaned up.
		recordMountPointsForTest(t, mp1, mp2)

		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp1 + "\n" + mp2), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
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

	t.Run("preserves a pre-existing mount point directory it did not create", func(t *testing.T) {
		dir := t.TempDir()
		mp := filepath.Join(dir, "mp")
		os.MkdirAll(mp, 0755)
		// An empty, unrecorded target (e.g. an explicit -m over a user's own
		// directory) must survive the unmount: lmount only cleans up mount
		// points it created itself.
		recordMountPointsForTest(t)

		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			return []byte(mp), nil
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(mp); err != nil {
			t.Errorf("pre-existing mount point %q should have been preserved, got stat err %v", mp, err)
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
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
		recordMountPointsForTest(t, mnt)

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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/")
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-source error for the root, got %v", err)
		}
	})

	t.Run("skip removal when not empty", func(t *testing.T) {
		dir := t.TempDir()
		mp := filepath.Join(dir, "mnt")
		os.MkdirAll(mp, 0755)
		os.WriteFile(filepath.Join(mp, "leftover"), []byte("x"), 0644)
		// Recorded mount point whose directory still holds a user-created file:
		// the record authorizes removal, but removeIfEmpty must keep it.
		recordMountPointsForTest(t, mp)

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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "__test_dev__")
		if err == nil || !strings.Contains(err.Error(), "luksClose __test_dev__") {
			t.Errorf("expected a luksClose error naming the mapping, got %v", err)
		}
	})
}

// newMapperFixture wires the fake /dev/mapper and /sys roots to dir and adds a
// mapping entry: the named mapping is a symlink to a dm block device whose
// sysfs slaves directory contains the given backing device.
// noProbe is an umountAndClose runOutput-style seam stub for tests where the
// differently-named-mapping probe is not expected to succeed. Returning an
// error makes mappingForSource report "no mapping", matching a probe that
// found nothing (or that the test does not want to exercise).
func noProbe(name string, args ...string) ([]byte, error) {
	return nil, errors.New("no LUKS-mapping probe expected")
}

func newMapperFixture(t *testing.T, dir string, mapping, backing string) {
	t.Helper()
	mapper := filepath.Join(dir, "mapper")
	sys := filepath.Join(dir, "sys")
	if err := os.MkdirAll(mapper, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "dm-0"), filepath.Join(mapper, mapping)); err != nil {
		t.Fatal(err)
	}
	slaves := filepath.Join(sys, "dm-0", "slaves")
	if err := os.MkdirAll(filepath.Join(slaves, backing), 0755); err != nil {
		t.Fatal(err)
	}
	oldMapper, oldSys := mapperDir, sysClassBlock
	mapperDir, sysClassBlock = mapper, sys
	t.Cleanup(func() { mapperDir, sysClassBlock = oldMapper, oldSys })
}

// recordMountPointsForTest redirects the mount-point state seam to a temp file
// preloaded with the given paths, so umount cleanup tests exercise the
// recorded-directory path without touching the developer's real state file.
func recordMountPointsForTest(t *testing.T, paths ...string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "mounts.json")
	orig := mountPointStatePath
	mountPointStatePath = func() (string, error) { return f, nil }
	t.Cleanup(func() { mountPointStatePath = orig })
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[p] = struct{}{}
	}
	if err := saveMountPoints(set); err != nil {
		t.Fatal(err)
	}
}

func TestMountPointStatePath(t *testing.T) {
	t.Run("uses XDG_STATE_HOME when set absolute", func(t *testing.T) {
		old, had := os.LookupEnv("XDG_STATE_HOME")
		if err := os.Setenv("XDG_STATE_HOME", "/var/state"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if had {
				os.Setenv("XDG_STATE_HOME", old)
			} else {
				os.Unsetenv("XDG_STATE_HOME")
			}
		}()
		p, err := mountPointStatePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := filepath.Join("/var/state", "lmount", "mounts.json"); p != want {
			t.Errorf("mountPointStatePath = %q, want %q", p, want)
		}
	})

	t.Run("refuses a relative XDG_STATE_HOME", func(t *testing.T) {
		old, had := os.LookupEnv("XDG_STATE_HOME")
		if err := os.Setenv("XDG_STATE_HOME", "rel/state"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if had {
				os.Setenv("XDG_STATE_HOME", old)
			} else {
				os.Unsetenv("XDG_STATE_HOME")
			}
		}()
		if _, err := mountPointStatePath(); err == nil {
			t.Error("expected an error for a relative XDG_STATE_HOME")
		}
	})

	t.Run("falls back under the home directory", func(t *testing.T) {
		old, had := os.LookupEnv("XDG_STATE_HOME")
		os.Unsetenv("XDG_STATE_HOME")
		defer func() {
			if had {
				os.Setenv("XDG_STATE_HOME", old)
			}
		}()
		origHome := userHomeDir
		userHomeDir = func() (string, error) { return "/home/lu", nil }
		t.Cleanup(func() { userHomeDir = origHome })
		p, err := mountPointStatePath()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := filepath.Join("/home/lu", ".local", "state", "lmount", "mounts.json"); p != want {
			t.Errorf("mountPointStatePath = %q, want %q", p, want)
		}
	})
}

func TestMountPointState(t *testing.T) {
	t.Run("missing file is an empty set", func(t *testing.T) {
		recordMountPointsForTest(t)
		set, err := loadMountPoints()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(set) != 0 {
			t.Errorf("expected an empty set, got %v", set)
		}
	})

	t.Run("round-trips recorded and missing entries", func(t *testing.T) {
		recordMountPointsForTest(t, "/a/mp1", "/b/mp2")
		set, err := loadMountPoints()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := set["/a/mp1"]; !ok {
			t.Error("mp1 was not recorded")
		}
		if _, ok := set["/b/mp2"]; !ok {
			t.Error("mp2 was not recorded")
		}
		if _, ok := set["/c/mp3"]; ok {
			t.Error("mp3 should not be recorded")
		}
	})

	t.Run("a corrupt state file is returned as an error", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "mounts.json")
		if err := os.WriteFile(f, []byte("{not json"), 0600); err != nil {
			t.Fatal(err)
		}
		orig := mountPointStatePath
		mountPointStatePath = func() (string, error) { return f, nil }
		t.Cleanup(func() { mountPointStatePath = orig })
		if _, err := loadMountPoints(); err == nil {
			t.Error("expected an error for a corrupt state file")
		}
	})

	t.Run("recorded entries can be forgotten by a later save", func(t *testing.T) {
		recordMountPointsForTest(t, "/a/mp1", "/b/mp2")
		set, err := loadMountPoints()
		if err != nil {
			t.Fatal(err)
		}
		delete(set, "/a/mp1")
		if err := saveMountPoints(set); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		after, err := loadMountPoints()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := after["/a/mp1"]; ok {
			t.Error("mp1 should have been forgotten")
		}
		if _, ok := after["/b/mp2"]; !ok {
			t.Error("mp2 should still be recorded")
		}
	})

	t.Run("a failed save leaves the previous state file intact", func(t *testing.T) {
		// The state file is written via a same-directory temp file + atomic
		// rename, so a save that cannot land (here: the directory turned
		// read-only, so the temp file cannot be created) must leave the prior,
		// complete state untouched and drop no temp-file litter behind.
		dir := t.TempDir()
		f := filepath.Join(dir, "mounts.json")
		orig := mountPointStatePath
		mountPointStatePath = func() (string, error) { return f, nil }
		t.Cleanup(func() { mountPointStatePath = orig })

		good := map[string]struct{}{"/a/mp1": {}, "/b/mp2": {}}
		if err := saveMountPoints(good); err != nil {
			t.Fatalf("initial save: %v", err)
		}
		before, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(before) == 0 {
			t.Fatal("initial state file is empty")
		}

		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0700) })

		if err := saveMountPoints(map[string]struct{}{"/a/mp1": {}}); err == nil {
			t.Fatal("expected the save to fail with a read-only state directory")
		}
		after, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Errorf("failed save corrupted the state file:\nbefore: %q\nafter:  %q", before, after)
		}
		if litter, _ := filepath.Glob(filepath.Join(dir, "mounts-*.tmp")); len(litter) != 0 {
			t.Errorf("failed save left temp files behind: %v", litter)
		}
	})

	t.Run("a successful save is atomic, always 0600, and leaves no temp file", func(t *testing.T) {
		// The rename-based write must also normalize the mode of a
		// pre-existing state file: os.WriteFile only applies its mode on
		// create, so an older or admin-created loose-permission mounts.json
		// kept its mode across every in-place rewrite. The fresh temp file is
		// born 0600 and renamed over the target, so the state file is always
		// owner-only no matter what preceded it.
		dir := t.TempDir()
		f := filepath.Join(dir, "mounts.json")
		if err := os.WriteFile(f, []byte("stale 0644"), 0644); err != nil {
			t.Fatal(err)
		}
		orig := mountPointStatePath
		mountPointStatePath = func() (string, error) { return f, nil }
		t.Cleanup(func() { mountPointStatePath = orig })

		if err := saveMountPoints(map[string]struct{}{"/x": {}}); err != nil {
			t.Fatalf("save: %v", err)
		}
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("state file mode = %o, want 0600", perm)
		}
		set, err := loadMountPoints()
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if _, ok := set["/x"]; !ok {
			t.Errorf("state did not round-trip: %v", set)
		}
		if litter, _ := filepath.Glob(filepath.Join(dir, "mounts-*.tmp")); len(litter) != 0 {
			t.Errorf("successful save left temp files behind: %v", litter)
		}
	})

	t.Run("concurrent records never lose an entry", func(t *testing.T) {
		// Parallel lmount invocations (a script mounting several images at
		// once) each load the same starting set, add their own path, and save.
		// Without the state lock the last writer wins and the other records
		// silently vanish, so those mount point directories are never cleaned
		// up. Run enough contenders that the old unlocked code reliably drops
		// entries, then require every one to survive.
		dir := t.TempDir()
		f := filepath.Join(dir, "mounts.json")
		orig := mountPointStatePath
		mountPointStatePath = func() (string, error) { return f, nil }
		t.Cleanup(func() { mountPointStatePath = orig })

		const n = 30
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- recordMountPoint(fmt.Sprintf("/mnt/image%d", i))
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("recordMountPoint: %v", err)
			}
		}
		set, err := loadMountPoints()
		if err != nil {
			t.Fatal(err)
		}
		if len(set) != n {
			t.Fatalf("state has %d entries, want %d: %v", len(set), n, set)
		}
		for i := 0; i < n; i++ {
			if _, ok := set[fmt.Sprintf("/mnt/image%d", i)]; !ok {
				t.Errorf("concurrent record for image%d was lost", i)
			}
		}
	})

	t.Run("lockState blocks another writer until released", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "mounts.json")
		orig := mountPointStatePath
		mountPointStatePath = func() (string, error) { return f, nil }
		t.Cleanup(func() { mountPointStatePath = orig })

		release, err := lockState()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- recordMountPoint("/held") }()
		select {
		case <-done:
			t.Fatal("recordMountPoint returned while the lock was held")
		case <-time.After(150 * time.Millisecond):
		}
		release()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		set, err := loadMountPoints()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := set["/held"]; !ok {
			t.Errorf("entry was not recorded: %v", set)
		}
	})
}

func TestMappingForSource(t *testing.T) {
	t.Run("matches a mapping whose backing carries the source's LUKS UUID", func(t *testing.T) {
		dir := t.TempDir()
		newMapperFixture(t, dir, "myvol", "loop9")
		newMapperFixture(t, dir, "other", "sdb5")
		src := "luks.img"
		u := []byte("0bc3f7d6-3d26-4a89-a6b9-6d0d4d5f2001\n")
		run := func(name string, args ...string) ([]byte, error) {
			if name != "cryptsetup" || len(args) < 1 || args[0] != "luksUUID" {
				return nil, exitStatus(t, 1)
			}
			if args[1] == src || args[1] == "/dev/loop9" {
				return u, nil
			}
			return nil, exitStatus(t, 1)
		}
		if got := mappingForSource(run, src); got != "myvol" {
			t.Errorf("mappingForSource = %q, want myvol", got)
		}
	})

	t.Run("returns empty when no open mapping has a matching UUID", func(t *testing.T) {
		dir := t.TempDir()
		newMapperFixture(t, dir, "myvol", "loop9")
		src := "luks.img"
		run := func(name string, args ...string) ([]byte, error) {
			if name != "cryptsetup" || len(args) < 1 || args[0] != "luksUUID" {
				return nil, exitStatus(t, 1)
			}
			if args[1] == src {
				return []byte("source-uuid\n"), nil
			}
			return nil, exitStatus(t, 1)
		}
		if got := mappingForSource(run, src); got != "" {
			t.Errorf("mappingForSource = %q, want no mapping", got)
		}
	})

	t.Run("returns empty when the source is not a LUKS container", func(t *testing.T) {
		dir := t.TempDir()
		newMapperFixture(t, dir, "myvol", "loop9")
		run := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }
		if got := mappingForSource(run, "plain.img"); got != "" {
			t.Errorf("mappingForSource = %q, want no mapping for a non-LUKS source", got)
		}
	})
}

func TestUmountAndCloseFindsDifferentlyNamedMapping(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "luks.img")
	if err := os.WriteFile(img, []byte(luksMagic), 0600); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "mp")
	if err := os.MkdirAll(mp, 0755); err != nil {
		t.Fatal(err)
	}
	newMapperFixture(t, dir, "myvol", "loop9")

	var umountArgs, closeNames []string
	runCmd := func(name string, args ...string) error {
		switch {
		case name == "umount":
			umountArgs = append(umountArgs, args...)
		case name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose":
			closeNames = append(closeNames, args[1])
		}
		return nil
	}
	runOutput := func(name string, args ...string) ([]byte, error) {
		switch {
		case name == "cryptsetup" && len(args) > 0 && args[0] == "luksUUID":
			return []byte("uuid"), nil
		case name == "findmnt":
			return []byte(mp), nil
		}
		return nil, exitStatus(t, 1)
	}
	checkMapped := func(name string) bool { return false }

	err := umountAndClose(checkMapped, runCmd, runOutput, runOutput, img)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(umountArgs) != 1 || umountArgs[0] != mp {
		t.Errorf("expected umount %s, got %v", mp, umountArgs)
	}
	if len(closeNames) != 1 || closeNames[0] != "myvol" {
		t.Errorf("expected luksClose myvol, got %v", closeNames)
	}
}

// TestUmountAndCloseUsesPrivilegedMappingProbe verifies that the
// differently-named-mapping lookup is driven through the privileged runOutput
// seam (sudo cryptsetup luksUUID), not the unprivileged runOutputDirect
// reserved for findmnt. Reading a loop device's dm-slave header needs device
// access (a user outside the "disk" group lacks it); if the probe ran
// unprivileged it would silently fail and a container mounted under a
// differently-named mapping would be left open with a misleading
// "Nothing mounted."
func TestUmountAndCloseUsesPrivilegedMappingProbe(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "luks.img")
	if err := os.WriteFile(img, []byte(luksMagic), 0600); err != nil {
		t.Fatal(err)
	}
	newMapperFixture(t, dir, "myvol", "loop9")

	var umountArgs []string
	runCmd := func(name string, args ...string) error {
		if name == "umount" {
			umountArgs = append(umountArgs, args...)
		}
		return nil
	}
	// The privileged seam is the only one allowed to see luksUUID. findmnt goes
	// through runOutputDirect. If the mapping probe were (incorrectly) routed to
	// runOutputDirect, the luksUUID guard below fails and no mapping is found,
	// so the container would be treated as plain and left unreported.
	privileged := func(name string, args ...string) ([]byte, error) {
		if name == "cryptsetup" && len(args) > 0 && args[0] == "luksUUID" {
			return []byte("uuid"), nil
		}
		return nil, errors.New("no privileged findmnt expected")
	}
	unprivileged := func(name string, args ...string) ([]byte, error) {
		if name == "findmnt" {
			return []byte(filepath.Join(dir, "mp")), nil
		}
		if name == "cryptsetup" && len(args) > 0 && args[0] == "luksUUID" {
			t.Error("cryptsetup luksUUID must run through the privileged seam, not runOutputDirect")
		}
		return nil, exitStatus(t, 1)
	}

	err := umountAndClose(func(string) bool { return false }, runCmd, privileged, unprivileged, img)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(umountArgs) != 1 || umountArgs[0] != filepath.Join(dir, "mp") {
		t.Errorf("expected umount of the mapped target, got %v", umountArgs)
	}
}

func TestUmountAndClose_nonLuks(t *testing.T) {
	t.Run("empty source is rejected before any probe", func(t *testing.T) {
		var probes int
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			probes++
			return nil, nil
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "")
		if err == nil || !strings.Contains(err.Error(), "cannot determine name from empty source") {
			t.Fatalf("expected an empty-source error, got %v", err)
		}
		if probes != 0 {
			t.Errorf("no findmnt probe should run for an empty source, got %d", probes)
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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, nil }
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, srcFile)
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, srcFile+"/")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, missing)
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
		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, ".")
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
		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, dir)
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
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }
		checkMapped := func(name string) bool { return true }

		// The source path no longer exists, but the mapping named after its
		// basename is still open; the mapping must be found and closed, not
		// dismissed with a "does not exist" error. findmnt reports nothing
		// mounted by exiting 1, which must not be mistaken for a probe failure.
		missing := filepath.Join(t.TempDir(), "gone.img")
		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, missing)
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

		err = umountAndClose(checkMapped, runCmd, noProbe, runOutput, "sdc1")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
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

	t.Run("notes when a not-mounted source is itself a LUKS container", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "luks.img")
		if err := os.WriteFile(img, []byte(luksMagic), 0600); err != nil {
			t.Fatal(err)
		}
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			return nil, exitStatus(t, 1)
		}
		checkMapped := func(name string) bool { return false }

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = umountAndClose(checkMapped, runCmd, runOutput, runOutput, img)
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if err != nil {
			t.Fatalf("an unmapped LUKS file should not error, got %v", err)
		}
		if !strings.Contains(buf.String(), "LUKS container but has no open /dev/mapper mapping") {
			t.Errorf("expected the unmapped-container hint, got %q", buf.String())
		}
	})

	t.Run("keeps the unmapped-container hint for an unreadable LUKS source", func(t *testing.T) {
		// The privileged isLuks probe already established that this
		// unreadable container is LUKS; the "Nothing mounted" hint must not be
		// dropped just because the local read cannot re-derive that fact.
		dir := t.TempDir()
		img := filepath.Join(dir, "luks.img")
		if err := os.WriteFile(img, []byte(luksMagic), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(img, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(img, 0600) })
		runCmd := func(name string, args ...string) error { return nil }
		runOutput := func(name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "isLuks" {
				// cryptsetup floor: the unreadable header is LUKS.
				return nil, nil
			}
			// luksUUID finds no mapping and findmnt reports nothing (exit 1).
			return nil, exitStatus(t, 1)
		}
		checkMapped := func(name string) bool { return false }

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = umountAndClose(checkMapped, runCmd, runOutput, runOutput, img)
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if err != nil {
			t.Fatalf("an unmapped unreadable LUKS file should not error, got %v", err)
		}
		if !strings.Contains(buf.String(), "LUKS container but has no open /dev/mapper mapping") {
			t.Errorf("expected the hint for an unreadable-but-probed LUKS source, got %q", buf.String())
		}
	})

	t.Run("treats a plain source with no findmnt output as not mounted", func(t *testing.T) {
		var umountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "umount" {
				umountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			// findmnt exits 1 when nothing matches its search.
			return nil, exitStatus(t, 1)
		}
		checkMapped := func(name string) bool { return false }

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if err != nil {
			t.Fatalf("a plain source with no findmnt match should not error, got %v", err)
		}
		if !strings.Contains(buf.String(), "Nothing mounted at /dev/__test_dev__") {
			t.Errorf("expected a nothing-mounted note, got %q", buf.String())
		}
		if umountCalls != 0 {
			t.Errorf("expected no umount calls when nothing is mounted, got %d", umountCalls)
		}
	})

	t.Run("does not claim nothing is mounted when findmnt exits with an error code", func(t *testing.T) {
		var umountCalls int
		runCmd := func(name string, args ...string) error {
			if name == "umount" {
				umountCalls++
			}
			return nil
		}
		runOutput := func(name string, args ...string) ([]byte, error) {
			// findmnt exits 2 for a probe error; only exit 1 means no match.
			return nil, exitStatus(t, 2)
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
		if err == nil || !strings.Contains(fmt.Sprintf("%v", err), "findmnt failed") {
			t.Errorf("expected a findmnt failure, got %v", err)
		}
		if err != nil && strings.Contains(fmt.Sprintf("%v", err), "Nothing mounted") {
			t.Errorf("a findmnt error must not claim nothing is mounted, got %v", err)
		}
		if umountCalls != 0 {
			t.Errorf("no umount should run after a failed probe, got %d", umountCalls)
		}
	})

	t.Run("rejects when findmnt itself is missing", func(t *testing.T) {
		runCmd := func(name string, args ...string) error { return nil }
		runOutputDirect := func(name string, args ...string) ([]byte, error) {
			// A missing binary yields exec.ErrNotFound, not findmnt's normal
			// "no match" exit status; nobody ran to produce the empty output.
			return nil, fmt.Errorf("exec: %q: %w", "findmnt", exec.ErrNotFound)
		}
		checkMapped := func(name string) bool { return false }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutputDirect, "/dev/__test_dev__")
		if err == nil || !strings.Contains(fmt.Sprintf("%v", err), "findmnt") {
			t.Errorf("expected a missing-findmnt error, got %v", err)
		}
		if err != nil && strings.Contains(fmt.Sprintf("%v", err), "Nothing mounted") {
			t.Errorf("a missing findmnt must not claim nothing is mounted, got %v", err)
		}
	})

	t.Run("closes an open LUKS mapping when findmnt reports no mount (exit 1)", func(t *testing.T) {
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
		// findmnt's documented exit 1 is "nothing matches", the ordinary result
		// for an open-but-unmounted mapping. It must not be treated as a probe
		// failure: the point of -u is to detach a dangling mapping.
		runOutputDirect := func(name string, args ...string) ([]byte, error) {
			return nil, exitStatus(t, 1)
		}
		checkMapped := func(name string) bool { return true }

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutputDirect, "/dev/__test_dev__")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if closes != 1 {
			t.Errorf("expected the dangling mapping to be closed, got %d close(s)", closes)
		}
		if umounts != 0 {
			t.Errorf("must not umount when nothing is mounted, got %d umount(s)", umounts)
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutputDirect, "/dev/__test_dev__")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
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

		err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
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

func TestOpenAndMountCurrentUserLookupFailure(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain.img")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "mnt")

	oldCur := currentUser
	currentUser = func() (*user.User, error) {
		return nil, errors.New("no passwd entry for uid")
	}
	defer func() { currentUser = oldCur }()

	got := captureStderr(t, func() {
		err := openAndMount(
			func(n string, a ...string) error { return nil },
			func(n string, a ...string) ([]byte, error) { return nil, errors.New("unexpected probe") },
			src, "", mp,
		)
		if err != nil {
			t.Fatalf("openAndMount unexpected error: %v", err)
		}
	})
	if !strings.Contains(got, "Warning: cannot determine current user") ||
		!strings.Contains(got, "no passwd entry") {
		t.Errorf("expected a current-user warning, got %q", got)
	}
}

func TestUmountAndCloseDevDirectorySource(t *testing.T) {
	if _, err := os.Stat("/dev/fd"); err != nil {
		t.Skip("/dev/fd is not a directory on this host")
	}
	seen := make(map[string]bool)
	err := umountAndClose(
		func(name string) bool { return false },
		func(n string, a ...string) error { seen[n] = true; return nil },
		noProbe,
		func(n string, a ...string) ([]byte, error) { seen[n] = true; return nil, nil },
		"/dev/fd",
	)
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("expected a directory rejection for /dev/fd, got %v", err)
	}
	if len(seen) != 0 {
		t.Errorf("expected no findmnt/unmount calls, saw %v", seen)
	}
}

func TestUmountAndClosePartialFailureAccumulates(t *testing.T) {
	dir := t.TempDir()
	mpA := filepath.Join(dir, "a")
	mpB := filepath.Join(dir, "b")
	if err := os.MkdirAll(mpA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mpB, 0755); err != nil {
		t.Fatal(err)
	}

	var closed bool
	var umounts []string
	runCmd := func(name string, args ...string) error {
		switch name {
		case "umount":
			umounts = append(umounts, args[0])
			if args[0] == mpA {
				return errors.New("busy")
			}
		case "cryptsetup":
			if len(args) > 0 && args[0] == "luksClose" {
				closed = true
			}
		}
		return nil
	}
	runOutput := func(name string, args ...string) ([]byte, error) {
		return []byte(mpA + "\n" + mpB), nil
	}
	checkMapped := func(name string) bool { return true }

	err := umountAndClose(checkMapped, runCmd, noProbe, runOutput, "/dev/__test_dev__")
	if err == nil || !strings.Contains(err.Error(), "cleanup errors") {
		t.Fatalf("expected accumulated cleanup errors, got %v", err)
	}
	if !strings.Contains(err.Error(), "umount "+mpA) {
		t.Errorf("expected the failing umount to be named, got %v", err)
	}
	if !strings.Contains(err.Error(), "LUKS mapping __test_dev__ left open") {
		t.Errorf("expected the open mapping to be called out, got %v", err)
	}
	if closed {
		t.Error("luksClose must not run while a target is still mounted")
	}
	// B was unmounted successfully; A's failure must not stop the loop.
	if len(umounts) != 2 {
		t.Errorf("expected both targets to be attempted, got %v", umounts)
	}
}

func TestOpenAndMountMissingBareName(t *testing.T) {
	run := func(name string, args ...string) error {
		t.Errorf("no command may run for a missing bare name, got %s %v", name, args)
		return nil
	}
	out := func(name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("unexpected output probe")
	}

	err := openAndMount(run, out, "zz-no-such-device", "", "")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected a does-not-exist error, got %v", err)
	}
}

func TestOpenAndMountBareNameResolvedDevIsModeChecked(t *testing.T) {
	// A bare name that resolves to an existing /dev/ entry (e.g. "fd" ->
	// /dev/fd, a directory) must be mode-checked like any explicit source. The
	// original stat of the bare name fails, so without the re-stat on the
	// resolved path the directory would slip through checkSourceMode and
	// surface as a cryptic probe/mount failure instead.
	var targets []string
	if _, err := os.Stat("/dev/fd"); err != nil {
		if _, err2 := os.Stat("/dev/mapper"); err2 != nil {
			t.Skip("no /dev directory entry to exercise bare-name resolution")
		}
	}
	// Pick a bare name whose /dev/<name> is a directory on this host.
	bare := "fd"
	if _, err := os.Stat("/dev/fd"); err != nil {
		bare = "mapper"
	}
	resolved := "/dev/" + bare

	run := func(name string, args ...string) error {
		targets = append(targets, args...)
		return nil
	}
	out := func(name string, args ...string) ([]byte, error) {
		t.Errorf("no privileged probe should run for a resolved /dev/ directory, got %s %v", name, args)
		return nil, exitStatus(t, 1)
	}

	err := openAndMount(run, out, bare, "", filepath.Join(t.TempDir(), "mnt"))
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("expected a directory rejection for the resolved source %q, got %v", resolved, err)
	}
	if len(targets) != 0 {
		t.Errorf("no command should run for a rejected resolved /dev/ directory, got %v", targets)
	}
}

func TestOpenAndMountLeadingDashSource(t *testing.T) {
	var runs int
	run := func(name string, args ...string) error {
		runs++
		return nil
	}
	out := func(name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("unexpected output probe")
	}

	err := openAndMount(run, out, "-evil.img", "", "")
	if err == nil || !strings.Contains(err.Error(), "starts with a dash") {
		t.Fatalf("expected a leading-dash rejection, got %v", err)
	}
	if runs != 0 {
		t.Errorf("no command should run for a leading-dash source, saw %d", runs)
	}
}

func TestOpenAndMountRelativeHomeRefused(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "img")
	if err := os.WriteFile(img, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	origHome := userHomeDir
	userHomeDir = func() (string, error) { return "relhome", nil }
	t.Cleanup(func() { userHomeDir = origHome })

	err := openAndMount(func(s string, a ...string) error { return nil }, func(s string, a ...string) ([]byte, error) { return nil, fmt.Errorf("no cryptsetup needed") }, img, "", "")
	if err == nil || !strings.Contains(err.Error(), "cannot infer an absolute mount point") {
		t.Fatalf("expected a relative-HOME refusal, got %v", err)
	}
}

func TestUmountAndCloseBareNameSearchesDev(t *testing.T) {
	if _, err := os.Stat("/dev/fd"); err != nil {
		t.Skip("no /dev/fd entry to exercise the bare-name device resolution")
	}
	var searchArg, rawFlag, listFlag string
	run := func(name string, args ...string) error { return nil }
	runOutput := func(name string, args ...string) ([]byte, error) {
		for i, a := range args {
			if a == "-S" && i+1 < len(args) {
				searchArg = args[i+1]
			}
			if a == "-r" {
				rawFlag = a
			}
			if a == "-l" {
				listFlag = a
			}
		}
		return []byte("\n"), nil
	}

	err := umountAndClose(func(string) bool { return false }, run, noProbe, runOutput, "fd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if searchArg != "/dev/fd" {
		t.Errorf("expected findmnt to search /dev/fd, got %q", searchArg)
	}
	if rawFlag == "" {
		t.Error("findmnt must run with -r so paths containing spaces are not \\040-escaped")
	}
	if listFlag != "" {
		// util-linux >= 2.39 rejects "-l --raw" as mutually exclusive; -r
		// alone already disables the tree layout, so -l must never be passed.
		t.Errorf("findmnt must not combine -l with -r, got args with -l")
	}
}

func TestWaitForDevice(t *testing.T) {
	t.Run("returns immediately when the node exists", func(t *testing.T) {
		dir := t.TempDir()
		orig := devStat
		devStat = func(string) (os.FileInfo, error) { return nil, nil }
		t.Cleanup(func() { devStat = orig })

		start := time.Now()
		if !waitForDevice(filepath.Join(dir, "node")) {
			t.Error("expected the existing node to be found")
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("existing node took %v, want immediate", d)
		}
	})

	t.Run("waits for a late-appearing node", func(t *testing.T) {
		dir := t.TempDir()
		orig := devStat
		fails := 0
		devStat = func(string) (os.FileInfo, error) {
			fails++
			if fails <= 2 {
				return nil, fmt.Errorf("not yet")
			}
			return nil, nil
		}
		t.Cleanup(func() { devStat = orig })
		origTries := waitForDeviceTries
		waitForDeviceTries = 5
		t.Cleanup(func() { waitForDeviceTries = origTries })

		if !waitForDevice(filepath.Join(dir, "node")) {
			t.Error("expected the late-appearing node to be found")
		}
		if fails != 3 {
			t.Errorf("expected 3 stats for a node appearing on the 3rd, got %d", fails)
		}
	})

	t.Run("gives up after the budget when the parent exists", func(t *testing.T) {
		dir := t.TempDir()
		// Do not override devStat so the node is genuinely absent, and keep
		// os.Stat(dir) (the parent) working.
		origTries := waitForDeviceTries
		waitForDeviceTries = 2
		t.Cleanup(func() { waitForDeviceTries = origTries })

		start := time.Now()
		if waitForDevice(filepath.Join(dir, "node")) {
			t.Error("expected the timeout to report the node as missing")
		}
		if d := time.Since(start); d < 90*time.Millisecond {
			t.Errorf("timeout path returned in %v, expected to burn the budget", d)
		}
	})

	t.Run("skips polling when the parent directory is missing", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-parent")
		start := time.Now()
		if waitForDevice(filepath.Join(missing, "node")) {
			t.Error("expected the missing parent to report the node as missing")
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("missing parent took %v, want immediate", d)
		}
	})
}

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type cmdCall struct {
	name string
	args []string
}

// noOutput is a runOutput-style seam (cryptsetup luksUUID) returning no
// output; mappingForSource then finds no matching mapping, so the
// differently-named-mapping expand guard stays inert unless a test overrides
// it with a real UUID-aware stub.
func noOutput(name string, args ...string) ([]byte, error) {
	return nil, nil
}

func TestCheckParentDir(t *testing.T) {
	dir := t.TempDir()

	t.Run("existing directory passes", func(t *testing.T) {
		if err := checkParentDir(filepath.Join(dir, "img"), "container"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty path passes via the working directory", func(t *testing.T) {
		if err := checkParentDir("", "container"); err != nil {
			t.Fatalf("unexpected error for an empty path: %v", err)
		}
	})

	t.Run("missing parent directory is named", func(t *testing.T) {
		missing := filepath.Join(dir, "sub", "img")
		err := checkParentDir(missing, "container")
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected a does-not-exist error, got %v", err)
		}
	})

	t.Run("parent is a file", func(t *testing.T) {
		f := filepath.Join(dir, "afile")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		err := checkParentDir(filepath.Join(f, "img"), "key file")
		if err == nil || !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("expected an is-not-a-directory error, got %v", err)
		}
		if !strings.Contains(err.Error(), "key file") {
			t.Errorf("expected the what-label in the error, got %v", err)
		}
	})
}

// sparseContainerDD stubs the container-writing dd/truncate calls so the
// container file ends up exactly the requested size without writing real zero
// bytes (a sparse truncate is instant). createContainer verifies the container
// size after writeZeros exactly as it verifies a generated key file, so every
// test that reaches the success path must produce an exactly-sized container;
// this stub mirrors writeZeros' own math: dd writes bs=..M * count bytes and
// truncate extends by the remainder.
func sparseContainerDD(of string) func(name string, args ...string) error {
	var bs, count int64
	return func(name string, args ...string) error {
		switch name {
		case "dd":
			for _, a := range args {
				switch {
				case strings.HasPrefix(a, "bs="):
					v := strings.TrimSuffix(strings.TrimPrefix(a, "bs="), "M")
					n, _ := strconv.ParseInt(v, 10, 64)
					bs = n * _1M
				case strings.HasPrefix(a, "count="):
					n, _ := strconv.ParseInt(strings.TrimPrefix(a, "count="), 10, 64)
					count = n
				}
			}
			return os.Truncate(of, bs*count)
		case "truncate":
			if len(args) != 2 || args[0] != "-s" || !strings.HasPrefix(args[1], "+") {
				return fmt.Errorf("unexpected truncate args: %v", args)
			}
			n, _ := strconv.ParseInt(strings.TrimPrefix(args[1], "+"), 10, 64)
			fi, err := os.Stat(of)
			if err != nil {
				return err
			}
			return os.Truncate(of, fi.Size()+n)
		default:
			return nil
		}
	}
}

func TestCreateContainer(t *testing.T) {
	t.Run("success without key file", func(t *testing.T) {
		img := filepath.Join(t.TempDir(), "container.img")
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", "", 512, false)
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
		// Without -ck/-k no key file may reach cryptsetup: the container must
		// prompt for a passphrase instead of silently keying from nothing.
		for _, a := range calls[1].args {
			if a == "--key-file" {
				t.Errorf("luksFormat must not receive --key-file without -ck/-k, got %v", calls[1])
			}
		}
		if calls[2].name != "cryptsetup" || len(calls[2].args) < 1 || calls[2].args[0] != "luksOpen" {
			t.Errorf("call 2: expected cryptsetup luksOpen, got %v", calls[2])
		}
		// verify mapper name is basename, not the full path
		if len(calls[2].args) < 3 || calls[2].args[len(calls[2].args)-1] != "container.img" {
			t.Errorf("call 2: expected mapper name 'container.img', got args: %v", calls[2].args)
		}
		if calls[3].name != "mkfs.ext4" {
			t.Errorf("call 3: expected mkfs.ext4, got %s", calls[3].name)
		}
		if calls[4].name != "cryptsetup" || len(calls[4].args) < 1 || calls[4].args[0] != "luksClose" {
			t.Errorf("call 4: expected cryptsetup luksClose, got %v", calls[4])
		}
	})

	t.Run("success reports the created container and its exact size", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")

		run := func(name string, args ...string) error {
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = createContainer(run, run, img, "256M", "", "", 512, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		out := buf.String()

		if !strings.Contains(out, "Created container "+img) {
			t.Errorf("expected a created-container summary naming %q, got %q", img, out)
		}
		if !strings.Contains(out, "(268435456 bytes)") {
			t.Errorf("expected the created-container summary to report the exact size, got %q", out)
		}
	})

	t.Run("no-passphrase report names the only key and flags the missing passphrase", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		key := filepath.Join(dir, "container.key")

		var addKeyCalled bool
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return sparseContainerDD(img)(name, args...)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return os.WriteFile(key, bytes.Repeat([]byte("K"), 512), 0600)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksAddKey" {
				addKeyCalled = true
			}
			return nil
		}

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = createContainer(run, run, img, "256M", "", key, 512, true)
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		out := buf.String()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "unlocks with key file "+key) {
			t.Errorf("expected the report to name %q, got %q", key, out)
		}
		if !strings.Contains(out, "key-file only; no passphrase was set") {
			t.Errorf("expected the key-file-only reminder, got %q", out)
		}
		if addKeyCalled {
			t.Errorf("a key-file-only create must not luksAddKey; the key is the initial keyslot")
		}
	})

	t.Run("rejects a name with whitespace before creating anything", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		// The container basename would become an unmappable /dev/mapper name.
		img := filepath.Join(t.TempDir(), "my container.img")
		err := createContainer(run, run, img, "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "invalid device-mapper name") {
			t.Errorf("expected an invalid device-mapper name error, got %v", err)
		}
		if len(calls) != 0 {
			t.Errorf("no commands should run for an unmappable name, got %v", calls)
		}
	})

	t.Run("rejects a dot-dot container name before creating anything", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		// srcName("..") is "..", which would alias /dev/mapper/.. (i.e. /dev).
		err := createContainer(run, run, "..", "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "invalid device-mapper name") {
			t.Errorf("expected an invalid device-mapper name error, got %v", err)
		}
		if len(calls) != 0 {
			t.Errorf("no commands should run for an unmappable name, got %v", calls)
		}
	})

	t.Run("success without key file, non-relative path", func(t *testing.T) {
		dir := t.TempDir()
		subdir := filepath.Join(dir, "subdir")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		img := filepath.Join(subdir, "container.img")
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", "", 512, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(calls) != 5 {
			t.Fatalf("expected 5 calls, got %d: %v", len(calls), calls)
		}

		// luksOpen mapper name must be just "container.img", not the full path
		luksOpen := calls[2]
		if luksOpen.name != "cryptsetup" || len(luksOpen.args) < 1 || luksOpen.args[0] != "luksOpen" {
			t.Fatalf("call 2: expected cryptsetup luksOpen, got %v", luksOpen)
		}
		src := luksOpen.args[len(luksOpen.args)-2]
		mapper := luksOpen.args[len(luksOpen.args)-1]
		if src != img {
			t.Errorf("luksOpen source should be %q, got %q", img, src)
		}
		if mapper != "container.img" {
			t.Errorf("luksOpen mapper name should be 'container.img', got %q", mapper)
		}

		// mkfs.ext4 should target /dev/mapper/container.img
		mkfs := calls[3]
		if mkfs.name != "mkfs.ext4" || len(mkfs.args) < 1 || mkfs.args[len(mkfs.args)-1] != "/dev/mapper/container.img" {
			t.Errorf("mkfs should target /dev/mapper/container.img, got %v", mkfs)
		}

		// luksClose should use mapper name "container.img"
		luksClose := calls[4]
		if luksClose.name != "cryptsetup" || len(luksClose.args) < 1 || luksClose.args[0] != "luksClose" || luksClose.args[len(luksClose.args)-1] != "container.img" {
			t.Errorf("luksClose mapper name should be 'container.img', got %v", luksClose)
		}
	})

	t.Run("success with generated key file", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		kf := filepath.Join(dir, "keyfile")

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				// simulate the generated key file being written to disk
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// the generated key file must be private, not world-readable
		if fi, statErr := os.Stat(kf); statErr == nil && fi.Mode()&0777 != 0600 {
			t.Errorf("expected generated key file mode 0600, got %o", fi.Mode()&0777)
		}
		if len(calls) != 7 {
			t.Fatalf("expected 7 calls, got %d: %v", len(calls), calls)
		}

		if calls[0].name != "dd" || len(calls[0].args) < 1 || calls[0].args[0] != "if=/dev/urandom" {
			t.Errorf("call 0: expected dd urandom key file, got %v", calls[0])
		}
		if !slices.Contains(calls[0].args, "of="+kf) {
			t.Errorf("call 0: key dd must target the key file, got %v", calls[0].args)
		}
		if slices.Contains(calls[0].args, "conv=excl") {
			t.Errorf("call 0: key dd must not need conv=excl (the path is already claimed via O_EXCL), got %v", calls[0].args)
		}
		if calls[1].name != "dd" || len(calls[1].args) < 1 || calls[1].args[0] != "if=/dev/zero" {
			t.Errorf("call 1: expected dd zero container, got %v", calls[1])
		}
		if !slices.Contains(calls[1].args, "of="+img) {
			t.Errorf("call 1: container dd must target the container, got %v", calls[1].args)
		}
		// A passphrase create never installs the key file at luksFormat time;
		// the passphrase keyslot is created interactively instead.
		if calls[2].name != "cryptsetup" || calls[2].args[0] != "luksFormat" || calls[2].args[1] != "--batch-mode" {
			t.Errorf("call 2: expected cryptsetup luksFormat --batch-mode, got %v", calls[2])
		}
		for _, a := range calls[2].args {
			if a == "--key-file" {
				t.Errorf("luksFormat must not use --key-file in passphrase mode, got %v", calls[2].args)
			}
		}
		// The generated key file is added as an additional keyslot afterwards.
		if calls[3].name != "cryptsetup" || calls[3].args[0] != "luksAddKey" ||
			len(calls[3].args) < 3 || calls[3].args[1] != img || calls[3].args[2] != kf {
			t.Errorf("call 3: expected cryptsetup luksAddKey %s %s, got %v", img, kf, calls[3])
		}
		if calls[4].name != "cryptsetup" || calls[4].args[0] != "luksOpen" {
			t.Errorf("call 4: expected cryptsetup luksOpen, got %v", calls[4])
		}
		foundOpenKey := false
		for i, a := range calls[4].args {
			if a == "--key-file" && i+1 < len(calls[4].args) && calls[4].args[i+1] == kf {
				foundOpenKey = true
				break
			}
		}
		if !foundOpenKey {
			t.Errorf("luksOpen missing --key-file %q, got %v", kf, calls[4].args)
		}
		if calls[5].name != "mkfs.ext4" {
			t.Errorf("call 5: expected mkfs.ext4, got %s", calls[5].name)
		}
		if calls[6].name != "cryptsetup" || calls[6].args[0] != "luksClose" {
			t.Errorf("call 6: expected cryptsetup luksClose, got %v", calls[6])
		}
	})

	t.Run("no-passphrase create installs the generated key file directly", func(t *testing.T) {
		var calls []cmdCall
		kf := filepath.Join(t.TempDir(), "key.bin")
		img := filepath.Join(t.TempDir(), "container.img")
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// dd (urandom), dd (container), luksFormat --key-file, luksOpen --key-file, mkfs.ext4, luksClose = 6
		if len(calls) != 6 {
			t.Fatalf("expected 6 calls, got %d: %v", len(calls), calls)
		}
		format := calls[2]
		if format.name != "cryptsetup" || format.args[0] != "luksFormat" {
			t.Fatalf("call 2: expected luksFormat, got %v", format)
		}
		foundFormatKey := false
		for i, a := range format.args {
			if a == "--key-file" && i+1 < len(format.args) && format.args[i+1] == kf {
				foundFormatKey = true
				break
			}
		}
		if !foundFormatKey {
			t.Errorf("luksFormat missing --key-file %q, got %v", kf, format.args)
		}
		// No additional keyslot is added: the key file IS the initial key.
		for _, c := range calls {
			if c.name == "cryptsetup" && c.args[0] == "luksAddKey" {
				t.Errorf("no-passphrase create must not add a second keyslot, got %v", calls)
			}
		}
	})

	t.Run("success with existing key file", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		kf := filepath.Join(dir, "existing.key")
		os.WriteFile(kf, []byte("keydata"), 0644)
		err := createContainer(run, run, img, "256M", kf, "", 512, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// dd (container), luksFormat, luksAddKey, luksOpen --key-file, mkfs.ext4, luksClose = 6
		if len(calls) != 6 {
			t.Fatalf("expected 6 calls, got %d: %v", len(calls), calls)
		}

		// no key file generation call
		if calls[0].name != "dd" || len(calls[0].args) < 1 || calls[0].args[0] != "if=/dev/zero" {
			t.Errorf("call 0: expected dd zero container, got %v", calls[0])
		}
		// A passphrase create never installs the key file at luksFormat time;
		// the passphrase keyslot is created interactively instead.
		if calls[1].name != "cryptsetup" || calls[1].args[0] != "luksFormat" {
			t.Errorf("call 1: expected cryptsetup luksFormat, got %v", calls[1])
		}
		for _, a := range calls[1].args {
			if a == "--key-file" {
				t.Errorf("luksFormat must not use --key-file in passphrase mode, got %v", calls[1].args)
			}
		}
		// The existing key file is added as an additional keyslot, which still
		// requires the container passphrase to authorize.
		if calls[2].name != "cryptsetup" || calls[2].args[0] != "luksAddKey" ||
			len(calls[2].args) < 3 || calls[2].args[1] != img || calls[2].args[2] != kf {
			t.Errorf("call 2: expected cryptsetup luksAddKey %s %s, got %v", img, kf, calls[2])
		}
		// luksOpen with --key-file existing key
		if calls[3].name != "cryptsetup" || calls[3].args[0] != "luksOpen" {
			t.Errorf("call 3: expected cryptsetup luksOpen, got %v", calls[3])
		}
		foundKey := false
		for i, a := range calls[3].args {
			if a == "--key-file" && i+1 < len(calls[3].args) && calls[3].args[i+1] == kf {
				foundKey = true
				break
			}
		}
		if !foundKey {
			t.Errorf("luksOpen missing --key-file %q: %v", kf, calls[3].args)
		}
	})

	t.Run("no-passphrase without a key file is refused", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512, true)
		if err == nil || !strings.Contains(err.Error(), "requires a key file") {
			t.Errorf("expected a requires-a-key-file error, got %v", err)
		}
	})

	t.Run("luksAddKey failure is surfaced", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		kf := filepath.Join(dir, "key.bin")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksAddKey" {
				return fmt.Errorf("addkey boom")
			}
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "luksAddKey failed: addkey boom") {
			t.Errorf("expected a luksAddKey failure, got %v", err)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("a failed luksAddKey must roll back the container, got stat err %v", statErr)
		}
	})

	t.Run("create never requires sudo", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				kf := strings.TrimPrefix(strings.Split(args[1], "=")[1], "of=")
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				var of string
				for _, a := range args {
					if strings.HasPrefix(a, "of=") {
						of = strings.TrimPrefix(a, "of=")
					}
				}
				return sparseContainerDD(of)(name, args...)
			}
			return nil
		}
		var sudoCmds []string
		runSudo := func(name string, args ...string) error {
			sudoCmds = append(sudoCmds, name)
			return nil
		}
		for _, noPassphrase := range []bool{false, true} {
			dir := t.TempDir()
			err := createContainer(runSudo, run, filepath.Join(dir, "c.img"), "256M", "", filepath.Join(dir, "k.bin"), 512, noPassphrase)
			if err != nil {
				t.Fatalf("noPassphrase=%v: %v", noPassphrase, err)
			}
		}
		for _, cmd := range sudoCmds {
			if cmd == "luksFormat" || cmd == "luksAddKey" {
				t.Errorf("header operations must run unprivileged, got sudo %q", cmd)
			}
		}
		sawOpen := false
		for _, c := range sudoCmds {
			if c == "cryptsetup" {
				sawOpen = true
			}
		}
		if !sawOpen {
			t.Errorf("expected at least a sudo cryptsetup (luksOpen); got %v", sudoCmds)
		}
	})

	t.Run("waits for the mapper node before mkfs", func(t *testing.T) {
		img := filepath.Join(t.TempDir(), "c.img")
		run := func(name string, args ...string) error {
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		origStat := devStat
		origTries := waitForDeviceTries
		devStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		waitForDeviceTries = 2
		t.Cleanup(func() { devStat = origStat; waitForDeviceTries = origTries })

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

		if err := createContainer(run, run, img, "256M", "", "", 512, false); err != nil {
			t.Fatalf("expected a continuing create, got %v", err)
		}
		os.Stderr = oldStderr
		w.Close()
		<-done
		if !strings.Contains(buf.String(), "udev may still be settling") {
			t.Errorf("expected a settling warning when the node never appears, got %q", buf.String())
		}
	})

	t.Run("accepts a trailing-slash existing key file", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}

		kf := filepath.Join(dir, "existing.key")
		os.WriteFile(kf, []byte("keydata"), 0644)
		err := createContainer(run, run, img, "256M", kf+string(filepath.Separator), "", 512, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// In passphrase mode the key file goes through luksAddKey (call 2), and
		// the trailing slash must already be normalized before it reaches the
		// command line (os.Stat would otherwise have rejected kf/ as a directory).
		if calls[2].name != "cryptsetup" || calls[2].args[0] != "luksAddKey" ||
			len(calls[2].args) < 3 || calls[2].args[2] != kf {
			t.Errorf("luksAddKey missing normalized key file %q, got %v", kf, calls[2])
		}
	})

	t.Run("rejects both a generated and an existing key file", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		img := filepath.Join(t.TempDir(), "container.img")
		existing := filepath.Join(t.TempDir(), "existing.key")
		if err := os.WriteFile(existing, []byte("key"), 0600); err != nil {
			t.Fatal(err)
		}
		err := createContainer(run, run, img, "256M", existing, filepath.Join(t.TempDir(), "new.key"), 512, false)
		if err == nil || !strings.Contains(err.Error(), "cannot both be set") {
			t.Errorf("expected a both-keys error, got %v", err)
		}
		if len(calls) != 0 {
			t.Errorf("no commands should run with both keys set, got %v", calls)
		}
	})

	t.Run("rejects the filesystem root as a container", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		err := createContainer(run, run, "/", "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "invalid device-mapper name") {
			t.Errorf("expected an invalid name error for the root container, got %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("no commands should run for a root container, got %v", runs)
		}
	})

	t.Run("rejects an empty container name", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		err := createContainer(run, run, "", "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Errorf("expected an empty-name error, got %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("no commands should run for an empty container name, got %v", runs)
		}
	})

	t.Run("container already exists", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir := t.TempDir()
		existing := filepath.Join(dir, "existing.img")
		if err := os.WriteFile(existing, []byte("racers data"), 0644); err != nil {
			t.Fatal(err)
		}
		err := createContainer(run, run, existing, "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got %v", err)
		}
		if got, readErr := os.ReadFile(existing); readErr != nil || string(got) != "racers data" {
			t.Errorf("pre-existing container must not be touched by cleanup; read %q (err %v)", got, readErr)
		}
	})

	t.Run("container path probe failure is reported, not overwritten", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		// A path whose parent is a file makes os.Stat fail with ENOTDIR, a
		// non-isNotExist error (and the basename "c.img" is a valid mapping
		// name, so the mapper-name check passes). The create must refuse
		// rather than overwrite.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "afile"), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(dir, "afile", "c.img")
		err := createContainer(run, run, bad, "256M", "", "", 512, false)
		if err == nil {
			t.Fatalf("expected an error for a container path that cannot be probed")
		}
		if !strings.Contains(err.Error(), "checking container path") {
			t.Errorf("expected a checking-container-path error, got %v", err)
		}
	})

	t.Run("missing container parent directory is rejected up front", func(t *testing.T) {
		var cryptCalls int
		run := func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		img := filepath.Join(t.TempDir(), "missing-subdir", "c.img")
		err := createContainer(run, run, img, "256M", "", filepath.Join(t.TempDir(), "keyfile"), 512, false)
		if err == nil || !strings.Contains(err.Error(), "container directory") {
			t.Errorf("expected a container-directory error, got %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("no cryptsetup work should happen when the container directory is missing, got %d calls", cryptCalls)
		}
	})

	t.Run("rejects key file path equal to container path", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir := t.TempDir()
		img := filepath.Join(dir, "same.img")
		err := createContainer(run, run, img, "256M", "", img, 512, false)
		if err == nil || !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected a key-file/container collision error, got %v", err)
		}
	})

	t.Run("rejects key file path equal to container path under a cleaned spelling", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir, err := filepath.Abs(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		img := filepath.Join(dir, "same.img")
		// "dir/sub/../same.img" and "dir/same.img" resolve to the same file but
		// differ textually; the guard must still reject the collision.
		sneaky := dir + "/sub/../same.img"
		err = createContainer(run, run, img, "256M", "", sneaky, 512, false)
		if err == nil || !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected a cleaned-path collision error, got %v", err)
		}
	})

	t.Run("rejects a key file that aliases the absolute container path", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir, err := filepath.Abs(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		// cwd is the container's directory, so the relative key "same.img"
		// names exactly the absolute container /dir/same.img. The string
		// equality guard would miss this alias; the absolute-path one must not.
		oldWd, wdErr := os.Getwd()
		if wdErr != nil {
			t.Fatal(wdErr)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer os.Chdir(oldWd)

		img := filepath.Join(dir, "same.img")
		err = createContainer(run, run, img, "256M", "", "same.img", 512, false)
		if err == nil || !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected a relative/absolute collision error, got %v", err)
		}
	})

	t.Run("missing key file parent directory is rejected up front", func(t *testing.T) {
		var cryptCalls int
		run := func(name string, args ...string) error {
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		img := filepath.Join(t.TempDir(), "c.img")
		kf := filepath.Join(t.TempDir(), "missing-subdir", "keyfile")
		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "key file directory") {
			t.Errorf("expected a key-file-directory error, got %v", err)
		}
		if cryptCalls != 0 {
			t.Errorf("no cryptsetup work should happen when the key file directory is missing, got %d calls", cryptCalls)
		}
	})

	t.Run("key file already exists", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		existingKey := filepath.Join(dir, "existing.key")
		if err := os.WriteFile(existingKey, []byte("keydata"), 0644); err != nil {
			t.Fatal(err)
		}
		err := createContainer(run, run, img, "256M", "", existingKey, 512, false)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got %v", err)
		}
		if got, readErr := os.ReadFile(existingKey); readErr != nil || string(got) != "keydata" {
			t.Errorf("pre-existing key file must not be touched; read %q (err %v)", got, readErr)
		}
	})

	t.Run("key file path that is a directory is reported as such", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		dirKey := filepath.Join(dir, "keydir")
		if err := os.MkdirAll(dirKey, 0755); err != nil {
			t.Fatal(err)
		}
		err := createContainer(run, run, img, "256M", "", dirKey, 512, false)
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-key-file error, got %v", err)
		}
	})

	t.Run("existing key file must exist", func(t *testing.T) {
		var ranCryptsetup bool
		run := func(name string, args ...string) error {
			if name == "cryptsetup" {
				ranCryptsetup = true
			}
			return nil
		}
		img := filepath.Join(t.TempDir(), "c.img")
		err := createContainer(run, run, img, "256M", "/nonexistent/existing.key", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected existing-key-file error, got %v", err)
		}
		if ranCryptsetup {
			t.Error("cryptsetup should not run when the existing key file is missing")
		}
	})

	t.Run("empty existing key file is rejected", func(t *testing.T) {
		var ranCryptsetup bool
		run := func(name string, args ...string) error {
			if name == "cryptsetup" {
				ranCryptsetup = true
			}
			return nil
		}
		img := filepath.Join(t.TempDir(), "c.img")
		emptyKey := filepath.Join(t.TempDir(), "empty.key")
		if err := os.WriteFile(emptyKey, nil, 0600); err != nil {
			t.Fatal(err)
		}
		err := createContainer(run, run, img, "256M", emptyKey, "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("expected an empty-key-file error, got %v", err)
		}
		if ranCryptsetup {
			t.Error("cryptsetup should not run when the existing key file is empty")
		}
	})

	t.Run("directory existing key file is rejected", func(t *testing.T) {
		var ranCryptsetup bool
		run := func(name string, args ...string) error {
			if name == "cryptsetup" {
				ranCryptsetup = true
			}
			return nil
		}
		img := filepath.Join(t.TempDir(), "c.img")
		dirKey := filepath.Join(t.TempDir(), "keydir")
		if err := os.MkdirAll(dirKey, 0755); err != nil {
			t.Fatal(err)
		}
		err := createContainer(run, run, img, "256M", dirKey, "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-key-file error, got %v", err)
		}
		if ranCryptsetup {
			t.Error("cryptsetup should not run when the existing key file is a directory")
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "invalid", "", "", 512, false)
		if err == nil {
			t.Error("expected error for invalid size, got nil")
		}
	})

	t.Run("size below minimum", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		img := filepath.Join(t.TempDir(), "c.img")
		err := createContainer(run, run, img, "16M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "minimum container size is 32M") {
			t.Errorf("expected minimum size error, got %v", err)
		}
		err = createContainer(run, run, img, "31M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "minimum container size is 32M") {
			t.Errorf("expected minimum size error for 31M, got %v", err)
		}
	})

	t.Run("key file size must be a positive multiple of 8 no larger than 8192", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		img := filepath.Join(t.TempDir(), "c.img")
		for _, ks := range []int{0, -1, 4, 12, 8193, 9216, 1048576} {
			err := createContainer(run, run, img, "256M", "", filepath.Join(t.TempDir(), "k"), ks, false)
			if err == nil || !strings.Contains(err.Error(), "key file size must be a positive multiple of 8") {
				t.Errorf("expected key size error for %d, got %v", ks, err)
			}
		}
	})

	t.Run("dd key file fails cleans up partial key file and container", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				// simulate a partial write before failure
				if err := os.WriteFile(kf, []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
				return errors.New("dd keyfile failed")
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "creating key file") {
			t.Fatalf("expected key file error, got %v", err)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("partial key file %q should have been removed", kf)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("container %q should not exist (key file failure precedes container creation)", img)
		}
	})

	t.Run("verify generated key file size", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				// simulate a dd that exits 0 after a partial write
				return os.WriteFile(kf, []byte("short"), 0600)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "has 5 bytes, want 512") {
			t.Fatalf("expected a generated key size error, got %v", err)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("wrong-sized key file %q should have been removed", kf)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("container %q should not exist after a key size error", img)
		}
	})

	t.Run("verify container size after dd", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")

		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				// simulate a dd that exits 0 after a partial write of the
				// container, mirroring the failure mode the generated key file
				// path already defends against
				return os.WriteFile(img, []byte("short"), 0600)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", "", 0, false)
		if err == nil || !strings.Contains(err.Error(), "container") || !strings.Contains(err.Error(), "has 5 bytes, want 268435456") {
			t.Fatalf("expected a container size error, got %v", err)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("short container %q should have been rolled back", img)
		}
	})

	t.Run("dd container fails cleans up key file", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return errors.New("dd container failed")
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "creating container") {
			t.Fatalf("expected container error, got %v", err)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("key file %q should have been removed when container creation failed", kf)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("partial container %q should have been removed when dd failed", img)
		}
	})

	t.Run("a permission-locked parent surfaces the stat error", func(t *testing.T) {
		dir := t.TempDir()
		restricted := filepath.Join(dir, "restricted")
		if err := os.MkdirAll(filepath.Join(restricted, "child"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(restricted, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(restricted, 0755) })

		err := checkParentDir(filepath.Join(restricted, "child", "img"), "container")
		if err == nil || !strings.Contains(err.Error(), "checking container directory") {
			t.Errorf("expected a checking-directory error, got %v", err)
		}
	})

	t.Run("dd container fails", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "dd" {
				return errors.New("dd failed")
			}
			return nil
		}
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "creating container") {
			t.Errorf("expected container creation error, got %v", err)
		}
	})

	t.Run("dd container fails removes the partial container", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				// Simulate dd failing partway: the O_EXCL claim succeeded and a
				// partial file now sits at img, but dd errors out. The partial
				// file must be removed so the path is reusable on a retry.
				return errors.New("dd failed partway")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "creating container") {
			t.Fatalf("expected container error, got %v", err)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("partial container %q should have been removed, got stat err %v", img, statErr)
		}
	})

	t.Run("luksFormat fails cleans up key file and container", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		var closeCalls, mkfsCalls int
		run := func(name string, args ...string) error {
			switch {
			case name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom"):
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			case name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero"):
				return sparseContainerDD(img)(name, args...)
			case name == "cryptsetup" && len(args) > 0 && args[0] == "luksFormat":
				return errors.New("luksFormat failed")
			case name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose":
				closeCalls++
			case name == "mkfs.ext4":
				mkfsCalls++
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "luksFormat failed") {
			t.Errorf("expected luksFormat error, got %v", err)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("generated key file %q should have been removed after luksFormat failure", kf)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("container %q should have been removed after luksFormat failure", img)
		}
		if closeCalls != 0 || mkfsCalls != 0 {
			t.Errorf("no luksClose or mkfs.ext4 should run when luksFormat failed, got close=%d mkfs=%d", closeCalls, mkfsCalls)
		}
	})

	t.Run("luksOpen fails cleans up key file and container", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		var closeCalls, mkfsCalls int
		run := func(name string, args ...string) error {
			switch {
			case name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom"):
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			case name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero"):
				return sparseContainerDD(img)(name, args...)
			case name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen":
				return errors.New("luksOpen failed")
			case name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose":
				closeCalls++
			case name == "mkfs.ext4":
				mkfsCalls++
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "luksOpen failed") {
			t.Errorf("expected luksOpen error, got %v", err)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("generated key file %q should have been removed after luksOpen failure", kf)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("container %q should have been removed after luksOpen failure", img)
		}
		if closeCalls != 0 || mkfsCalls != 0 {
			t.Errorf("no luksClose or mkfs.ext4 should run when luksOpen failed, got close=%d mkfs=%d", closeCalls, mkfsCalls)
		}
	})

	t.Run("key file missing after dd is reported", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		var zeroCalls int
		run := func(name string, args ...string) error {
			switch {
			case name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom"):
				// A silent dd failure: the key file is gone afterwards even
				// though dd exited 0.
				return os.Remove(kf)
			case name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero"):
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "missing after dd") {
			t.Errorf("expected a missing-key-file error, got %v", err)
		}
		if zeroCalls != 0 {
			t.Error("the container should not be written when its key was never stored")
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("key file %q must not exist after a failed dd", kf)
		}
	})

	t.Run("mkfs fails cleans up luksClose", func(t *testing.T) {
		img := filepath.Join(t.TempDir(), "c.img")
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "mkfs.ext4" {
				return errors.New("mkfs failed")
			}
			if name == "dd" || name == "truncate" {
				return sparseContainerDD(img)(name, args...)
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", "", 512, false)
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

	t.Run("mkfs and luksClose failures surface a left-open mapping", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return sparseContainerDD(img)(name, args...)
			}
			if name == "mkfs.ext4" {
				return errors.New("mkfs failed")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "mkfs.ext4 failed") {
			t.Errorf("expected mkfs.ext4 error, got %v", err)
		}
		if !strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("expected a left-open-mapping hint when luksClose fails after mkfs, got %v", err)
		}
		// The mapping could not be closed, so the container file must be kept.
		if _, statErr := os.Stat(img); os.IsNotExist(statErr) {
			t.Error("container file should be preserved when luksClose fails")
		}
	})

	t.Run("failed cleanup warns instead of hiding the original error", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "sub")
		if err := os.Mkdir(sub, 0755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sub, 0755) })
		img := filepath.Join(sub, "c.img")
		kf := filepath.Join(sub, "keyfile")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return sparseContainerDD(img)(name, args...)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksFormat" {
				// Files exist now; take the directory's write permission away so
				// the failure cleanup (os.Remove) cannot succeed. This must
				// happen only after the mocks have written the files.
				if err := os.Chmod(sub, 0555); err != nil {
					t.Fatal(err)
				}
				return errors.New("luksFormat failed")
			}
			return nil
		}

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		defer func() { os.Stderr = oldStderr }()

		err = createContainer(run, run, img, "256M", "", kf, 512, false)
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		stderr := buf.String()

		if err == nil || !strings.Contains(err.Error(), "luksFormat failed") {
			t.Errorf("expected the luksFormat error, got %v", err)
		}
		if !strings.Contains(stderr, "Warning: removing key file") {
			t.Errorf("expected a key-file removal warning on stderr, got %q", stderr)
		}
		if !strings.Contains(stderr, "Warning: removing container") {
			t.Errorf("expected a container removal warning on stderr, got %q", stderr)
		}
	})

	t.Run("luksClose fails", func(t *testing.T) {
		img := filepath.Join(t.TempDir(), "c.img")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return sparseContainerDD(img)(name, args...)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", "", 512, false)
		if err == nil || !strings.Contains(err.Error(), "luksClose failed") {
			t.Errorf("expected luksClose error, got %v", err)
		}
		// luksClose failed, so the /dev/mapper mapping is still considered open;
		// the backing container file must NOT be deleted underneath it.
		if _, statErr := os.Stat(img); os.IsNotExist(statErr) {
			t.Error("container file should be preserved when luksClose fails")
		}
	})

	t.Run("luksClose fails keeps generated key file too", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return sparseContainerDD(img)(name, args...)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				// simulate the generated key file
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "luksClose failed") {
			t.Errorf("expected luksClose error, got %v", err)
		}
		// The generated key file is the container's only key; when the mapping
		// stays open and the container is kept, the key file must be kept too.
		if _, statErr := os.Stat(kf); os.IsNotExist(statErr) {
			t.Error("generated key file should be preserved when luksClose fails")
		}
		if !strings.Contains(err.Error(), "created and left mapped open") {
			t.Errorf("expected the error to say the container was left mapped, got %v", err)
		}
	})

	t.Run("cleans up container and key file on failure", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return os.WriteFile(kf, bytes.Repeat([]byte("x"), 512), 0644)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return sparseContainerDD(img)(name, args...)
			}
			if name == "mkfs.ext4" {
				return errors.New("mkfs failed")
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512, false)
		if err == nil || !strings.Contains(err.Error(), "mkfs.ext4 failed") {
			t.Fatalf("expected mkfs error, got %v", err)
		}
		if _, statErr := os.Stat(img); !os.IsNotExist(statErr) {
			t.Errorf("container %q should have been removed after failure", img)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("key file %q should have been removed after failure", kf)
		}
	})

	t.Run("does not remove file on early validation error", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")

		// "container already exists" returns before any file creation/cleanup
		// is set up, so a pre-existing file must be left untouched.
		if err := os.WriteFile(img, []byte("keep"), 0644); err != nil {
			t.Fatal(err)
		}
		run := func(name string, args ...string) error { return nil }
		err := createContainer(run, run, img, "256M", "", "", 512, false)
		if err == nil {
			t.Fatal("expected 'already exists' error")
		}
		if _, statErr := os.Stat(img); os.IsNotExist(statErr) {
			t.Errorf("file %q should not have been removed on early validation error", img)
		}
	})
}

func TestExpandContainer(t *testing.T) {

	// writeLUKSFake writes a file that passes isLuksContainer's magic check
	// (first 6 bytes "LUKS\xba\xbe"), since expandContainer now rejects
	// non-LUKS files before growing them.
	writeLUKSFake := func(t *testing.T, dir, name string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("LUKS\xba\xbe\x00\x02padding"), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("success without key file", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// truncate, luksOpen, fsck (pre), resize2fs, fsck (post), luksClose = 6
		if len(calls) != 6 {
			t.Fatalf("expected 6 calls, got %d: %v", len(calls), calls)
		}

		// grow by truncate (portable; dd oflag=append is GNU-only)
		if calls[0].name != "truncate" {
			t.Errorf("call 0: expected truncate, got %s", calls[0].name)
		}
		if len(calls[0].args) >= 2 && calls[0].args[0] == "-s" && calls[0].args[1] != "+268435456" {
			t.Errorf("expected truncate -s +268435456, got %v", calls[0].args)
		}

		// luksOpen
		if calls[1].name != "cryptsetup" || len(calls[1].args) < 1 || calls[1].args[0] != "luksOpen" {
			t.Errorf("call 1: expected cryptsetup luksOpen, got %v", calls[1])
		}

		// fsck pre
		if calls[2].name != "fsck.ext4" {
			t.Errorf("call 2: expected fsck.ext4, got %s", calls[2].name)
		}

		// resize2fs
		if calls[3].name != "resize2fs" {
			t.Errorf("call 3: expected resize2fs, got %s", calls[3].name)
		}

		// fsck post
		if calls[4].name != "fsck.ext4" {
			t.Errorf("call 4: expected fsck.ext4, got %s", calls[4].name)
		}

		// luksClose
		if calls[5].name != "cryptsetup" || len(calls[5].args) < 1 || calls[5].args[0] != "luksClose" {
			t.Errorf("call 5: expected cryptsetup luksClose, got %v", calls[5])
		}
	})

	t.Run("rolls the grown file back when luksOpen fails", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		orig, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				return fmt.Errorf("boom")
			}
			return nil
		}

		err = expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "luksOpen failed") {
			t.Errorf("expected a luksOpen failure, got %v", err)
		}
		if len(calls) != 3 {
			t.Fatalf("expected truncate + luksOpen + rollback truncate calls, got %v", calls)
		}
		grown, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if grown.Size() != orig.Size() {
			t.Errorf("container not rolled back: size %d, want %d", grown.Size(), orig.Size())
		}
	})

	t.Run("surfaces the rollback failure when shrinking back", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		truncates := 0
		run := func(name string, args ...string) error {
			if name == "truncate" {
				truncates++
				// The first truncate grows the file; the second (rollback) fails.
				if truncates == 2 {
					return fmt.Errorf("truncate failure on shrink")
				}
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				return fmt.Errorf("boom")
			}
			return nil
		}

		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "container size not restored: truncate failure on shrink") {
			t.Errorf("expected a not-restored error, got %v", err)
		}
	})

	t.Run("rejects an already-open mapping before growing the file", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		orig := mapperProbe
		mapperProbe = func(string) bool { return true }
		t.Cleanup(func() { mapperProbe = orig })

		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "unmount and close it before expanding") {
			t.Errorf("expected an open-mapping error, got %v", err)
		}
		for _, r := range runs {
			if r.name == "truncate" {
				t.Errorf("truncate must not run while the mapping is open, got %v", runs)
			}
		}
	})

	t.Run("rejects a container open under a differently-named mapping before growing", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		newMapperFixture(t, dir, "myvol", "loop9")

		u := []byte("0bc3f7d6-3d26-4a89-a6b9-6d0d4d5f2001\n")
		runOut := func(name string, args ...string) ([]byte, error) {
			if name != "cryptsetup" || len(args) < 1 || args[0] != "luksUUID" {
				return nil, exitStatus(t, 1)
			}
			if args[1] == f || args[1] == "/dev/loop9" {
				return u, nil
			}
			return nil, exitStatus(t, 1)
		}

		err := expandContainer(run, run, runOut, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "/dev/mapper/myvol") || !strings.Contains(err.Error(), "unmount and close it before expanding") {
			t.Errorf("expected a differently-named open-mapping error, got %v", err)
		}
		for _, r := range runs {
			if r.name == "truncate" {
				t.Errorf("truncate must not run while a mapping is open, got %v", runs)
			}
		}
	})

	t.Run("rejects a key file that is the container itself before growing", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		err := expandContainer(run, run, noOutput, f, "256M", f)
		if err == nil || !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected a key/container collision error, got %v", err)
		}
		for _, r := range runs {
			if r.name == "truncate" {
				t.Errorf("truncate must not run for a colliding key file, got %v", runs)
			}
		}
	})

	t.Run("rejects a key file hard-linked to the container before growing", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		// A distinct name for the same inode cannot be caught by the
		// path/symlink comparison; only comparing file identities catches it.
		hard := filepath.Join(dir, "key.hardlink")
		if err := os.Link(f, hard); err != nil {
			t.Skipf("hard links unsupported: %v", err)
		}
		t.Cleanup(func() { os.Remove(hard) })

		err := expandContainer(run, run, noOutput, f, "256M", hard)
		if err == nil || !strings.Contains(err.Error(), "same file") {
			t.Errorf("expected a hardlink collision error, got %v", err)
		}
		for _, r := range runs {
			if r.name == "truncate" {
				t.Errorf("truncate must not run for a hardlinked key file, got %v", runs)
			}
		}
	})

	t.Run("normalizes a trailing slash on the container file", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var luksOpenSource string
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" && len(args) > 1 {
				luksOpenSource = args[len(args)-2]
			}
			return nil
		}

		// A trailing slash would make os.Stat treat the file as a directory
		// (ENOTDIR); the normalized path must be grown and opened instead.
		err := expandContainer(run, run, noOutput, f+"/", "256M", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if luksOpenSource != f {
			t.Errorf("expected luksOpen source %q (slash normalized), got %q", f, luksOpenSource)
		}
	})

	t.Run("rejects an unmappable container name before growing the file", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "my test.img")

		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "invalid device-mapper name") {
			t.Errorf("expected an invalid device-mapper name error, got %v", err)
		}
		// The backing file must not have been grown before the name check.
		for _, r := range runs {
			if r.name == "truncate" {
				t.Errorf("truncate should not run for an unmappable name, got %v", runs)
			}
		}
	})

	t.Run("final luksClose failure reports a left-open mapping", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}

		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "luksClose failed") {
			t.Errorf("expected final luksClose error, got %v", err)
		}
		if !strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("expected the error to say the mapping was left open, got %v", err)
		}
	})

	t.Run("success does not roll back after resize", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var shrinkCalls int
		run := func(name string, args ...string) error {
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				shrinkCalls++
			}
			return nil
		}

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		err = expandContainer(run, run, noOutput, f, "256M", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if shrinkCalls != 0 {
			t.Errorf("expected no rollback shrink on success, got %d", shrinkCalls)
		}
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if !strings.Contains(buf.String(), "Old size:") {
			t.Errorf("expected an Old size/New size report, got %q", buf.String())
		}
		if !strings.Contains(buf.String(), "Done.") {
			t.Errorf("expected the success closing line, got %q", buf.String())
		}
	})

	t.Run("success with key file", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		kf := filepath.Join(dir, "key")
		if err := os.WriteFile(kf, []byte("keymaterial"), 0600); err != nil {
			t.Fatal(err)
		}

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", kf)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(calls) < 2 {
			t.Fatal("expected at least 2 calls")
		}
		// luksOpen should have --key-file
		luksOpenCall := calls[1]
		if luksOpenCall.name != "cryptsetup" {
			t.Fatalf("call 1 expected cryptsetup, got %s", luksOpenCall.name)
		}
		foundKey := false
		for i, a := range luksOpenCall.args {
			if a == "--key-file" && i+1 < len(luksOpenCall.args) && luksOpenCall.args[i+1] == kf {
				foundKey = true
				break
			}
		}
		if !foundKey {
			t.Errorf("luksOpen missing --key-file %q: %v", kf, luksOpenCall.args)
		}
	})

	t.Run("accepts a trailing-slash key file path", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		kf := filepath.Join(dir, "key")
		if err := os.WriteFile(kf, []byte("keymaterial"), 0600); err != nil {
			t.Fatal(err)
		}

		var luksOpenArgs []string
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				luksOpenArgs = args
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", kf+string(filepath.Separator))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		foundKey := false
		for i, a := range luksOpenArgs {
			if a == "--key-file" && i+1 < len(luksOpenArgs) && luksOpenArgs[i+1] == kf {
				foundKey = true
				break
			}
		}
		if !foundKey {
			t.Errorf("luksOpen missing normalized --key-file %q: %v", kf, luksOpenArgs)
		}
	})

	t.Run("rejects the filesystem root as a container", func(t *testing.T) {
		var runs []cmdCall
		run := func(name string, args ...string) error {
			runs = append(runs, cmdCall{name, args})
			return nil
		}

		err := expandContainer(run, run, noOutput, "/", "256M", "")
		if err == nil || !strings.Contains(err.Error(), "filesystem root") {
			t.Errorf("expected a filesystem-root error, got %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("no commands should run for a root container, got %v", runs)
		}
	})

	t.Run("a failed post-expand stat does not fail a successful expand", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				// Simulate the container vanishing by the time the final
				// diagnostics stat runs (e.g. a concurrent removal).
				return os.Remove(f)
			}
			return nil
		}

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStderr := os.Stderr
		os.Stderr = w
		defer func() { os.Stderr = oldStderr }()

		if err := expandContainer(run, run, noOutput, f, "256M", ""); err != nil {
			t.Fatalf("expand must succeed despite the report stat failing: %v", err)
		}
		w.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		if !strings.Contains(buf.String(), "Warning: stat") {
			t.Errorf("expected a warning about the failed stat, got %q", buf.String())
		}
	})

	t.Run("returns the right flags for missing, short, and LUKS files", func(t *testing.T) {
		dir := t.TempDir()

		missing := filepath.Join(dir, "missing")
		if _, read := sniffLuks(missing); read {
			t.Error("a missing file must not be readable")
		}

		short := filepath.Join(dir, "short")
		if err := os.WriteFile(short, []byte("LU"), 0644); err != nil {
			t.Fatal(err)
		}
		if luks, read := sniffLuks(short); luks || !read {
			t.Errorf("short file: got luks=%v readable=%v, want false,true", luks, read)
		}

		luksFile := filepath.Join(dir, "luks")
		if err := os.WriteFile(luksFile, []byte(luksMagic), 0644); err != nil {
			t.Fatal(err)
		}
		if luks, read := sniffLuks(luksFile); !luks || !read {
			t.Errorf("LUKS-magic file: got luks=%v readable=%v, want true,true", luks, read)
		}

		other := filepath.Join(dir, "other")
		if err := os.WriteFile(other, []byte("NOTLUK\xba\xbeheader-tails"), 0644); err != nil {
			t.Fatal(err)
		}
		if luks, read := sniffLuks(other); luks || !read {
			t.Errorf("mismatched-magic file: got luks=%v readable=%v, want false,true", luks, read)
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := expandContainer(run, run, noOutput, "/nonexistent/file", "256M", "")
		if err == nil || !strings.Contains(err.Error(), "stat") {
			t.Errorf("expected stat error, got %v", err)
		}
	})

	t.Run("rejects a socket container file before probing or growing", func(t *testing.T) {
		sock := makeSocket(t)

		var truncateCalls, cryptCalls int
		run := func(name string, args ...string) error {
			if name == "truncate" {
				truncateCalls++
			}
			if name == "cryptsetup" {
				cryptCalls++
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, sock, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("expected a not-a-regular-file error, got %v", err)
		}
		if truncateCalls != 0 {
			t.Errorf("container should not be grown when it is a socket, got %d truncate calls", truncateCalls)
		}
		if cryptCalls != 0 {
			t.Errorf("cryptsetup should not be probed for a socket container, got %d calls", cryptCalls)
		}
	})

	t.Run("missing key file fails fast before growing", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var truncateArgs []string
		run := func(name string, args ...string) error {
			if name == "truncate" {
				truncateArgs = append(truncateArgs, args...)
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", filepath.Join(dir, "nokey"))
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' key file error, got %v", err)
		}
		if len(truncateArgs) != 0 {
			t.Errorf("container should not be grown when the key file is missing, truncate: %v", truncateArgs)
		}
	})

	t.Run("directory key file is rejected before growing", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var truncateArgs []string
		run := func(name string, args ...string) error {
			if name == "truncate" {
				truncateArgs = append(truncateArgs, args...)
			}
			return nil
		}
		dirKey := filepath.Join(dir, "keydir")
		if err := os.MkdirAll(dirKey, 0755); err != nil {
			t.Fatal(err)
		}
		err := expandContainer(run, run, noOutput, f, "256M", dirKey)
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Errorf("expected a directory-key-file error, got %v", err)
		}
		if len(truncateArgs) != 0 {
			t.Errorf("container should not be grown when the key file is a directory, truncate: %v", truncateArgs)
		}
	})

	t.Run("empty key file is rejected before growing", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var truncateArgs []string
		run := func(name string, args ...string) error {
			if name == "truncate" {
				truncateArgs = append(truncateArgs, args...)
			}
			return nil
		}
		emptyKey := filepath.Join(dir, "empty.key")
		if err := os.WriteFile(emptyKey, nil, 0600); err != nil {
			t.Fatal(err)
		}
		err := expandContainer(run, run, noOutput, f, "256M", emptyKey)
		if err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("expected an empty-key-file error, got %v", err)
		}
		if len(truncateArgs) != 0 {
			t.Errorf("container should not be grown when the key file is empty, truncate: %v", truncateArgs)
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		run := func(name string, args ...string) error { return nil }
		err := expandContainer(run, run, noOutput, f, "invalid", "")
		if err == nil {
			t.Error("expected error for invalid size, got nil")
		}
	})

	t.Run("truncate fails", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		run := func(name string, args ...string) error {
			if name == "truncate" {
				return errors.New("truncate failed")
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "expanding container") {
			t.Errorf("expected expand error, got %v", err)
		}
	})

	t.Run("luksOpen fails cleans up", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		before, statErr := os.Stat(f)
		if statErr != nil {
			t.Fatal(statErr)
		}

		var closeCalled bool
		var shrinkArgs []string
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				return errors.New("open fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				shrinkArgs = args
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "luksOpen failed") {
			t.Errorf("expected luksOpen error, got %v", err)
		}
		if closeCalled {
			t.Error("luksClose should not be called when luksOpen itself failed")
		}
		if len(shrinkArgs) != 3 || shrinkArgs[1] != fmt.Sprintf("%d", before.Size()) {
			t.Errorf("expected rollback truncate -s %d, got %v", before.Size(), shrinkArgs)
		}
	})

	t.Run("fsck pre fails cleans up luksClose", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		before, statErr := os.Stat(f)
		if statErr != nil {
			t.Fatal(statErr)
		}

		var closeCalled bool
		var shrinkArgs []string
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && len(args) > 1 && args[0] == "-f" && args[1] == "-y" {
				return errors.New("fsck fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				shrinkArgs = args
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (pre)") {
			t.Errorf("expected fsck pre error, got %v", err)
		}
		if !closeCalled {
			t.Error("expected luksClose after fsck pre failure")
		}
		if len(shrinkArgs) != 3 || shrinkArgs[1] != fmt.Sprintf("%d", before.Size()) {
			t.Errorf("expected rollback truncate -s %d, got %v", before.Size(), shrinkArgs)
		}
	})

	t.Run("fsck pre failure surfaces a rollback failure", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var shrinkErr bool
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && len(args) > 1 && args[0] == "-f" && args[1] == "-y" {
				return errors.New("fsck fail")
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				// The shrinking rollback fails, leaving the container grown.
				shrinkErr = true
				return errors.New("shrink fail")
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (pre)") {
			t.Errorf("expected fsck pre error, got %v", err)
		}
		if !shrinkErr {
			t.Fatal("expected the rollback truncate to be attempted")
		}
		if !strings.Contains(err.Error(), "container size not restored") {
			t.Errorf("expected a size-not-restored hint when the rollback fails, got %v", err)
		}
	})

	t.Run("fsck post failure closes the mapping", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var closeCalled, resizeCalled bool
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && args[0] == "-f" && args[1] == "-y" {
				// Only fail the post-resize check (the second fsck).
				if resizeCalled {
					return errors.New("fsck post fail")
				}
				return nil
			}
			if name == "resize2fs" {
				resizeCalled = true
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (post)") {
			t.Errorf("expected fsck post error, got %v", err)
		}
		if !strings.Contains(err.Error(), "container left grown; filesystem resized") {
			t.Errorf("expected the container to be reported as left grown, got %v", err)
		}
		if !closeCalled {
			t.Error("expected luksClose after the post-resize check failed")
		}
	})

	t.Run("fsck pre failure closes mapping before shrinking", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var order []string
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && len(args) > 1 && args[0] == "-f" && args[1] == "-y" {
				return errors.New("fsck fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				order = append(order, "close")
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				order = append(order, "shrink")
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (pre)") {
			t.Errorf("expected fsck pre error, got %v", err)
		}
		if len(order) != 2 || order[0] != "close" || order[1] != "shrink" {
			t.Errorf("expected close-then-shrink order, got %v", order)
		}
	})

	t.Run("fsck pre failure does not shrink when close fails", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var shrinkArgs, growArgs []string
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && len(args) > 1 && args[0] == "-f" && args[1] == "-y" {
				return errors.New("fsck fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close fail")
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" {
				if strings.HasPrefix(args[1], "+") {
					growArgs = args
				} else {
					shrinkArgs = args
				}
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (pre)") {
			t.Errorf("expected fsck pre error, got %v", err)
		}
		if len(growArgs) == 0 {
			t.Error("expected the container to have been grown before luksOpen")
		}
		if len(shrinkArgs) != 0 {
			t.Errorf("expected no shrink when luksClose fails, got %v", shrinkArgs)
		}
	})

	t.Run("fsck post failure reports a left-open mapping when close fails", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var fsckCalls int
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && len(args) > 1 && args[0] == "-f" && args[1] == "-y" {
				fsckCalls++
				// Fail only the second (post-resize) check.
				if fsckCalls == 2 {
					return errors.New("fsck post fail")
				}
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close fail")
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (post)") {
			t.Errorf("expected fsck post error, got %v", err)
		}
		if !strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("expected a left-open-mapping hint when luksClose fails, got %v", err)
		}
	})

	t.Run("resize2fs fails does not roll back", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var closeCalled bool
		var shrinkArgs []string
		run := func(name string, args ...string) error {
			if name == "resize2fs" {
				return errors.New("resize fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
				return errors.New("close fail")
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				shrinkArgs = args
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "resize2fs failed") {
			t.Errorf("expected resize2fs error, got %v", err)
		}
		if !closeCalled {
			t.Error("expected luksClose after resize2fs failure")
		}
		if !strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("expected a left-open-mapping hint when luksClose fails, got %v", err)
		}
		if len(shrinkArgs) != 0 {
			t.Errorf("expected no rollback shrink after resize2fs failure, got %v", shrinkArgs)
		}
	})

	t.Run("resize2fs fails reports the container is left grown", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var closeCalled bool
		var shrinkArgs []string
		run := func(name string, args ...string) error {
			if name == "resize2fs" {
				return errors.New("resize fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				shrinkArgs = args
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "resize2fs failed") {
			t.Fatalf("expected resize2fs error, got %v", err)
		}
		if !closeCalled {
			t.Error("expected luksClose after resize2fs failure")
		}
		if strings.Contains(err.Error(), "mapping left open") {
			t.Errorf("mapping was closed; the error must not claim it is open: %v", err)
		}
		if !strings.Contains(err.Error(), "container left grown") {
			t.Errorf("expected a left-grown hint when the mapping closed, got %v", err)
		}
		if len(shrinkArgs) != 0 {
			t.Errorf("expected no rollback shrink after resize2fs failure, got %v", shrinkArgs)
		}
	})

	t.Run("luksOpen fails surfaces a rollback failure", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		var shrinkErr bool
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				return errors.New("open fail")
			}
			if name == "truncate" && len(args) >= 2 && args[0] == "-s" && !strings.HasPrefix(args[1], "+") {
				// The shrinking rollback fails, leaving the file grown.
				shrinkErr = true
				return errors.New("shrink fail")
			}
			return nil
		}
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "luksOpen failed") {
			t.Errorf("expected luksOpen error, got %v", err)
		}
		if !shrinkErr {
			t.Fatal("expected the rollback truncate to be attempted")
		}
		if !strings.Contains(err.Error(), "container size not restored") {
			t.Errorf("expected a size-not-restored hint when the rollback fails, got %v", err)
		}
	})

	t.Run("rejects non-LUKS file without growing it", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		if err := os.WriteFile(f, []byte("not a luks container"), 0644); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}

		var ddCalled bool
		run := func(name string, args ...string) error {
			if name == "dd" {
				ddCalled = true
			}
			return nil
		}
		err = expandContainer(run, run, noOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "not a LUKS container") {
			t.Fatalf("expected not-a-LUKS error, got %v", err)
		}
		if ddCalled {
			t.Error("dd should not be called on a non-LUKS file")
		}
		after, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if after.Size() != before.Size() {
			t.Errorf("file size changed from %d to %d; non-LUKS file must not be grown", before.Size(), after.Size())
		}
	})

	t.Run("a readable non-LUKS container is rejected with no privileged probe", func(t *testing.T) {
		// The mount side pins this as a hard constraint ("sniffs a LUKS-magic
		// file without probing cryptsetup"); the expand gate must uphold the
		// same contract. A readable header is a definitive "not LUKS" verdict,
		// so a plain container reaching cryptsetup isLuks would be a wasted
		// sudo invocation that this test must catch: pre-R3-6 expand probed
		// every readable non-LUKS file, and the old test (rejected + not grown)
		// would not have flagged a regression back to it.
		dir := t.TempDir()
		f := filepath.Join(dir, "plain.img")
		if err := os.WriteFile(f, []byte("not a luks container, definitely plain"), 0644); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}

		var probed, sudoCrypto bool
		run := func(name string, args ...string) error {
			if name == "cryptsetup" {
				sudoCrypto = true
			}
			return nil
		}
		probeOut := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "isLuks" {
				probed = true
			}
			return nil, exitStatus(t, 1)
		}
		err = expandContainer(run, run, probeOut, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "not a LUKS container") {
			t.Fatalf("expected not-a-LUKS error, got %v", err)
		}
		if probed {
			t.Error("cryptsetup isLuks must not be probed for a readable non-LUKS container")
		}
		if sudoCrypto {
			t.Error("cryptsetup must not be invoked at all for a readable non-LUKS container")
		}
		after, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if after.Size() != before.Size() {
			t.Errorf("file size changed from %d to %d; non-LUKS file must not be grown", before.Size(), after.Size())
		}
	})

	t.Run("an unreadable LUKS container falls back to the privileged probe", func(t *testing.T) {
		// A container the invoking user may write but not read (a chmod-000
		// file standing in for a root-owned container) would otherwise be
		// refused as "not a LUKS container"; the probe must admit it and the
		// expand must proceed.
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		if err := os.Chmod(f, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(f, 0600) })

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		// noOutput claims cryptsetup isLuks success, so the fallback verdict is
		// "LUKS" and the normal six-call expand sequence runs.
		err := expandContainer(run, run, noOutput, f, "256M", "")
		if err != nil {
			t.Fatalf("expected the privileged probe to admit the unreadable LUKS container, got %v", err)
		}
		if len(calls) != 6 {
			t.Fatalf("expected the full expand sequence (6 calls), got %d: %v", len(calls), calls)
		}
		if calls[0].name != "truncate" {
			t.Errorf("call 0: expected truncate, got %s", calls[0].name)
		}
	})

	t.Run("an unreadable non-LUKS source is rejected via the probe verdict", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		if err := os.WriteFile(f, []byte("plain content"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(f, 0600) })

		var truncated bool
		run := func(name string, args ...string) error {
			if name == "truncate" {
				truncated = true
			}
			return nil
		}
		// cryptsetup exit 1 is the genuine "not LUKS" verdict.
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }

		err := expandContainer(run, run, runOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "not a LUKS container") {
			t.Fatalf("expected a not-a-LUKS error from the exit-1 verdict, got %v", err)
		}
		if truncated {
			t.Error("truncate must not run on an unreadable non-LUKS source")
		}
	})

	t.Run("an unreadable source with a probe failure surfaces the probe error", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(f, 0600) })

		run := func(name string, args ...string) error { return nil }
		// An exit code that is neither 0 nor 1 is a failed probe, not a
		// verdict; it must be reported rather than read as "not LUKS".
		runOutput := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 4) }

		err := expandContainer(run, run, runOutput, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "cannot determine whether") {
			t.Fatalf("expected a probe-failure error, got %v", err)
		}
	})

	t.Run("waits for the mapper node after luksOpen", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")
		run := func(name string, args ...string) error { return nil }

		origStat := devStat
		origTries := waitForDeviceTries
		devStat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		waitForDeviceTries = 2
		t.Cleanup(func() { devStat = origStat; waitForDeviceTries = origTries })

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

		if err := expandContainer(run, run, noOutput, f, "256M", ""); err != nil {
			t.Fatalf("expected a continuing expand, got %v", err)
		}
		os.Stderr = oldStderr
		w.Close()
		<-done
		if !strings.Contains(buf.String(), "udev may still be settling") {
			t.Errorf("expected a settling warning when the node never appears, got %q", buf.String())
		}
	})
}

func TestLuksForSource(t *testing.T) {
	t.Run("readable LUKS-magic file is detected without a probe", func(t *testing.T) {
		dir := t.TempDir()
		luksFile := filepath.Join(dir, "luks.img")
		if err := os.WriteFile(luksFile, []byte(luksMagic), 0644); err != nil {
			t.Fatal(err)
		}
		var probed bool
		run := func(name string, args ...string) ([]byte, error) {
			probed = true
			return nil, exitStatus(t, 1)
		}
		if !luksForSource(run, luksFile) {
			t.Error("a readable LUKS-magic file must be detected")
		}
		if probed {
			t.Error("no privileged probe should run for a readable LUKS-magic file")
		}
	})

	t.Run("a readable non-LUKS file is resolved without a privileged probe", func(t *testing.T) {
		// A plain container has a definitively readable header: isLuksContainer
		// already read it and saw no magic, so a privileged cryptsetup probe
		// (and its possible sudo prompt) on every plain-file unmount adds
		// nothing. Only an unreadable header needs the probe.
		dir := t.TempDir()
		plain := filepath.Join(dir, "plain.img")
		if err := os.WriteFile(plain, []byte("not luks at all"), 0644); err != nil {
			t.Fatal(err)
		}
		var probed bool
		run := func(name string, args ...string) ([]byte, error) {
			probed = true
			return nil, exitStatus(t, 1)
		}
		if luksForSource(run, plain) {
			t.Error("a readable non-LUKS file must be reported as not LUKS")
		}
		if probed {
			t.Error("no privileged probe should run for a readable non-LUKS file")
		}
	})

	t.Run("an unreadable regular file falls back to the privileged probe", func(t *testing.T) {
		// A source whose header cannot be read (here a chmod-000 file standing
		// in for an unreadable block device) must not be silently treated as
		// "not LUKS": isLuksContainer says false, and the fallback probe then
		// resolves the real verdict so a differently-named mapping is found.
		dir := t.TempDir()
		unread := filepath.Join(dir, "locked.img")
		if err := os.WriteFile(unread, []byte(luksMagic), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unread, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(unread, 0600) })

		if isLuksContainer(unread) {
			t.Fatal("isLuksContainer must report an unreadable file as not LUKS (this is the gap being fixed)")
		}

		// The privileged probe reports it IS LUKS (cryptsetup isLuks exit 0).
		run := func(name string, args ...string) ([]byte, error) {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "isLuks" {
				return nil, nil
			}
			return nil, exitStatus(t, 1)
		}
		if !luksForSource(run, unread) {
			t.Error("an unreadable source that is LUKS must be detected via the privileged probe")
		}
	})

	t.Run("an unreadable source that is not LUKS is reported as not LUKS", func(t *testing.T) {
		dir := t.TempDir()
		unread := filepath.Join(dir, "plain")
		if err := os.WriteFile(unread, []byte("plain"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unread, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(unread, 0600) })

		// cryptsetup isLuks exits 1 for a genuinely non-LUKS source.
		run := func(name string, args ...string) ([]byte, error) { return nil, exitStatus(t, 1) }
		if luksForSource(run, unread) {
			t.Error("an unreadable non-LUKS source must be reported as not LUKS (exit-1 verdict)")
		}
	})

	t.Run("a FIFO is never opened, so it is not LUKS and is not probed", func(t *testing.T) {
		fifo := makeFIFO(t)
		var probed bool
		run := func(name string, args ...string) ([]byte, error) {
			probed = true
			return nil, exitStatus(t, 1)
		}
		if luksForSource(run, fifo) {
			t.Error("a FIFO must never be treated as a LUKS container")
		}
		if probed {
			t.Error("a FIFO must not be opened for a LUKS probe (would block)")
		}
	})

	t.Run("a failed probe is treated as not LUKS, never fabricating a mapping", func(t *testing.T) {
		dir := t.TempDir()
		unread := filepath.Join(dir, "locked")
		if err := os.WriteFile(unread, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unread, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(unread, 0600) })

		// A probe failure (not a clean exit-1 verdict) yields no LUKS
		// determination, so luksForSource must not invent one.
		run := func(name string, args ...string) ([]byte, error) { return nil, errors.New("cryptsetup missing") }
		if luksForSource(run, unread) {
			t.Error("a failed LUKS probe must not be treated as LUKS")
		}
	})
}

func TestCreateContainerBlockSize(t *testing.T) {
	tests := []struct {
		size      string
		wantBS    string
		wantCount string
	}{
		{"50M", "32M", "1"},
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
			createContainer(run, run, filepath.Join(t.TempDir(), "test.img"), tt.size, "", "", 512, false)

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

			// The total bytes allocated across the dd bulk write and the
			// truncate remainder must equal the requested size exactly
			// (no overshoot from ceil'ing).
			wantTotal, err := parseSize(tt.size)
			if err != nil {
				t.Fatal(err)
			}
			var got int64
			for _, c := range calls {
				switch c.name {
				case "dd":
					var bs, count int64
					for _, a := range c.args {
						if v, ok := strings.CutPrefix(a, "bs="); ok {
							bs, _ = strconv.ParseInt(strings.TrimSuffix(v, "M"), 10, 64)
							if strings.HasSuffix(v, "M") {
								bs *= 1024 * 1024
							}
						}
						if cnt, ok := strings.CutPrefix(a, "count="); ok {
							count, _ = strconv.ParseInt(cnt, 10, 64)
						}
					}
					if bs == 0 {
						t.Fatalf("dd missing bs: %v", c.args)
					}
					got += bs * count
				case "truncate":
					for _, a := range c.args {
						if sz, ok := strings.CutPrefix(a, "+"); ok {
							n, _ := strconv.ParseInt(sz, 10, 64)
							got += n
						}
					}
				}
				if c.name != "dd" && c.name != "truncate" {
					break
				}
			}
			if got != wantTotal {
				t.Errorf("allocated %d bytes, want %d for %s", got, wantTotal, tt.size)
			}

		})
	}
}

func TestWriteZerosExclusiveOwnerIsUntouchable(t *testing.T) {
	dir := t.TempDir()

	t.Run("fresh path is claimed as ours", func(t *testing.T) {
		of := filepath.Join(dir, "fresh.img")
		run := func(name string, args ...string) error {
			if name == "dd" {
				// land the bulk write the way dd would, so the resulting file
				// has the requested size and the claim is visibly ours
				for _, a := range args {
					if target, ok := strings.CutPrefix(a, "of="); ok {
						return os.Truncate(target, 32*1024*1024)
					}
				}
			}
			return nil
		}
		created, err := writeZeros(run, of, 32*1024*1024)
		if err != nil {
			t.Fatalf("unexpected error on a fresh path: %v", err)
		}
		if !created {
			t.Error("a fresh path must be reported as created by this call")
		}
		if fi, statErr := os.Stat(of); statErr != nil || fi.Size() != 32*1024*1024 {
			t.Errorf("expected a 32M container file, got %v (err %v)", fi, statErr)
		}
	})

	t.Run("a racing file that already exists is not ours", func(t *testing.T) {
		of := filepath.Join(dir, "racer.img")
		racer := []byte("racing data")
		if err := os.WriteFile(of, racer, 0644); err != nil {
			t.Fatal(err)
		}
		run := func(name string, args ...string) error {
			if name == "dd" {
				t.Error("dd must not run when the exclusive claim fails")
			}
			return nil
		}
		created, err := writeZeros(run, of, 32*1024*1024)
		if err == nil {
			t.Fatal("expected an error when the path already exists")
		}
		if created {
			t.Error("a pre-existing file must not be reported as created by this call")
		}
		// The make check gate runs the race test, so assert the file survived
		// byte-for-byte: O_EXCL must never let a failure path clean up someone
		// else's file.
		if got, readErr := os.ReadFile(of); readErr != nil || string(got) != string(racer) {
			t.Errorf("racer's file must survive untouched; read %q (err %v)", got, readErr)
		}
	})
}

func TestWriteZerosTruncateFailure(t *testing.T) {
	dir := t.TempDir()
	of := filepath.Join(dir, "img")

	var sawDD, sawTruncate bool
	run := func(name string, args ...string) error {
		switch name {
		case "dd":
			sawDD = true
		case "truncate":
			sawTruncate = true
			return errors.New("truncate boom")
		}
		return nil
	}

	// 17MiB+1 byte is not a whole multiple of the 18MiB rounded block size, so
	// the dd bulk write is followed by a truncate extension to the exact size.
	created, err := writeZeros(run, of, 17*1024*1024+1)
	if err == nil || !strings.Contains(err.Error(), "truncate boom") {
		t.Fatalf("expected the truncate failure to surface, got %v", err)
	}
	if !created {
		t.Error("the O_EXCL claim succeeded, so the partial file is ours to clean up")
	}
	if !sawDD {
		t.Error("expected the bulk dd write to run before truncate")
	}
	if !sawTruncate {
		t.Error("expected a truncate extension for the sub-block remainder")
	}
}

func TestCreateContainerRejectsAlreadyOpenMapping(t *testing.T) {
	orig := mapperProbe
	mapperProbe = func(string) bool { return true }
	t.Cleanup(func() { mapperProbe = orig })

	var runs int
	run := func(name string, args ...string) error {
		runs++
		return nil
	}

	err := createContainer(run, run, "vault.img", "32M", "", "", 0, false)
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected an already-in-use mapping error, got %v", err)
	}
	if runs != 0 {
		t.Errorf("no command should run when the mapping name is taken, saw %d", runs)
	}
}

func TestCreateContainerKeyFileChmodFailure(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "container.img")

	run := func(name string, args ...string) error {
		if name == "dd" {
			// simulate the dd payload landing on disk for both the key file
			// (if=/dev/urandom) and the container (if=/dev/zero)
			for _, a := range args {
				if strings.HasPrefix(a, "of=") {
					target := strings.TrimPrefix(a, "of=")
					os.Remove(target)
					return os.WriteFile(target, make([]byte, 512), 0644)
				}
			}
			t.Fatal("dd args did not include an of= target")
		}
		return nil
	}

	origChmod := chmod
	chmod = func(name string, mode os.FileMode) error {
		return fmt.Errorf("permission denied")
	}
	t.Cleanup(func() { chmod = origChmod })

	err := createContainer(run, run, img, "256M", "", filepath.Join(dir, "key.bin"), 512, false)
	if err == nil || !strings.Contains(err.Error(), "setting key file permissions") {
		t.Fatalf("expected a key file permission error, got %v", err)
	}
}

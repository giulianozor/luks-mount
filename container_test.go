package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

		img := filepath.Join(t.TempDir(), "container.img")
		err := createContainer(run, run, img, "256M", "", "", 512)
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

	t.Run("success without key file, non-relative path", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		img := filepath.Join(dir, "subdir", "container.img")
		err := createContainer(run, run, img, "256M", "", "", 512)
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
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		kf := filepath.Join(dir, "keyfile")
		err := createContainer(run, run, img, "256M", "", kf, 512)
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

	t.Run("success with existing key file", func(t *testing.T) {
		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		kf := filepath.Join(dir, "existing.key")
		err := createContainer(run, run, img, "256M", kf, "", 512)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// dd (container), luksFormat, luksAddKey, luksOpen, mkfs.ext4, luksClose = 6
		if len(calls) != 6 {
			t.Fatalf("expected 6 calls, got %d: %v", len(calls), calls)
		}

		// no key file generation call
		if calls[0].name != "dd" || len(calls[0].args) < 1 || calls[0].args[0] != "if=/dev/zero" {
			t.Errorf("call 0: expected dd zero container, got %v", calls[0])
		}
		// luksAddKey with existing key
		if calls[2].name != "cryptsetup" || calls[2].args[0] != "luksAddKey" || calls[2].args[len(calls[2].args)-1] != kf {
			t.Errorf("call 2: expected luksAddKey with %q, got %v", kf, calls[2])
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

	t.Run("container already exists", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir := t.TempDir()
		existing := filepath.Join(dir, "existing.img")
		os.WriteFile(existing, []byte("data"), 0644)
		err := createContainer(run, run, existing, "256M", "", "", 512)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got %v", err)
		}
	})

	t.Run("key file already exists", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		existingKey := filepath.Join(dir, "existing.key")
		os.WriteFile(existingKey, []byte("keydata"), 0644)
		err := createContainer(run, run, img, "256M", "", existingKey, 512)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got %v", err)
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "invalid", "", "", 512)
		if err == nil {
			t.Error("expected error for invalid size, got nil")
		}
	})

	t.Run("size below minimum", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		img := filepath.Join(t.TempDir(), "c.img")
		err := createContainer(run, run, img, "16M", "", "", 512)
		if err == nil || !strings.Contains(err.Error(), "minimum container size is 32M") {
			t.Errorf("expected minimum size error, got %v", err)
		}
		err = createContainer(run, run, img, "31M", "", "", 512)
		if err == nil || !strings.Contains(err.Error(), "minimum container size is 32M") {
			t.Errorf("expected minimum size error for 31M, got %v", err)
		}
	})

	t.Run("non-positive key file size rejected", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		img := filepath.Join(t.TempDir(), "c.img")
		for _, ks := range []int{0, -1} {
			err := createContainer(run, run, img, "256M", "", filepath.Join(t.TempDir(), "k"), ks)
			if err == nil || !strings.Contains(err.Error(), "key file size must be positive") {
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

		err := createContainer(run, run, img, "256M", "", kf, 512)
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

	t.Run("dd container fails cleans up key file", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				return nil
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return errors.New("dd container failed")
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512)
		if err == nil || !strings.Contains(err.Error(), "creating container") {
			t.Fatalf("expected container error, got %v", err)
		}
		if _, statErr := os.Stat(kf); !os.IsNotExist(statErr) {
			t.Errorf("key file %q should have been removed when container creation failed", kf)
		}
	})

	t.Run("dd container fails", func(t *testing.T) {
		run := func(name string, args ...string) error {
			if name == "dd" {
				return errors.New("dd failed")
			}
			return nil
		}
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512)
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
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512)
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
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512)
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
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512)
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
		err := createContainer(run, run, filepath.Join(t.TempDir(), "c.img"), "256M", "", "", 512)
		if err == nil || !strings.Contains(err.Error(), "luksClose failed") {
			t.Errorf("expected luksClose error, got %v", err)
		}
	})

	t.Run("cleans up container and key file on failure", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		kf := filepath.Join(dir, "keyfile")

		run := func(name string, args ...string) error {
			if name == "mkfs.ext4" {
				return errors.New("mkfs failed")
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512)
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
		err := createContainer(run, run, img, "256M", "", "", 512)
		if err == nil {
			t.Fatal("expected 'already exists' error")
		}
		if _, statErr := os.Stat(img); os.IsNotExist(statErr) {
			t.Errorf("file %q should not have been removed on early validation error", img)
		}
	})
}

func TestExpandContainer(t *testing.T) {
	t.Run("success without key file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		os.WriteFile(f, []byte("initial"), 0644)

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}

		err := expandContainer(run, run, f, "256M", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// dd, luksOpen, fsck (pre), resize2fs, fsck (post), luksClose = 6
		if len(calls) != 6 {
			t.Fatalf("expected 6 calls, got %d: %v", len(calls), calls)
		}

		// dd with append
		if calls[0].name != "dd" {
			t.Errorf("call 0: expected dd, got %s", calls[0].name)
		}
		hasAppend := false
		for _, a := range calls[0].args {
			if a == "oflag=append" {
				hasAppend = true
				break
			}
		}
		if !hasAppend {
			t.Errorf("dd args missing oflag=append: %v", calls[0].args)
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

	t.Run("success with key file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		os.WriteFile(f, []byte("initial"), 0644)

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			return nil
		}
		err := expandContainer(run, run, f, "256M", "/path/to/key")

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
			if a == "--key-file" && i+1 < len(luksOpenCall.args) && luksOpenCall.args[i+1] == "/path/to/key" {
				foundKey = true
				break
			}
		}
		if !foundKey {
			t.Errorf("luksOpen missing --key-file /path/to/key: %v", luksOpenCall.args)
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := expandContainer(run, run, "/nonexistent/file", "256M", "")
		if err == nil || !strings.Contains(err.Error(), "stat") {
			t.Errorf("expected stat error, got %v", err)
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		os.WriteFile(f, []byte("x"), 0644)

		run := func(name string, args ...string) error { return nil }
		err := expandContainer(run, run, f, "invalid", "")
		if err == nil {
			t.Error("expected error for invalid size, got nil")
		}
	})

	t.Run("dd fails", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		os.WriteFile(f, []byte("x"), 0644)

		run := func(name string, args ...string) error {
			if name == "dd" {
				return errors.New("dd failed")
			}
			return nil
		}
		err := expandContainer(run, run, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "expanding container") {
			t.Errorf("expected expand error, got %v", err)
		}
	})

	t.Run("luksOpen fails cleans up", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		os.WriteFile(f, []byte("x"), 0644)

		var closeCalled bool
		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksOpen" {
				return errors.New("open fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
			}
			return nil
		}
		err := expandContainer(run, run, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "luksOpen failed") {
			t.Errorf("expected luksOpen error, got %v", err)
		}
		if closeCalled {
			t.Error("luksClose should not be called when luksOpen itself failed")
		}
	})

	t.Run("fsck pre fails cleans up luksClose", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		os.WriteFile(f, []byte("x"), 0644)

		var closeCalled bool
		run := func(name string, args ...string) error {
			if name == "fsck.ext4" && len(args) > 1 && args[0] == "-f" && args[1] == "-y" {
				return errors.New("fsck fail")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				closeCalled = true
			}
			return nil
		}
		err := expandContainer(run, run, f, "256M", "")
		if err == nil || !strings.Contains(err.Error(), "fsck.ext4 (pre)") {
			t.Errorf("expected fsck pre error, got %v", err)
		}
		if !closeCalled {
			t.Error("expected luksClose after fsck pre failure")
		}
	})
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
			createContainer(run, run, filepath.Join(t.TempDir(), "test.img"), tt.size, "", "", 512)

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

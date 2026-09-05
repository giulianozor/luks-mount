package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
		subdir := filepath.Join(dir, "subdir")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		img := filepath.Join(subdir, "container.img")
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
		dir := t.TempDir()
		img := filepath.Join(dir, "container.img")
		kf := filepath.Join(dir, "keyfile")

		var calls []cmdCall
		run := func(name string, args ...string) error {
			calls = append(calls, cmdCall{name, args})
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				// simulate the generated key file being written to disk
				return os.WriteFile(kf, []byte("keydata"), 0644)
			}
			return nil
		}

		err := createContainer(run, run, img, "256M", "", kf, 512)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// the generated key file must be private, not world-readable
		if fi, statErr := os.Stat(kf); statErr == nil && fi.Mode()&0777 != 0600 {
			t.Errorf("expected generated key file mode 0600, got %o", fi.Mode()&0777)
		}
		if len(calls) != 6 {
			t.Fatalf("expected 6 calls, got %d: %v", len(calls), calls)
		}

		if calls[0].name != "dd" || len(calls[0].args) < 1 || calls[0].args[0] != "if=/dev/urandom" {
			t.Errorf("call 0: expected dd urandom key file, got %v", calls[0])
		}
		if calls[1].name != "dd" || len(calls[1].args) < 1 || calls[1].args[0] != "if=/dev/zero" {
			t.Errorf("call 1: expected dd zero container, got %v", calls[1])
		}
		// luksFormat should install the generated key file as the initial key
		if calls[2].name != "cryptsetup" || calls[2].args[0] != "luksFormat" || calls[2].args[1] != "--batch-mode" {
			t.Errorf("call 2: expected cryptsetup luksFormat --batch-mode, got %v", calls[2])
		}
		foundFormatKey := false
		for i, a := range calls[2].args {
			if a == "--key-file" && i+1 < len(calls[2].args) && calls[2].args[i+1] == kf {
				foundFormatKey = true
				break
			}
		}
		if !foundFormatKey {
			t.Errorf("luksFormat missing --key-file %q, got %v", kf, calls[2].args)
		}
		if calls[3].name != "cryptsetup" || calls[3].args[0] != "luksOpen" {
			t.Errorf("call 3: expected cryptsetup luksOpen, got %v", calls[3])
		}
		if calls[4].name != "mkfs.ext4" {
			t.Errorf("call 4: expected mkfs.ext4, got %s", calls[4].name)
		}
		if calls[5].name != "cryptsetup" || calls[5].args[0] != "luksClose" {
			t.Errorf("call 5: expected cryptsetup luksClose, got %v", calls[5])
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
		os.WriteFile(kf, []byte("keydata"), 0644)
		err := createContainer(run, run, img, "256M", kf, "", 512)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// dd (container), luksFormat --key-file, luksOpen --key-file, mkfs.ext4, luksClose = 5
		if len(calls) != 5 {
			t.Fatalf("expected 5 calls, got %d: %v", len(calls), calls)
		}

		// no key file generation call
		if calls[0].name != "dd" || len(calls[0].args) < 1 || calls[0].args[0] != "if=/dev/zero" {
			t.Errorf("call 0: expected dd zero container, got %v", calls[0])
		}
		// luksFormat should install the existing key file as the initial key
		if calls[1].name != "cryptsetup" || calls[1].args[0] != "luksFormat" {
			t.Errorf("call 1: expected cryptsetup luksFormat, got %v", calls[1])
		}
		foundFormatKey := false
		for i, a := range calls[1].args {
			if a == "--key-file" && i+1 < len(calls[1].args) && calls[1].args[i+1] == kf {
				foundFormatKey = true
				break
			}
		}
		if !foundFormatKey {
			t.Errorf("luksFormat missing --key-file %q, got %v", kf, calls[1].args)
		}
		// luksOpen with --key-file existing key
		if calls[2].name != "cryptsetup" || calls[2].args[0] != "luksOpen" {
			t.Errorf("call 2: expected cryptsetup luksOpen, got %v", calls[2])
		}
		// no luksAddKey call
		for _, c := range calls {
			if c.name == "cryptsetup" && len(c.args) > 0 && c.args[0] == "luksAddKey" {
				t.Errorf("luksAddKey should not be called when luksFormat already uses the key file: %v", c)
			}
		}
		foundKey := false
		for i, a := range calls[2].args {
			if a == "--key-file" && i+1 < len(calls[2].args) && calls[2].args[i+1] == kf {
				foundKey = true
				break
			}
		}
		if !foundKey {
			t.Errorf("luksOpen missing --key-file %q: %v", kf, calls[2].args)
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

	t.Run("container path probe failure is reported, not overwritten", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		// A too-long component makes os.Stat fail with a non-isNotExist error
		// (file name too long). The create must refuse rather than overwrite.
		bad := strings.Repeat("a", 3000)
		err := createContainer(run, run, bad, "256M", "", "", 512)
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
		err := createContainer(run, run, img, "256M", "", filepath.Join(t.TempDir(), "keyfile"), 512)
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
		err := createContainer(run, run, img, "256M", "", img, 512)
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
		err = createContainer(run, run, img, "256M", "", sneaky, 512)
		if err == nil || !strings.Contains(err.Error(), "must be different") {
			t.Errorf("expected a cleaned-path collision error, got %v", err)
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
		err := createContainer(run, run, img, "256M", "", kf, 512)
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
		os.WriteFile(existingKey, []byte("keydata"), 0644)
		err := createContainer(run, run, img, "256M", "", existingKey, 512)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got %v", err)
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
		err := createContainer(run, run, img, "256M", "/nonexistent/existing.key", "", 512)
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected existing-key-file error, got %v", err)
		}
		if ranCryptsetup {
			t.Error("cryptsetup should not run when the existing key file is missing")
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
				return os.WriteFile(kf, []byte("keydata"), 0644)
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

	t.Run("mkfs and luksClose failures surface a left-open mapping", func(t *testing.T) {
		dir := t.TempDir()
		img := filepath.Join(dir, "c.img")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				// simulate a real container file being created
				return os.WriteFile(img, []byte("container"), 0644)
			}
			if name == "mkfs.ext4" {
				return errors.New("mkfs failed")
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", "", 512)
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

	t.Run("luksClose fails", func(t *testing.T) {
		img := filepath.Join(t.TempDir(), "c.img")
		run := func(name string, args ...string) error {
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				// simulate a real container file being created
				return os.WriteFile(img, []byte("container"), 0644)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", "", 512)
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
				// simulate a real container file being created
				return os.WriteFile(img, []byte("container"), 0644)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "urandom") {
				// simulate the generated key file
				return os.WriteFile(kf, []byte("keydata"), 0644)
			}
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}
		err := createContainer(run, run, img, "256M", "", kf, 512)
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
				return os.WriteFile(kf, []byte("keydata"), 0644)
			}
			if name == "dd" && len(args) > 0 && strings.Contains(args[0], "zero") {
				return os.WriteFile(img, []byte("container"), 0644)
			}
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

		err := expandContainer(run, run, f, "256M", "")
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

	t.Run("final luksClose failure reports a left-open mapping", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		run := func(name string, args ...string) error {
			if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
				return errors.New("close failed")
			}
			return nil
		}

		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if shrinkCalls != 0 {
			t.Errorf("expected no rollback shrink on success, got %d", shrinkCalls)
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
		err := expandContainer(run, run, f, "256M", kf)

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

	t.Run("file does not exist", func(t *testing.T) {
		run := func(name string, args ...string) error { return nil }
		err := expandContainer(run, run, "/nonexistent/file", "256M", "")
		if err == nil || !strings.Contains(err.Error(), "stat") {
			t.Errorf("expected stat error, got %v", err)
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
		err := expandContainer(run, run, f, "256M", filepath.Join(dir, "nokey"))
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected a 'does not exist' key file error, got %v", err)
		}
		if len(truncateArgs) != 0 {
			t.Errorf("container should not be grown when the key file is missing, truncate: %v", truncateArgs)
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		dir := t.TempDir()
		f := writeLUKSFake(t, dir, "test.img")

		run := func(name string, args ...string) error { return nil }
		err := expandContainer(run, run, f, "invalid", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err := expandContainer(run, run, f, "256M", "")
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
		err = expandContainer(run, run, f, "256M", "")
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

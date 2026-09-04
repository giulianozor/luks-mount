package main

import (
	"fmt"
	"io"
	"os"
)

func createContainer(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int) error {
	total, err := parseSize(size)
	if err != nil {
		return err
	}

	const minSize = int64(32 * 1024 * 1024)
	if total < minSize {
		return fmt.Errorf("minimum container size is 32M, got %s", size)
	}

	if _, err := os.Stat(name); err == nil {
		return fmt.Errorf("container %q already exists", name)
	}

	if keyFile != "" {
		if _, err := os.Stat(keyFile); err == nil {
			return fmt.Errorf("key file %q already exists", keyFile)
		}
		if keySize <= 0 {
			return fmt.Errorf("key file size must be positive, got %d", keySize)
		}
	}

	if existingKeyFile != "" {
		if _, err := os.Stat(existingKeyFile); err != nil {
			return fmt.Errorf("existing key file %q does not exist", existingKeyFile)
		}
	}

	effectiveKeyFile := existingKeyFile
	if existingKeyFile == "" {
		effectiveKeyFile = keyFile
	}

	generatedKey := false
	mappedOpen := false
	success := false
	defer func() {
		if success {
			return
		}
		if generatedKey {
			if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: removing key file %s after failure: %v\n", keyFile, err)
			}
		}
		if mappedOpen {
			// A LUKS mapping is still active (luksOpen succeeded but luksClose
			// failed). Do not delete the backing file underneath it.
			fmt.Fprintf(os.Stderr, "Warning: LUKS mapping %s is still open; leaving container %s in place\n", srcName(name), name)
			return
		}
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: removing container %s after failure: %v\n", name, err)
		}
	}()

	if keyFile != "" {
		fmt.Printf("Creating key file %s...\n", keyFile)
		generatedKey = true
		if err := runDirect("dd", "if=/dev/urandom", "of="+keyFile, fmt.Sprintf("bs=%d", keySize), "count=1"); err != nil {
			return fmt.Errorf("creating key file: %w", err)
		}
	}

	fmt.Printf("Creating container %s...\n", name)
	if err := writeZeros(runDirect, name, total); err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	fmt.Printf("Formatting LUKS container %s...\n", name)
	if err := runDirect("cryptsetup", "luksFormat", "--batch-mode", name); err != nil {
		return fmt.Errorf("luksFormat failed: %w", err)
	}

	if effectiveKeyFile != "" {
		fmt.Printf("Adding key file %s to LUKS container...\n", effectiveKeyFile)
		if err := runDirect("cryptsetup", "luksAddKey", name, effectiveKeyFile); err != nil {
			return fmt.Errorf("luksAddKey failed: %w", err)
		}
	}

	containerName := srcName(name)
	fmt.Printf("Opening LUKS container %s...\n", name)
	luksArgs := []string{"luksOpen"}
	if effectiveKeyFile != "" {
		luksArgs = append(luksArgs, "--key-file", effectiveKeyFile)
	}
	luksArgs = append(luksArgs, name, containerName)
	if err := runSudo("cryptsetup", luksArgs...); err != nil {
		return fmt.Errorf("luksOpen failed: %w", err)
	}
	mappedOpen = true

	devMapper := "/dev/mapper/" + containerName
	fmt.Printf("Creating ext4 filesystem on %s...\n", devMapper)
	if err := runSudo("mkfs.ext4", "-m", "0", devMapper); err != nil {
		if closeErr := runSudo("cryptsetup", "luksClose", containerName); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after mkfs failure: %v\n", closeErr)
		} else {
			mappedOpen = false
		}
		return fmt.Errorf("mkfs.ext4 failed: %w", err)
	}

	fmt.Printf("Closing LUKS container %s...\n", containerName)
	if err := runSudo("cryptsetup", "luksClose", containerName); err != nil {
		return fmt.Errorf("luksClose failed: %w", err)
	}
	mappedOpen = false

	fmt.Println("Done.")
	success = true
	return nil
}

const luksMagic = "LUKS\xba\xbe"

func isLuksContainer(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(luksMagic))
	if _, err := io.ReadFull(f, buf); err != nil {
		return false
	}
	return string(buf) == luksMagic
}

// writeZeros writes exactly `total` zero bytes to a new output file `of`. It
// uses a large block size for the bulk of the data and extends the file by the
// remainder with `truncate` when the requested size is not a whole multiple of
// the block size, so the resulting file is never larger than requested.
func writeZeros(run func(name string, args ...string) error, of string, total int64) error {
	blockSize := calcBlockSize(total)
	count := total / blockSize

	args := []string{"if=/dev/zero", "of=" + of, fmt.Sprintf("bs=%dM", blockSize/_1M), fmt.Sprintf("count=%d", count), "status=progress"}
	if err := run("dd", args...); err != nil {
		return err
	}

	if rem := total % blockSize; rem > 0 {
		if err := run("truncate", "-s", fmt.Sprintf("+%d", rem), of); err != nil {
			return err
		}
	}
	return nil
}

func expandContainer(runSudo, runDirect func(name string, args ...string) error, filename, size, keyFile string) error {
	total, err := parseSize(size)
	if err != nil {
		return err
	}

	fi, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filename, err)
	}
	oldSize := fi.Size()

	if !isLuksContainer(filename) {
		return fmt.Errorf("not a LUKS container: %s", filename)
	}

	if err := runDirect("truncate", "-s", fmt.Sprintf("+%d", total), filename); err != nil {
		return fmt.Errorf("expanding container: %w", err)
	}

	// If a subsequent step fails before the filesystem is resized, shrink the
	// backing file back to its original size. Without this a failed expand
	// leaves the file permanently grown, and rerunning the same command would
	// grow it again (non-idempotent). Once resize2fs runs the filesystem may
	// be partially grown, so it must NOT be rolled back after that point.
	resized := false
	rollback := func() {
		if resized {
			return
		}
		if rollbackErr := runDirect("truncate", "-s", fmt.Sprintf("%d", oldSize), filename); rollbackErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: restoring container size after failure: %v\n", rollbackErr)
		}
	}

	name := srcName(filename)
	luksArgs := []string{"luksOpen"}
	if keyFile != "" {
		luksArgs = append(luksArgs, "--key-file", keyFile)
	}
	luksArgs = append(luksArgs, filename, name)
	fmt.Printf("Opening LUKS container %s...\n", filename)
	if err := runSudo("cryptsetup", luksArgs...); err != nil {
		rollback()
		return fmt.Errorf("luksOpen failed: %w", err)
	}

	devMapper := "/dev/mapper/" + name

	fmt.Printf("Checking filesystem %s...\n", devMapper)
	if err := runSudo("fsck.ext4", "-f", "-y", devMapper); err != nil {
		rollback()
		if closeErr := runSudo("cryptsetup", "luksClose", name); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after fsck (pre) failure: %v\n", closeErr)
		}
		return fmt.Errorf("fsck.ext4 (pre) failed: %w", err)
	}

	fmt.Printf("Resizing filesystem %s...\n", devMapper)
	resized = true
	if err := runSudo("resize2fs", devMapper); err != nil {
		if closeErr := runSudo("cryptsetup", "luksClose", name); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after resize2fs failure: %v\n", closeErr)
		}
		return fmt.Errorf("resize2fs failed: %w", err)
	}

	fmt.Printf("Checking filesystem %s...\n", devMapper)
	if err := runSudo("fsck.ext4", "-f", "-y", devMapper); err != nil {
		if closeErr := runSudo("cryptsetup", "luksClose", name); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after fsck (post) failure: %v\n", closeErr)
		}
		return fmt.Errorf("fsck.ext4 (post) failed: %w", err)
	}

	fmt.Printf("Closing LUKS container %s...\n", name)
	if err := runSudo("cryptsetup", "luksClose", name); err != nil {
		return fmt.Errorf("luksClose failed: %w", err)
	}

	newFi, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat %s after expand: %w", filename, err)
	}
	fmt.Printf("Old size: %d, New size: %d\n", oldSize, newFi.Size())
	return nil
}

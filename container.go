package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// checkParentDir verifies that the directory holding path exists and is
// actually a directory, so a later write (e.g. dd) fails with a clear message
// instead of a cryptic "No such file or directory".
func checkParentDir(path, what string) error {
	if parent := filepath.Dir(path); parent != "" {
		if fi, err := os.Stat(parent); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%s directory %s does not exist", what, parent)
			}
			return fmt.Errorf("checking %s directory %s: %w", what, parent, err)
		} else if !fi.IsDir() {
			return fmt.Errorf("%s parent %s is not a directory", what, parent)
		}
	}
	return nil
}

func createContainer(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int) error {
	total, err := parseSize(size)
	if err != nil {
		return err
	}

	// main() already rejects the combination, but enforce it here too so a
	// direct caller cannot silently prefer one key over the other.
	if keyFile != "" && existingKeyFile != "" {
		return fmt.Errorf("key file path and existing key file cannot both be set")
	}

	const minSize = int64(32 * 1024 * 1024)
	if total < minSize {
		return fmt.Errorf("minimum container size is 32M, got %s", size)
	}

	// The container's basename becomes its /dev/mapper mapping name; reject
	// names cryptsetup could not open as a mapping before creating any files.
	if err := checkMapperName(srcName(name)); err != nil {
		return fmt.Errorf("container %s: %w", name, err)
	}

	// A generated key file and the container are separate objects; if they are
	// the same file, writing the key overwrites the file that then becomes the
	// container (and vice versa), silently corrupting the key. Compare them as
	// absolute paths so equivalent spellings (e.g. "./a.img" and "a.img", or a
	// relative key against an absolute container path) collide too.
	if keyFile != "" && name != "" && sameFilePath(keyFile, name) {
		return fmt.Errorf("key file path and container path must be different, both are %q", filepath.Clean(name))
	}

	// The container is written with dd, which cannot create missing parent
	// directories; failing here with a clear message beats a cryptic dd error
	// after a generated key file has already been created.
	if _, err := os.Stat(name); err == nil {
		return fmt.Errorf("container %q already exists", name)
	} else if !os.IsNotExist(err) {
		// A permission error (or similar) probing the path means we cannot
		// know whether a container is already there. Continuing would risk
		// overwriting a container we could not even stat.
		return fmt.Errorf("checking container path %s: %w", name, err)
	}

	if err := checkParentDir(name, "container"); err != nil {
		return err
	}

	if keyFile != "" {
		if fi, err := os.Stat(keyFile); err == nil {
			if fi.IsDir() {
				// A directory path can never become a key file; say so rather
				// than the misleading "already exists".
				return fmt.Errorf("key file %q is a directory", keyFile)
			}
			return fmt.Errorf("key file %q already exists", keyFile)
		}
		if keySize <= 0 {
			return fmt.Errorf("key file size must be positive, got %d", keySize)
		}
		// The generated key file is also written with dd and needs its parent
		// directory present.
		if err := checkParentDir(keyFile, "key file"); err != nil {
			return err
		}
	}

	if existingKeyFile != "" {
		if err := checkKeyFile(existingKeyFile, "existing key file"); err != nil {
			return err
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
		if mappedOpen {
			// A LUKS mapping is still active (luksOpen succeeded but luksClose
			// failed). Do not delete the backing file underneath it. The
			// generated key file may be the container's only key, so keep it
			// too, or the kept container would be permanently unopenable.
			fmt.Fprintf(os.Stderr, "Warning: LUKS mapping %s is still open; leaving container %s in place\n", srcName(name), name)
			return
		}
		if generatedKey {
			if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: removing key file %s after failure: %v\n", keyFile, err)
			}
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
		// dd creates the file with the default umask (typically world-readable);
		// this is a decryption key, so restrict it to the owner.
		if err := os.Chmod(keyFile, 0600); err != nil {
			return fmt.Errorf("setting key file permissions: %w", err)
		}
	}

	fmt.Printf("Creating container %s...\n", name)
	if err := writeZeros(runDirect, name, total); err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	fmt.Printf("Formatting LUKS container %s...\n", name)
	formatArgs := []string{"luksFormat", "--batch-mode"}
	if effectiveKeyFile != "" {
		// Install the key file as the container's initial key so no interactive
		// passphrase is needed and the generated/existing key is a valid user key.
		formatArgs = append(formatArgs, "--key-file", effectiveKeyFile)
	}
	formatArgs = append(formatArgs, name)
	if err := runDirect("cryptsetup", formatArgs...); err != nil {
		return fmt.Errorf("luksFormat failed: %w", err)
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
			// The mapping stays open, so the container and any generated key
			// file are deliberately kept. Say so, or the user may assume the
			// failed create was fully rolled back.
			return fmt.Errorf("mkfs.ext4 failed: %w (mapping left open: %v)", err, closeErr)
		}
		mappedOpen = false
		return fmt.Errorf("mkfs.ext4 failed: %w", err)
	}

	fmt.Printf("Closing LUKS container %s...\n", containerName)
	if err := runSudo("cryptsetup", "luksClose", containerName); err != nil {
		return fmt.Errorf("luksClose failed: %w (container %s was created and left mapped open)", err, name)
	}
	mappedOpen = false

	// Report the exact size written (mirroring expand's Old/New size line).
	// If the file cannot be stat'd the container was just created above, so it
	// is not worth failing the whole create over a diagnostics-only stat.
	if fi, err := os.Stat(name); err == nil {
		fmt.Printf("Created container %s (%d bytes).\n", name, fi.Size())
	}

	fmt.Println("Done.")
	success = true
	return nil
}

const luksMagic = "LUKS\xba\xbe"

// sniffLuks reports whether path begins with the LUKS magic and whether the
// header could be read at all. A successful read showing no magic proves the
// source is not LUKS without needing a privileged cryptsetup probe; a source
// that cannot be read (e.g. a device node without read permission) must be
// probed via cryptsetup instead.
func sniffLuks(path string) (luks bool, readable bool) {
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()
	buf := make([]byte, len(luksMagic))
	if _, err := io.ReadFull(f, buf); err != nil {
		// A short/empty source cannot be LUKS.
		return false, true
	}
	return string(buf) == luksMagic, true
}

func isLuksContainer(path string) bool {
	luks, read := sniffLuks(path)
	return read && luks
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

	// A trailing separator on the container name (e.g. "dir/img/" from a shell
	// completion) would make os.Stat/open treat the file as a directory; match
	// the normalization openAndMount/umountAndClose apply to their sources.
	filename = trimTrailingSeparators(filename)

	// The root filesystem is never a container; say so rather than the generic
	// "not a regular file" a stat of "/" would produce.
	if filepath.Clean(filename) == "/" {
		return fmt.Errorf("cannot expand the filesystem root")
	}

	fi, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filename, err)
	}
	oldSize := fi.Size()

	if !fi.Mode().IsRegular() {
		// isLuksContainer opens the file for reading; a FIFO at this path would
		// block that open forever, and truncate cannot extend a directory or
		// socket. Reject non-regular entries before any probing or growing.
		return fmt.Errorf("not a regular file: %s", filename)
	}

	if !isLuksContainer(filename) {
		return fmt.Errorf("not a LUKS container: %s", filename)
	}

	// The container's basename becomes its /dev/mapper mapping name here just
	// as it did at create time; reject a name cryptsetup could not open before
	// the backing file has been grown.
	if err := checkMapperName(srcName(filename)); err != nil {
		return fmt.Errorf("container %s: %w", filename, err)
	}

	// Growing (truncate) the backing file while its LUKS mapping is still
	// open and mounted would extend the file underneath a live filesystem and
	// can leave device-mapper in an inconsistent state even if the size is
	// later rolled back. Refuse up front, mirroring openAndMount's guard.
	if mapperProbe(srcName(filename)) {
		return fmt.Errorf("container %s is mounted as /dev/mapper/%s; unmount it before expanding", filename, srcName(filename))
	}

	// The key file and the container are separate objects; passing the
	// container itself as the key would make cryptsetup read a LUKS header as
	// a key and fail cryptically. Compare canonical paths so a relative or
	// symlinked spelling of the same file is caught too.
	if keyFile != "" && sameFilePath(keyFile, filename) {
		return fmt.Errorf("key file path and container path must be different, both are %q", filepath.Clean(filename))
	}

	if keyFile != "" {
		if err := checkKeyFile(keyFile, "key file"); err != nil {
			return err
		}
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
	rollback := func() error {
		if resized {
			return nil
		}
		return runDirect("truncate", "-s", fmt.Sprintf("%d", oldSize), filename)
	}

	name := srcName(filename)
	luksArgs := []string{"luksOpen"}
	if keyFile != "" {
		luksArgs = append(luksArgs, "--key-file", keyFile)
	}
	luksArgs = append(luksArgs, filename, name)
	fmt.Printf("Opening LUKS container %s...\n", filename)
	if err := runSudo("cryptsetup", luksArgs...); err != nil {
		if rbErr := rollback(); rbErr != nil {
			return fmt.Errorf("luksOpen failed: %w (container size not restored: %v)", err, rbErr)
		}
		return fmt.Errorf("luksOpen failed: %w", err)
	}

	devMapper := "/dev/mapper/" + name

	fmt.Printf("Checking filesystem %s...\n", devMapper)
	if err := runSudo("fsck.ext4", "-f", "-y", devMapper); err != nil {
		// Detach the mapping before shrinking the backing file, so we never
		// truncate a file that a live /dev/mapper/NAME still references. If the
		// mapping cannot be closed, leave the grown file in place rather than
		// resizing it under an open mapping.
		if closeErr := runSudo("cryptsetup", "luksClose", name); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after fsck (pre) failure: %v\n", closeErr)
			return fmt.Errorf("fsck.ext4 (pre) failed: %w (mapping left open; container not shrunk)", err)
		}
		if rbErr := rollback(); rbErr != nil {
			return fmt.Errorf("fsck.ext4 (pre) failed: %w (container size not restored: %v)", err, rbErr)
		}
		return fmt.Errorf("fsck.ext4 (pre) failed: %w", err)
	}

	fmt.Printf("Resizing filesystem %s...\n", devMapper)
	resized = true
	if err := runSudo("resize2fs", devMapper); err != nil {
		if closeErr := runSudo("cryptsetup", "luksClose", name); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after resize2fs failure: %v (mapping left open)\n", closeErr)
			return fmt.Errorf("resize2fs failed: %w (mapping left open)", err)
		}
		return fmt.Errorf("resize2fs failed: %w (container left grown; filesystem not resized)", err)
	}

	fmt.Printf("Checking filesystem %s...\n", devMapper)
	if err := runSudo("fsck.ext4", "-f", "-y", devMapper); err != nil {
		if closeErr := runSudo("cryptsetup", "luksClose", name); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: luksClose after fsck (post) failure: %v (mapping left open)\n", closeErr)
			return fmt.Errorf("fsck.ext4 (post) failed: %w (mapping left open)", err)
		}
		return fmt.Errorf("fsck.ext4 (post) failed: %w", err)
	}

	fmt.Printf("Closing LUKS container %s...\n", name)
	if err := runSudo("cryptsetup", "luksClose", name); err != nil {
		return fmt.Errorf("luksClose failed: %w (mapping left open)", err)
	}

	newFi, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("stat %s after expand: %w", filename, err)
	}
	fmt.Printf("Old size: %d, New size: %d\n", oldSize, newFi.Size())
	return nil
}

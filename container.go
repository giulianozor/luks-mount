package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// chmod is a seam for tests to force a key-file permission failure; replacing
// it in a test must restore the original (see the sharing note on userHomeDir).
var chmod = os.Chmod

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

func createContainer(runSudo, runDirect func(name string, args ...string) error, name, size, existingKeyFile, keyFile string, keySize int, noPassphrase bool) error {
	total, err := parseSize(size)
	if err != nil {
		return err
	}

	if noPassphrase && existingKeyFile == "" && keyFile == "" {
		return fmt.Errorf("-no-passphrase requires a key file (-ck or -k)")
	}

	// Normalize trailing separators on both key paths so a shell-completed
	// "…/key/" is not read as a directory and rejected with a misleading
	// "not a directory" error; the container name is normalized by main.
	existingKeyFile = trimTrailingSeparators(existingKeyFile)
	keyFile = trimTrailingSeparators(keyFile)

	// main() already rejects the combination, but enforce it here too so a
	// direct caller cannot silently prefer one key over the other.
	if keyFile != "" && existingKeyFile != "" {
		return fmt.Errorf("key file path and existing key file cannot both be set")
	}

	// An empty name would pass checkMapperName below ("" is allowed for the
	// unmount-only empty-source flow) and then have dd/luksFormat write to an
	// empty target path. Reject it up front with a clear error.
	if name == "" {
		return fmt.Errorf("container name must not be empty")
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

	// Reject a container whose future mapping is already open before dd
	// allocates potentially gigabytes of zeros, mirroring expandContainer's
	// refusal. Without this the failure surfaces only as a cryptic cryptsetup
	// luksOpen "already exists" after a full allocation.
	if mapperProbe(srcName(name)) {
		return fmt.Errorf("container %s would open as /dev/mapper/%s, which is already in use", name, srcName(name))
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
		if keySize <= 0 || keySize%8 != 0 || keySize > maxLUKSKeyBytes {
			// cryptsetup reads at most maxLUKSKeyBytes bytes of a key file and
			// silently truncates longer ones, so a generated key that large
			// could never unlock its own container; a zero, negative, or
			// non-octet-multiple key would never match any keyslot either.
			// Reject the value up front while the failure is cheap. runMain
			// validates -cks separately; this mirrors that check for direct
			// callers of createContainer.
			return fmt.Errorf("key file size must be a positive multiple of 8 (and at most %d bytes), got %d", maxLUKSKeyBytes, keySize)
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
	containerCreated := false
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
		// Only files this invocation actually created are rolled back. The
		// container and generated key are created with O_EXCL: when that open
		// fails, the path already existed (a racing create after the up-front
		// check), so removing it here would delete a file this run never wrote.
		if generatedKey {
			if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: removing key file %s after failure: %v\n", keyFile, err)
			}
		}
		if containerCreated {
			if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: removing container %s after failure: %v\n", name, err)
			}
		}
	}()

	if keyFile != "" {
		fmt.Printf("Creating key file %s...\n", keyFile)
		// Claim the path with O_EXCL first so the "this path was empty" fact is
		// atomic: if the open fails with EEXIST a racing create has won, and the
		// deferred cleanup must not (and, because generatedKey stays false, does
		// not) remove a file it never wrote. dd then fills the file in.
		f, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("creating key file: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("creating key file: %w", err)
		}
		generatedKey = true
		if err := runDirect("dd", "if=/dev/urandom", "of="+keyFile, fmt.Sprintf("bs=%d", keySize), "count=1"); err != nil {
			return fmt.Errorf("creating key file: %w", err)
		}
		// dd masks real device failures (e.g. a full disk) with a partial file
		// and a successful exit status, which would silently create a container
		// that trusts a key never actually stored at the key file. Verify the
		// size landed before including it in the LUKS header.
		fi, err := os.Stat(keyFile)
		if err != nil {
			return fmt.Errorf("key file %s missing after dd: %w", keyFile, err)
		}
		if fi.Size() != int64(keySize) {
			return fmt.Errorf("key file %s has %d bytes, want %d", keyFile, fi.Size(), keySize)
		}
		// dd creates the file with the default umask (typically world-readable);
		// this is a decryption key, so restrict it to the owner.
		if err := chmod(keyFile, 0600); err != nil {
			return fmt.Errorf("setting key file permissions: %w", err)
		}
	}

	fmt.Printf("Creating container %s...\n", name)
	// Record the writeZeros claim result up front: writeZeros returns
	// (created=true, err) when dd or truncate fails partway after the O_EXCL
	// open succeeded, so the container path was claimed by this run and must be
	// rolled back here rather than after the error check (which would return
	// with containerCreated still false and leak a partial container file).
	containerCreated, err = writeZeros(runDirect, name, total)
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}
	// dd masks real device failures (e.g. a full disk) with a partial file and
	// a successful exit status, so a short container can reach luksFormat and
	// report success at a size smaller than requested. Verify the size landed
	// before formatting, exactly as the generated key file is verified above;
	// on a mismatch the containerCreated flag rolls the file back.
	if fi, statErr := os.Stat(name); statErr != nil {
		return fmt.Errorf("container %s missing after write: %w", name, statErr)
	} else if fi.Size() != total {
		return fmt.Errorf("container %s has %d bytes, want %d", name, fi.Size(), total)
	}

	fmt.Printf("Formatting LUKS container %s...\n", name)
	formatArgs := []string{"luksFormat", "--batch-mode"}
	if noPassphrase {
		// Key-file-only create: no passphrase is ever asked. The (required)
		// key file becomes the container's initial keyslot.
		formatArgs = append(formatArgs, "--key-file", effectiveKeyFile)
	}
	formatArgs = append(formatArgs, name)
	if err := runDirect("cryptsetup", formatArgs...); err != nil {
		return fmt.Errorf("luksFormat failed: %w", err)
	}

	if effectiveKeyFile != "" && !noPassphrase {
		// A passphrase create sets the initial passphrase keyslot during
		// luksFormat, then adds the (optional) key file as an additional
		// keyslot. luksAddKey still asks for the container passphrase to
		// authorize the addition, so the create remains passphrase-gated.
		fmt.Printf("Adding key file %s to container %s...\n", effectiveKeyFile, name)
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
	// luksOpen is kernel-synchronous, but udev may still be creating the
	// /dev/mapper node when mkfs runs; wait briefly so a slow system does not
	// turn a settled mapping into a spurious ENOENT (mirroring openAndMount).
	if !waitForDevice(devMapper) {
		fmt.Fprintf(os.Stderr, "Warning: device %s not found after luksOpen (udev may still be settling); continuing.\n", devMapper)
	}
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
	if effectiveKeyFile != "" {
		// Name the key that can unlock the fresh container so its location is
		// on record while the create output is still on screen. For a
		// key-file-only create the key is the container's ONLY unlock secret,
		// so make it unmistakable that there is no passphrase to fall back on.
		fmt.Printf("Container %s unlocks with key file %s", name, effectiveKeyFile)
		if noPassphrase {
			fmt.Printf(" (key-file only; no passphrase was set)")
		}
		fmt.Println()
	}

	fmt.Println("Done.")
	success = true
	return nil
}

const luksMagic = "LUKS\xba\xbe"

// maxLUKSKeyBytes is cryptsetup's documented key-file read limit: only the
// first 8192 bytes of a key file participate in a keyslot operation, and a
// longer key file is silently truncated at unlock time. Generating a key file
// past this limit would create a container that trusts bytes cryptsetup will
// never read back, so -cks/--key-size is capped here in main.
const maxLUKSKeyBytes = 8192

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

// isLuksContainer reports whether path is a LUKS container (starts with the
// LUKS magic readable from its header). It only probes entries whose type is
// safe to open for reading: a regular file (a container image) or a device
// node (a LUKS-formatted partition). Opening a FIFO or socket for reading
// would block forever waiting for a writer, so those, directories, and other
// special entries are rejected by type before the open is ever attempted.
func isLuksContainer(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || (!fi.Mode().IsRegular() && fi.Mode()&os.ModeDevice == 0) {
		return false
	}
	luks, read := sniffLuks(path)
	return read && luks
}

// luksForSource reports whether path is LUKS. The header is read directly
// whenever the path is safe to open (mirroring the mount flow's sniff): a
// readable header is a definitive verdict, so a readable non-LUKS file is
// resolved without a privileged cryptsetup probe. Only a source that cannot be
// read locally (e.g. a block device the invoking user cannot open) is
// re-examined with the privileged probe — reading a file as root yields the
// same verdict a user-space read of the same file already gave, so an
// unnecessary probe would only add a sudo invocation for the common plain-file
// unmount while never preventing a differently-named mapping from being found.
// A FIFO, socket, directory, or character device is never opened for reading
// (which could block) and is reported as non-LUKS without a probe.
func luksForSource(runOutput func(name string, args ...string) ([]byte, error), path string) bool {
	fi, err := os.Stat(path)
	if err != nil || (!fi.Mode().IsRegular() && fi.Mode()&os.ModeDevice == 0) {
		return false
	}
	luks, readable := sniffLuks(path)
	if luks {
		return true
	}
	if readable {
		return false
	}
	// probeIsLuks exits 1 for a genuine non-LUKS verdict and returns an error
	// only when no verdict could be produced; a failed probe is treated as
	// "not LUKS" here so this helper never _creates_ an open mapping, it only
	// avoids missing one.
	want, perr := probeIsLuks(runOutput, path)
	if perr != nil {
		return false
	}
	return want
}

// writeZeros writes exactly `total` zero bytes to `of`, owning the path from
// the start: the O_EXCL open is the atomic existence check, so a file the
// caller's later failure cleanup must not touch gets reported as not created.
// It uses a large block size for the bulk of the data and extends the file by
// the remainder with `truncate` when the requested size is not a whole multiple
// of the block size, so the resulting file is never larger than requested. The
// returned created flag reports whether this call claimed the file, and dd is
// told nothing about the open: exclusivity is already held, so a plain write is
// all that remains.
func writeZeros(run func(name string, args ...string) error, of string, total int64) (bool, error) {
	f, err := os.OpenFile(of, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}

	blockSize := calcBlockSize(total)
	count := total / blockSize

	args := []string{"if=/dev/zero", "of=" + of, fmt.Sprintf("bs=%dM", blockSize/_1M), fmt.Sprintf("count=%d", count), "status=progress"}
	if err := run("dd", args...); err != nil {
		return true, err
	}

	if rem := total % blockSize; rem > 0 {
		if err := run("truncate", "-s", fmt.Sprintf("+%d", rem), of); err != nil {
			return true, err
		}
	}
	return true, nil
}

func expandContainer(runSudo, runDirect func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), filename, size, keyFile string) error {
	total, err := parseSize(size)
	if err != nil {
		return err
	}

	// A trailing separator on the container name (e.g. "dir/img/" from a shell
	// completion) would make os.Stat/open treat the file as a directory; match
	// the normalization openAndMount/umountAndClose apply to their sources.
	filename = trimTrailingSeparators(filename)
	// Normalize a trailing separator on an existing key file the same way path
	// arguments are normalized elsewhere; os.Stat would otherwise read it as a
	// directory and reject a valid key with a misleading "not a directory".
	keyFile = trimTrailingSeparators(keyFile)

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

	// The key file and the container are separate objects; passing the
	// container itself as the key would make cryptsetup read a LUKS header as
	// a key and fail cryptically. Compare canonical paths so a relative or
	// symlinked spelling of the same file is caught too, and compare inodes so
	// an equal hardlink is caught as well (two paths can EvalSymlinks to
	// different strings yet be the same file). Check this before the LUKS sniff
	// and the mapping probe so a colliding key never opens the container or
	// touches /dev/mapper unnecessarily.
	if keyFile != "" && sameFilePath(keyFile, filename) {
		return fmt.Errorf("key file path and container path must be different, both are %q", filepath.Clean(filename))
	}
	if keyFile != "" {
		if kStat, kErr := os.Stat(keyFile); kErr == nil && os.SameFile(kStat, fi) {
			return fmt.Errorf("key file and container are the same file: %q", filepath.Clean(filename))
		}
	}

	if keyFile != "" {
		if err := checkKeyFile(keyFile, "key file"); err != nil {
			return err
		}
	}

	// Deciding LUKS by reading the header locally mirrors the other flows; a
	// container the invoking user may write but not read (e.g. one owned by
	// another user) would otherwise be refused with a misleading "not a LUKS
	// container" even though runOutput's privileged probe can read it. Only
	// re-check with the probe when the header could not be read at all, so a
	// readable non-LUKS file is never handed to cryptsetup.
	luks, readable := sniffLuks(filename)
	if !luks && !readable {
		var probeErr error
		luks, probeErr = probeIsLuks(runOutput, filename)
		if probeErr != nil {
			return fmt.Errorf("cannot determine whether %s is a LUKS container: %w", filename, probeErr)
		}
	}
	if !luks {
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
	// The probe catches any open mapping, mounted or not.
	if mapperProbe(srcName(filename)) {
		return fmt.Errorf("container %s is open as /dev/mapper/%s; unmount and close it before expanding", filename, srcName(filename))
	}

	// A container opened under a differently-named mapping (e.g. cryptsetup
	// luksOpen vol.img myvol) or whose backing file moved after being opened is
	// not caught by the basename probe above. Match every open mapping's
	// backing device against the container's LUKS UUID the same way
	// umountAndClose does, and refuse to grow a file still in use.
	if byUUID := mappingForSource(runOutput, filename); byUUID != "" {
		return fmt.Errorf("container %s is open as /dev/mapper/%s; unmount and close it before expanding", filename, byUUID)
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
		// No error path below calls rollback() after resize2fs succeeds, so
		// this guard is currently unreachable; it exists as a structural
		// safety net so a future path can never shrink a partially-grown
		// filesystem.
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

	// luksOpen is kernel-synchronous, but udev may still be creating the
	// /dev/mapper node when the first fsck runs; wait briefly so a slow system
	// does not turn a settled mapping into a spurious ENOENT (mirroring
	// openAndMount's wait).
	if !waitForDevice(devMapper) {
		fmt.Fprintf(os.Stderr, "Warning: device %s not found after luksOpen (udev may still be settling); continuing.\n", devMapper)
	}

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
		return fmt.Errorf("fsck.ext4 (pre) failed: %w (the container is restored to its original size; if fsck reported 'errors corrected' with exit status 1, rerun the expand and it will proceed)", err)
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
		// resize2fs already succeeded by this point, so the backing file is
		// kept grown and the filesystem resized; say so rather than implying
		// the expand was rolled back.
		return fmt.Errorf("fsck.ext4 (post) failed: %w (container left grown; filesystem resized)", err)
	}

	fmt.Printf("Closing LUKS container %s...\n", name)
	if err := runSudo("cryptsetup", "luksClose", name); err != nil {
		return fmt.Errorf("luksClose failed: %w (mapping left open)", err)
	}

	newFi, err := os.Stat(filename)
	if err == nil {
		fmt.Printf("Old size: %d, New size: %d\n", oldSize, newFi.Size())
	} else {
		// The resize itself succeeded; this stat only sizes the report line.
		// Failing the whole expand over diagnostics would misreport a
		// successful operation (mirroring createContainer's tolerant report).
		fmt.Fprintf(os.Stderr, "Warning: stat %s after expand: %v\n", filename, err)
	}

	// End with the same "Done." every other successful operation prints
	// (createContainer, openAndMount, umountAndClose).
	fmt.Println("Done.")
	return nil
}

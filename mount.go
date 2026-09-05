package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

var userHomeDir = os.UserHomeDir

// currentUser is the user lookup used for the mount-point chown; a variable so
// tests can simulate a lookup failure (e.g. a binary built from a source tree
// with no passwd entry available).
var currentUser = user.Current

// mapperProbe reports whether a /dev/mapper/NAME mapping already exists; a
// variable so tests can simulate an open mapping without touching /dev/mapper.
// It shares the same stat-based probe umountAndClose uses (checkMapped).
var mapperProbe = checkMapped

// checkSourceMode rejects a source entry that can never back a mount: a
// directory, a FIFO/socket or other special non-device entry (which would also
// block the LUKS sniff open forever), or an empty regular file. It is applied
// uniformly including under /dev, where a FIFO would otherwise hang the probe.
func checkSourceMode(fi os.FileInfo, source string) error {
	if fi.IsDir() {
		// A directory can never be a mount source (lmount does no bind
		// mounts); rejecting it up front is clearer than mount's own failure.
		return fmt.Errorf("source %s is a directory, not a device or file", source)
	}
	if !fi.Mode().IsRegular() && fi.Mode()&os.ModeDevice == 0 {
		// A FIFO, socket, or other special file can never be a mount source
		// and may even block sniffing it (opening a FIFO for reading blocks
		// until a writer appears). Reject it up front rather than hanging or
		// failing cryptically later.
		return fmt.Errorf("source %s is not a regular file", source)
	}
	if fi.Mode().IsRegular() && fi.Size() == 0 {
		// An empty file carries no filesystem for a loop mount to attach;
		// mount's error on a zero-length image is cryptic.
		return fmt.Errorf("source %s is an empty file and cannot be mounted", source)
	}
	return nil
}

func openAndMount(runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source, keyFile, mountPoint string) error {
	isLuks := func(source string) bool {
		_, err := runOutput("cryptsetup", "isLuks", source)
		return err == nil
	}
	luksClose := func(name string) error {
		return runCmd("cryptsetup", "luksClose", name)
	}

	// A trailing separator on the source (e.g. "dir/img/" from a shell
	// completion) would make os.Stat/open it as a directory and fail with a
	// cryptic not-a-directory error; normalize it up front. A root path is
	// preserved and rejected later as a directory.
	source = trimTrailingSeparators(source)
	name := srcName(source)

	// A source spelled with a leading dash ("-evil.img") would be parsed as an
	// option by mount (and by cryptsetup luksOpen for a LUKS header), failing
	// with a cryptic error instead of mounting the file. No legitimate path
	// starts with a dash (absolute "./", relative, and /dev paths start with
	// "/", "." or ".."), so reject it up front with a hint.
	if strings.HasPrefix(source, "-") {
		return fmt.Errorf("source %q starts with a dash and would be parsed as an option; use ./%s", source, source)
	}

	// Normalize a trailing separator on an existing key file the same way.
	// Without this, os.Stat treats "…/key/" as a directory and checkKeyFile
	// rejects a valid key with a misleading "not a directory" error.
	keyFile = trimTrailingSeparators(keyFile)

	// Validate the source exists before probing LUKS: isLuks on a missing path
	// reports "not LUKS", which would otherwise mask a typo'd source path as a
	// "not LUKS" error, and wastes a privileged cryptsetup probe (and possibly a
	// sudo prompt) on a path that can never be mounted.
	if source == "" {
		return fmt.Errorf("cannot determine name from empty source")
	}
	fi, err := os.Stat(source)
	if err != nil {
		if os.IsNotExist(err) && !strings.HasPrefix(source, "/dev/") {
			if !strings.Contains(source, "/") {
				// A bare name such as "sda1" may still name a /dev/ device.
				// Resolve it here so openAndMount is self-contained (mirroring
				// umountAndClose and main's resolveSource), and only give up
				// when that /dev node is missing too.
				if _, devErr := os.Stat("/dev/" + source); devErr == nil {
					source = "/dev/" + source
					name = srcName(source)
				} else {
					return fmt.Errorf("source %s does not exist", source)
				}
			} else {
				// A non-device source that does not exist is almost certainly a
				// typo. Reject it up front rather than letting cryptsetup/mount
				// fail with a cryptic error, and never leave a LUKS mapping
				// open for nothing.
				return fmt.Errorf("source %s does not exist", source)
			}
		}
		// Other failures (a missing /dev node, or EACCES on a device the
		// invoking user cannot even stat) pass through: the LUKS sniff falls
		// back to the privileged cryptsetup probe and sudo can still act.
	} else if err := checkSourceMode(fi, source); err != nil {
		return err
	}

	// Deciding LUKS by reading the header's magic directly avoids a privileged
	// cryptsetup probe (and a possible sudo prompt) for every plain source we
	// can read ourselves. Only sources that cannot be read locally (e.g. a
	// device node without read permission) fall back to the cryptsetup probe.
	encrypted, sniffable := sniffLuks(source)
	if !sniffable {
		encrypted = isLuks(source)
	}

	if keyFile != "" && !encrypted {
		// A key file only makes sense for a LUKS source. Silently ignoring a
		// wrong/mistyped -k would give no indication to the user.
		return fmt.Errorf("source %s is not LUKS; -k/--key is not valid", source)
	}

	if keyFile != "" && encrypted {
		// Passing the source itself as the key would make cryptsetup read a
		// LUKS header as a key and fail cryptically. Compare canonical paths
		// so a relative or symlinked spelling of the same file is caught too.
		if sameFilePath(keyFile, source) {
			return fmt.Errorf("key file path and source path must be different, both are %q", filepath.Clean(source))
		}
		if err := checkKeyFile(keyFile, "key file"); err != nil {
			// Fail fast with a clear message on a typo'd key, rather than after
			// luksOpen returns a cryptic error (and before any mapping is opened).
			return err
		}
	}

	// failOpen returns err, attaching the luksClose error when the mapping
	// cannot be detached so an open mapping is never silently swallowed (a
	// failed close after a re-mount attempt should be just as visible as it is
	// on the mount-failure path).
	failOpen := func(err error) error {
		if encrypted {
			if closeErr := luksClose(name); closeErr != nil {
				return fmt.Errorf("%w (mapping left open: %v)", err, closeErr)
			}
		}
		return err
	}

	if encrypted {
		// The source basename becomes the /dev/mapper mapping name; an
		// unmappable name would surface only as a cryptic cryptsetup failure
		// after a privileged attempt, so reject it up front.
		if err := checkMapperName(name); err != nil {
			return fmt.Errorf("source %s: %w", source, err)
		}
		if mapperProbe(name) {
			// The mapping is already open; luksOpen would only fail with a
			// cryptic "already exists" after a wasteful privileged attempt.
			return fmt.Errorf("source %s is already open as /dev/mapper/%s", source, name)
		}
		fmt.Printf("Opening LUKS device %s...\n", source)
		args := []string{"luksOpen"}
		if keyFile != "" {
			args = append(args, "--key-file", keyFile)
		}
		args = append(args, source, name)
		if err := runCmd("cryptsetup", args...); err != nil {
			return fmt.Errorf("cryptsetup luksOpen failed: %w", err)
		}
		fmt.Printf("LUKS device %s opened.\n", source)
	}

	if mountPoint == "" {
		if name == "" {
			return failOpen(fmt.Errorf("cannot infer mount point name from empty source"))
		}
		home, err := userHomeDir()
		if err != nil {
			return failOpen(fmt.Errorf("getting home directory: %w", err))
		}
		mountPoint = filepath.Join(home, name)
		// HOME could be empty or relative (e.g. an unset/shortened HOME in a
		// service), which would make this an effectively relative mount point
		// created in an unexpected place. Refuse rather than mount to a path
		// that depends on the caller's working directory.
		absMp, absErr := filepath.Abs(mountPoint)
		if absErr == nil && absMp != mountPoint {
			return failOpen(fmt.Errorf("cannot infer an absolute mount point: HOME is %q", home))
		}
	}

	// A mount at the filesystem root would (if it succeeded) replace the root
	// filesystem view and, worse, chown the root directory to the invoking
	// user. Refuse up front; Clean() also catches path spellings like "//".
	if mountPoint != "" && filepath.Clean(mountPoint) == "/" {
		return failOpen(fmt.Errorf("refusing to mount a source at the filesystem root"))
	}

	// If the mount point path exists as a file (not a directory), fall back to
	// <path>.mnt. Bound the number of fallbacks: an unbounded loop would never
	// terminate if every <path>.mnt.mnt... candidate also exists as a file.
	// The loop also determines whether the directory we end up mounting at was
	// created here (createdMountpoint), the signal that governs cleanup on
	// failure and the ownership chown.
	mountPointBase := mountPoint
	createdMountpoint := false
	const maxMountPointCollisions = 16
	for attempt := 0; ; attempt++ {
		if attempt == maxMountPointCollisions {
			return failOpen(fmt.Errorf("no free mount point: %s and its %d .mnt variants are all files", mountPointBase, maxMountPointCollisions))
		}
		fi, err := os.Stat(mountPoint)
		if err == nil {
			if fi.IsDir() {
				break
			}
			fmt.Printf("Path %s is a file; using %s instead.\n", mountPoint, mountPoint+".mnt")
			mountPoint += ".mnt"
			continue
		}
		if !os.IsNotExist(err) {
			// A permission or other error probing the mount point. Surface it
			// clearly rather than masking it behind a mkdir failure, and close
			// a LUKS mapping that was already opened.
			return failOpen(fmt.Errorf("checking mount point %s: %w", mountPoint, err))
		}
		createdMountpoint = true
		break
	}

	fmt.Printf("Creating mount point %s...\n", mountPoint)
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return failOpen(fmt.Errorf("creating mountpoint: %w", err))
	}

	device := source
	if encrypted {
		device = "/dev/mapper/" + name
	}
	fmt.Printf("Mounting %s to %s...\n", device, mountPoint)
	if err := runCmd("mount", device, mountPoint); err != nil {
		if encrypted {
			if closeErr := luksClose(name); closeErr != nil {
				return fmt.Errorf("mount failed: %w (mapping left open: %v)", err, closeErr)
			}
		}
		if createdMountpoint {
			// Surface a failed cleanup: leaving a stray empty directory named
			// like a mount point is confusing, but so is a hidden error when
			// it cannot be removed (e.g. a parent directory became read-only).
			if err := os.Remove(mountPoint); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: removing mount point %s after failure: %v\n", mountPoint, err)
			}
		}
		return fmt.Errorf("mount failed: %w (device %s, target %s)", err, device, mountPoint)
	}

	// chown only mounts lmount created itself. Retargeting a pre-existing
	// directory (e.g. an admin-managed /mnt/shared) changes who owns a path
	// that is not lmount's to reassign; a fresh mount point must belong to the
	// invoking user so files written there are owned by them. This is also why
	// the chown entry in the sudoers example is flagged as optional.
	if createdMountpoint {
		current, err := currentUser()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot determine current user: %v\n", err)
		} else {
			fmt.Printf("Setting ownership of %s...\n", mountPoint)
			if err := runCmd("chown", current.Uid+":"+current.Gid, mountPoint); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not set ownership: %v\n", err)
			}
		}
	}

	fmt.Println("Done.")
	return nil
}

// parseFindmntTargets converts findmnt's -o TARGET output into a deduplicated
// list of mount-point targets. findmnt may repeat a TARGET when multiple
// stacked/bind mounts share a mount point; unmounting (and then removing) the
// same path twice only produces a spurious second-umount error, so each target
// is returned once.
func parseFindmntTargets(out []byte) []string {
	mounts := strings.Split(strings.TrimSpace(string(out)), "\n")
	seen := make(map[string]struct{}, len(mounts))
	targets := make([]string, 0, len(mounts))
	for _, m := range mounts {
		// Trim whitespace so a stray \r (CRLF) or indented line cannot produce
		// a failing umount/rmdir on a spurious path.
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		targets = append(targets, m)
	}
	return targets
}

func umountAndClose(checkMapped func(name string) bool, runCmd func(name string, args ...string) error, runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
	luksClose := func(name string) error {
		return runCmd("cryptsetup", "luksClose", name)
	}

	// Normalize a trailing separator on the source the same way openAndMount
	// does, so findmnt's -S search never queries a path ending in "/".
	source = trimTrailingSeparators(source)
	name := srcName(source)
	if name == "" {
		return fmt.Errorf("cannot determine name from empty source")
	}
	// Reject a source whose basename could not be a device-mapper mapping
	// before treating it as one: for e.g. "." the bare probe would stat
	// /dev/mapper/. (the /dev/mapper directory) and misclassify a plain
	// directory as an open mapping. An open mapping still wins over a missing
	// path (the backing file may have been deleted), so the mapping is checked
	// first.
	encrypted := checkMapperName(name) == nil && checkMapped(name)

	// Validate the source the same way openAndMount does. A directory can
	// never back a mount and would otherwise be misread as an open mapping
	// (e.g. "." probes /dev/mapper/. == /dev/mapper) or hit a cryptic findmnt
	// failure, so catch it up front. Missing path-like sources error out
	// unless an open mapping (checked above) can still be detached.
	if !strings.HasPrefix(source, "/dev/") && source != "" {
		fi, err := os.Stat(source)
		if err != nil {
			if os.IsNotExist(err) && !encrypted {
				// A bare name (no "/") may still name an existing /dev/
				// device, e.g. "-u sda1"; resolveSource maps those below. Any
				// other missing source can never be unmounted or detached, so
				// reject it before a cryptic findmnt probe.
				if strings.Contains(source, "/") {
					return fmt.Errorf("source %s does not exist", source)
				}
				if _, devErr := os.Stat("/dev/" + source); devErr != nil {
					return fmt.Errorf("source %s does not exist", source)
				}
			}
		} else if fi.IsDir() {
			return fmt.Errorf("source %s is a directory, not a device or file", source)
		}
	}

	search := source
	if encrypted {
		search = "/dev/mapper/" + name
	} else {
		search = resolveSource(source)
		if search == source {
			if fi, fiErr := os.Stat(search); fiErr == nil {
				// The source resolved to an existing filesystem entry (e.g. a
				// relative file path). Use its absolute path for findmnt so the
				// search matches regardless of the caller's working directory.
				if fi.IsDir() {
					// A directory is not a mount source; mirror openAndMount's
					// rejection (this is only reachable for a source under
					// /dev that is a directory, e.g. /dev/mapper itself).
					return fmt.Errorf("source %s is a directory, not a device or file", source)
				}
				if abs, absErr := filepath.Abs(search); absErr == nil {
					search = abs
				}
			} else if !strings.Contains(source, "/") {
				// A bare name that is neither an existing path nor resolvable
				// is treated as a device (e.g. "sda1" -> /dev/sda1).
				search = "/dev/" + name
			}
		}
	}

	out, findErr := runOutputDirect("findmnt", "-n", "-l", "-o", "TARGET", "-S", search)
	targets := parseFindmntTargets(out)
	if findErr != nil && (len(targets) > 0 || encrypted) {
		// findmnt both listed targets and reported failure, or a mapping probe
		// says the LUKS device is open but findmnt cannot see it. Either way we
		// cannot tell whether a filesystem is still mounted, and closing a LUKS
		// mapping under an uncertain probe could strand a live mount, so bail
		// out without unmounting or closing.
		return fmt.Errorf("findmnt failed for %s: %v", search, findErr)
	}
	// Otherwise findmnt merely reported that nothing matches: for a plain
	// source that is simply not mounted (its backing file still exists).
	if !encrypted && len(targets) == 0 {
		// A plain source that findmnt cannot find is simply not mounted; say so
		// rather than reporting the same success ("Done.") as a real unmount.
		fmt.Printf("Nothing mounted at %s.\n", source)
		return nil
	}
	var errs []string
	// Unmount deeper (nested) targets before shallower ones: umounting a parent
	// path while it still holds a child mount fails with "target is busy".
	// findmnt returns mounts in arbitrary order, so sort longest-path first. This
	// is safe because a mount point can only ever be a child of another mount.
	sort.Sort(sort.Reverse(sort.StringSlice(targets)))
	unmountFailed := false
	for _, m := range targets {
		fmt.Printf("Unmounting %s...\n", m)
		if err := runCmd("umount", m); err != nil {
			errs = append(errs, fmt.Sprintf("umount %s: %v", m, err))
			unmountFailed = true
			continue
		}
		if err := removeIfEmpty(m); err != nil {
			errs = append(errs, fmt.Sprintf("rmdir %s: %v", m, err))
		}
	}

	// Only detach the LUKS mapping once every target was unmounted. Closing the
	// mapping while a filesystem is still mounted would strand a dangling mount
	// over a now-removed mapper device.
	if encrypted && !unmountFailed {
		fmt.Printf("Closing LUKS device %s...\n", name)
		if err := luksClose(name); err != nil {
			// Include the mapping name so a failure during a multiple-device
			// cleanup identifies which mapping could not be detached.
			errs = append(errs, fmt.Sprintf("luksClose %s: %v", name, err))
		}
	} else if encrypted {
		// The umount errors already name their targets; add an explicit note so
		// the still-open mapping is not lost among them.
		errs = append(errs, fmt.Sprintf("LUKS mapping %s left open: a target is still mounted", name))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	fmt.Println("Done.")
	return nil
}

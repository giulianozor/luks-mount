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

func openAndMount(runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source, keyFile, mountPoint string) error {
	isLuks := func(source string) bool {
		_, err := runOutput("cryptsetup", "isLuks", source)
		return err == nil
	}
	luksClose := func(name string) error {
		return runCmd("cryptsetup", "luksClose", name)
	}

	name := srcName(source)

	// Validate the source exists before probing LUKS: isLuks on a missing path
	// reports "not LUKS", which would otherwise mask a typo'd source path as a
	// "not LUKS" error, and wastes a privileged cryptsetup probe (and possibly a
	// sudo prompt) on a path that can never be mounted.
	if !strings.HasPrefix(source, "/dev/") && source != "" {
		fi, err := os.Stat(source)
		if err != nil {
			if os.IsNotExist(err) {
				// A non-device source that does not exist is almost certainly a typo.
				// Reject it up front rather than letting cryptsetup/mount fail with a
				// cryptic error, and never leave a LUKS mapping open for nothing.
				return fmt.Errorf("source %s does not exist", source)
			}
		} else if fi.IsDir() {
			// A directory can never be a mount source (lmount does no bind
			// mounts); rejecting it up front is clearer than mount's own failure.
			return fmt.Errorf("source %s is a directory, not a device or file", source)
		} else if fi.Mode().IsRegular() && fi.Size() == 0 {
			// An empty file carries no filesystem for a loop mount to attach;
			// mount's error on a zero-length image is cryptic.
			return fmt.Errorf("source %s is an empty file and cannot be mounted", source)
		} else if !fi.Mode().IsRegular() && fi.Mode()&os.ModeDevice == 0 {
			// A FIFO, socket, or other special file can never be a mount
			// source and may even block sniffing it (opening a FIFO for
			// reading blocks until a writer appears). Reject it up front
			// rather than hanging or failing cryptically later.
			return fmt.Errorf("source %s is not a regular file", source)
		}
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

	// If the mount point path exists as a file (not a directory), fall back to
	// <path>.mnt. Bound the number of fallbacks: an unbounded loop would never
	// terminate if every <path>.mnt.mnt... candidate also exists as a file.
	mountPointBase := mountPoint
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
		break
	}

	_, statErr := os.Stat(mountPoint)
	createdMountpoint := os.IsNotExist(statErr)

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
			_ = os.Remove(mountPoint)
		}
		return fmt.Errorf("mount failed: %w", err)
	}

	current, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot determine current user: %v\n", err)
	} else {
		fmt.Printf("Setting ownership of %s...\n", mountPoint)
		if err := runCmd("chown", current.Uid+":"+current.Gid, mountPoint); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not set ownership: %v\n", err)
		}
	}

	fmt.Println("Done.")
	return nil
}

func umountAndClose(checkMapped func(name string) bool, runCmd func(name string, args ...string) error, runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
	luksClose := func(name string) error {
		return runCmd("cryptsetup", "luksClose", name)
	}

	name := srcName(source)
	if name == "" {
		return fmt.Errorf("cannot determine name from empty source")
	}
	encrypted := checkMapped(name)

	search := source
	if encrypted {
		search = "/dev/mapper/" + name
	} else {
		search = resolveSource(source)
		if search == source {
			if _, err := os.Stat(search); err == nil {
				// The source resolved to an existing filesystem entry (e.g. a
				// relative file path). Use its absolute path for findmnt so the
				// search matches regardless of the caller's working directory.
				if abs, absErr := filepath.Abs(search); absErr == nil {
					search = abs
				}
			} else if !strings.Contains(source, "/") {
				// A bare name that is neither an existing path nor resolvable
				// is treated as a device (e.g. "sda1" -> /dev/sda1).
				search = "/dev/" + name
			} else if os.IsNotExist(err) && !strings.HasPrefix(source, "/dev/") {
				// A path source that does not exist is almost certainly a typo.
				// Surface it rather than silently reporting success while doing
				// nothing. (Existing but unmounted sources stay idempotent, and
				// /dev device nodes may legitimately be absent.)
				return fmt.Errorf("source %s does not exist", source)
			}
		}
	}

	out, findErr := runOutputDirect("findmnt", "-n", "-l", "-o", "TARGET", "-S", search)
	if findErr != nil {
		// The probe failed, so we cannot tell whether the filesystem is still
		// mounted or where it is. Closing a LUKS mapping under an unmount probe
		// failure could strand a live mount, so bail out without unmounting or
		// closing.
		return fmt.Errorf("findmnt failed: %v", findErr)
	}
	var errs []string
	mounts := strings.Split(strings.TrimSpace(string(out)), "\n")
	// findmnt may repeat a TARGET when multiple stacked/bind mounts share a
	// mount point. Unmounting (and then removing) the same path twice only
	// produces a spurious second-umount error, so dedupe first.
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
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	fmt.Println("Done.")
	return nil
}

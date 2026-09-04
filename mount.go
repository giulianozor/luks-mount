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
	encrypted := isLuks(source)

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
			if encrypted {
				luksClose(name)
			}
			return fmt.Errorf("cannot infer mount point name from empty source")
		}
		home, err := userHomeDir()
		if err != nil {
			if encrypted {
				luksClose(name)
			}
			return fmt.Errorf("getting home directory: %w", err)
		}
		mountPoint = filepath.Join(home, name)
	}

	for {
		fi, err := os.Stat(mountPoint)
		if err == nil {
			if fi.IsDir() {
				break
			}
			mountPoint += ".mnt"
			continue
		}
		if !os.IsNotExist(err) {
			// A permission or other error probing the mount point. Surface it
			// clearly rather than masking it behind a mkdir failure, and close
			// a LUKS mapping that was already opened.
			if encrypted {
				luksClose(name)
			}
			return fmt.Errorf("checking mount point %s: %w", mountPoint, err)
		}
		break
	}

	_, statErr := os.Stat(mountPoint)
	createdMountpoint := os.IsNotExist(statErr)

	fmt.Printf("Creating mount point %s...\n", mountPoint)
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		if encrypted {
			luksClose(name)
		}
		return fmt.Errorf("creating mountpoint: %w", err)
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
	// Unmount deeper (nested) targets before shallower ones: umounting a parent
	// path while it still holds a child mount fails with "target is busy".
	// findmnt returns mounts in arbitrary order, so sort longest-path first. This
	// is safe because a mount point can only ever be a child of another mount.
	sort.Sort(sort.Reverse(sort.StringSlice(mounts)))
	for _, m := range mounts {
		if m == "" {
			continue
		}
		fmt.Printf("Unmounting %s...\n", m)
		if err := runCmd("umount", m); err != nil {
			errs = append(errs, fmt.Sprintf("umount %s: %v", m, err))
			continue
		}
		if err := removeIfEmpty(m); err != nil {
			errs = append(errs, fmt.Sprintf("rmdir %s: %v", m, err))
		}
	}

	if encrypted {
		fmt.Printf("Closing LUKS device %s...\n", name)
		if err := luksClose(name); err != nil {
			errs = append(errs, fmt.Sprintf("luksClose: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	fmt.Println("Done.")
	return nil
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
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

// mapperDir lists the open device-mapper mappings; a variable so tests can
// simulate /dev/mapper under a temp directory.
var mapperDir = "/dev/mapper"

// sysClassBlock is the sysfs root under which each dm block device exposes its
// backing devices in <dm>/slaves; a variable so tests can simulate the sysfs
// tree under a temp directory.
var sysClassBlock = "/sys/class/block"

// devStat probes whether a device node exists; a variable so tests can simulate
// udev settling after luksOpen without racing real /dev entries.
var devStat = os.Stat

var waitForDeviceTries = 20

// mountPointStatePath is where lmount records the mount point directories a
// successful mount created, so a later unmount can tell its own creations
// apart from a user's pre-existing directories (e.g. an explicit -m pointing
// at a directory the user owns). It follows the XDG state convention
// ($XDG_STATE_HOME, or ~/.local/state when unset) with an lmount/ subdirectory;
// a variable so tests can redirect it to a temp file.
var mountPointStatePath = func() (string, error) {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		// The XDG Base Directory spec requires an absolute path; a relative
		// value would scatter state around the caller's working directory.
		if !filepath.IsAbs(xdg) {
			return "", fmt.Errorf("XDG_STATE_HOME %q is not an absolute path", xdg)
		}
		return filepath.Join(xdg, "lmount", "mounts.json"), nil
	}
	home, err := userHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "lmount", "mounts.json"), nil
}

// mountPointState is the serialized form of the registry of mount point
// directories lmount created; a map provides membership tests elsewhere.
type mountPointState struct {
	Mounts []string `json:"mounts"`
}

// loadMountPoints reads the set of mount point directories recorded as created
// by lmount. A missing file is simply an empty set; any other failure is
// returned so callers can decide whether stale bookkeeping is fatal. Members
// are kept as findmnt reports them (canonical, symlink-resolved targets) so
// lookups are exact.
func loadMountPoints() (map[string]struct{}, error) {
	p, err := mountPointStatePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, err
	}
	var st mountPointState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(st.Mounts))
	for _, m := range st.Mounts {
		if m != "" {
			set[m] = struct{}{}
		}
	}
	return set, nil
}

// saveMountPoints writes the recorded set, creating the state directory with
// owner-only permissions and the file with owner-only access.
func saveMountPoints(set map[string]struct{}) error {
	p, err := mountPointStatePath()
	if err != nil {
		return err
	}
	st := mountPointState{Mounts: make([]string, 0, len(set))}
	for m := range set {
		st.Mounts = append(st.Mounts, m)
	}
	sort.Strings(st.Mounts)
	b, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	// Write through a same-directory temp file and an atomic rename. An
	// in-place os.WriteFile truncates the state file first, so a failure or a
	// crash mid-write leaves torn JSON behind; the next unmount then fails to
	// load any record and silently stops removing lmount-created mount point
	// directories (the losing write or corrupt file is never auto-recovered).
	// A rename is atomic on the same filesystem, so the target is always either
	// the old, complete state or the new, complete state. The fresh temp file
	// is also always created 0600, fixing the mode a pre-existing state file
	// keeps across an in-place WriteFile (which only sets the mode on create).
	tmp, err := os.CreateTemp(filepath.Dir(p), "mounts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// lockState serializes read-modify-write updates to the mount point state file
// with an advisory flock on a persistent <mounts.json>.lock next to it.
// Concurrent lmount invocations (e.g. a script mounting several images in
// parallel) otherwise race in recordMountPoint's load-merge-save and in
// umountAndClose's load-then-save span: both sides read the same starting set
// and the last writer wins, silently dropping the other's record, which makes a
// later unmount leave that mount point directory behind. The lock file is
// deliberately never removed: unlinking it would let a later opener create a
// fresh inode and bypass a holder of the old one. The release func drops the
// lock and closes the fd.
func lockState() (func(), error) {
	p, err := mountPointStatePath()
	if err != nil {
		return nil, err
	}
	// A first-ever record has no state directory yet (saveMountPoints creates
	// it); the lock file must land in the same directory, so create it first
	// with the same owner-only mode the state file uses.
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// recordMountPoint adds path to the set of lmount-created mount points. A
// failure to persist is returned, never fatal to the mount operation itself.
// The read-modify-write holds lockState, so parallel invocations cannot drop
// each other's records.
func recordMountPoint(path string) error {
	release, err := lockState()
	if err != nil {
		return err
	}
	defer release()
	set, err := loadMountPoints()
	if err != nil {
		return err
	}
	set[path] = struct{}{}
	return saveMountPoints(set)
}

// waitForDevice polls until path exists (udev may take a moment to create a
// freshly-opened /dev/mapper node) or the wait budget elapses. It reports
// whether the node was found; the caller proceeds either way so mount can
// surface a real error, adding a hint when the probe timed out.
func waitForDevice(path string) bool {
	for i := 0; i < waitForDeviceTries; i++ {
		if _, err := devStat(path); err == nil {
			return true
		}
		if i == 0 {
			// A missing parent directory means the node never existed and
			// polling is pointless (e.g. /dev/mapper is absent on non-Linux,
			// which is also what tests see with stubbed cryptsetup).
			if _, perr := os.Stat(filepath.Dir(path)); perr != nil {
				return false
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// checkSourceMode rejects a source entry that can never back a mount: a
// directory, an empty regular file, or a special file such as a FIFO, socket,
// or character device (which would either block the LUKS sniff open forever or
// never yield a mountable filesystem). Only a regular file or a block device
// -- the two legitimate mount sources lmount supports -- is allowed through.
func checkSourceMode(fi os.FileInfo, source string) error {
	if fi.IsDir() {
		// A directory can never be a mount source (lmount does no bind
		// mounts); rejecting it up front is clearer than mount's own failure.
		return fmt.Errorf("source %s is a directory, not a device or file", source)
	}
	mode := fi.Mode()
	if mode.IsRegular() {
		if fi.Size() == 0 {
			// An empty file carries no filesystem for a loop mount to attach;
			// mount's error on a zero-length image is cryptic.
			return fmt.Errorf("source %s is an empty file and cannot be mounted", source)
		}
		return nil
	}
	// Only a block source can back a mount. Character devices (e.g. /dev/tty,
	// /dev/input/event0) and other special files (FIFOs, sockets) either block
	// sniffing them (opening a FIFO or a char device for reading can block
	// forever) or can never yield a mountable filesystem, so reject them up
	// front by type rather than hanging or failing cryptically later. A block
	// device (os.ModeDevice without os.ModeCharDevice) is a legitimate mount
	// source and is allowed through to the LUKS sniff.
	if mode&os.ModeCharDevice != 0 || mode&os.ModeDevice == 0 {
		return fmt.Errorf("source %s is not a regular file or block device", source)
	}
	return nil
}

func openAndMount(runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source, keyFile, mountPoint string) error {
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
					// The resolved /dev/ node was never mode-checked (the
					// original stat of the bare name failed), but it is now the
					// effective source. Validate it like any explicit source so
					// a directory such as /dev/mapper, a character device, or a
					// FIFO is rejected with a clear message instead of surfacing
					// as a cryptic mount/`cryptsetup` failure after a wasteful
					// privileged probe. A stat failure here falls through to the
					// LUKS probe exactly as an unreadable device would.
					if resolvedFi, rErr := os.Stat(source); rErr == nil {
						if err := checkSourceMode(resolvedFi, source); err != nil {
							return err
						}
					}
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
		// A source whose path resolves through a non-directory (e.g.
		// "img/sub", since "img" is a file) or through a symbolic-link loop
		// can never back a mount, and os.Stat has already established that.
		// Reject it with the stat error rather than falling through to a
		// (possibly sudo-prompting) cryptsetup probe on a path that can only
		// fail cryptically.
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("source %s cannot be accessed: %w", source, err)
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
		var probeErr error
		encrypted, probeErr = probeIsLuks(runOutput, source)
		if probeErr != nil {
			return probeErr
		}
	}

	if keyFile != "" && !encrypted {
		// A key file only makes sense for a LUKS source. Silently ignoring a
		// wrong/mistyped -k would give no indication to the user.
		return fmt.Errorf("source %s is not LUKS; -k/--key is not valid", source)
	}

	if keyFile != "" && encrypted {
		// Passing the source itself as the key would make cryptsetup read a
		// LUKS header as a key and fail cryptically. Compare canonical paths
		// so a relative or symlinked spelling of the same file is caught too,
		// and compare inodes so an equal hardlink is caught as well (two paths
		// can EvalSymlinks to different strings yet be the same file).
		if sameFilePath(keyFile, source) {
			return fmt.Errorf("key file path and source path must be different, both are %q", filepath.Clean(source))
		}
		if kStat, kErr := os.Stat(keyFile); kErr == nil {
			if sStat, sErr := os.Stat(source); sErr == nil && os.SameFile(kStat, sStat) {
				return fmt.Errorf("key file and source are the same file: %q", filepath.Clean(source))
			}
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
		// Unreachable today: the earlier empty-source rejection guarantees a
		// non-empty name below. Kept as a guard so a refactor cannot turn the
		// inferred-mount-point branch into a silent relative-path mount.
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
	} else if !filepath.IsAbs(mountPoint) {
		// An explicitly-provided relative -m (e.g. "-m tmp/data") is resolved
		// against the caller's working directory when mount(2) runs, so record
		// and later compare the path exactly as it will be mounted. Leaving it
		// relative would make the cleanup and the "already mounted"/findmnt
		// probes disagree with the real target (a relative spelling is never
		// equal to the absolute mount target), and a later unmount could not
		// match it against a relative record. Normalize to an absolute path of
		// the current working directory up front. filepath.Abs never fails in
		// practice (no cwd); guard anyway so a failure cannot silently proceed
		// with a relative path that would break matching.
		abs, err := filepath.Abs(mountPoint)
		if err != nil {
			return failOpen(fmt.Errorf("resolving mount point %s: %w", mountPoint, err))
		}
		mountPoint = abs
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
			return failOpen(fmt.Errorf("no free mount point: %s and up to %d .mnt variants are all files", mountPointBase, maxMountPointCollisions-1))
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

	// A directory that is already an active mount point would be stacked over
	// (hiding whatever is already mounted there) with no warning, and an
	// admin-managed mount target that lmount reuses would also be chown'd
	// below. Refuse when findmnt reports the target in use; a freshly created
	// mount point cannot already be mounted, so the probe is skipped then.
	if !createdMountpoint {
		inUse, probeErr := mountPointInUse(mountPoint)
		if probeErr != nil {
			return failOpen(fmt.Errorf("checking whether %s is already mounted: %w", mountPoint, probeErr))
		}
		if inUse {
			return failOpen(fmt.Errorf("refusing to mount over %s: a filesystem is already mounted there", mountPoint))
		}
	}

	fmt.Printf("Creating mount point %s...\n", mountPoint)
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return failOpen(fmt.Errorf("creating mountpoint: %w", err))
	}

	device := source
	if encrypted {
		device = "/dev/mapper/" + name
		// luksOpen is kernel-synchronous, but udev may still be creating the
		// stale /dev/mapper node when we are ready to mount; wait briefly so a
		// slow system does not turn a settled mapping into a spurious ENOENT.
		if !waitForDevice(device) {
			// The budget elapsed; mount will fail clearly if the node is truly
			// absent, but warn first so the reason is visible in the output.
			fmt.Fprintf(os.Stderr, "Warning: device %s not found after luksOpen (udev may still be settling); continuing.\n", device)
		}
	}
	fmt.Printf("Mounting %s to %s...\n", device, mountPoint)
	if err := runCmd("mount", device, mountPoint); err != nil {
		var closeNote string
		if encrypted {
			if closeErr := luksClose(name); closeErr != nil {
				closeNote = fmt.Sprintf(" (mapping left open: %v)", closeErr)
			}
		}
		if createdMountpoint {
			// Surface a failed cleanup: leaving a stray empty directory named
			// like a mount point is confusing, but so is a hidden error when
			// it cannot be removed (e.g. a parent directory became read-only).
			if rmErr := os.Remove(mountPoint); rmErr != nil && !os.IsNotExist(rmErr) {
				fmt.Fprintf(os.Stderr, "Warning: removing mount point %s after failure: %v\n", mountPoint, rmErr)
			}
		}
		return fmt.Errorf("mount failed: %w (device %s, target %s)%s", err, device, mountPoint, closeNote)
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

	if createdMountpoint {
		// Remember that this directory was created by lmount so a later unmount
		// knows it may clean it up. Losing the record is not a mount failure:
		// the worst outcome is an empty directory left behind, which is safer
		// than deleting a directory the user did not ask lmount to create.
		//
		// Record the canonical path (symlinks resolved): findmnt reports a
		// mount target by its resolved path, so unmount's membership test keys
		// on that canonical spelling. A record that kept the literal mount
		// spelling (e.g. "-m /var/run" resolving to /private/var/run) would
		// never match findmnt's target and the directory would be left behind.
		// Canonical resolution happens here so the stored value is exactly what
		// a later unmount looks up.
		record := mountPoint
		if resolved, err := filepath.EvalSymlinks(mountPoint); err == nil {
			record = resolved
		}
		if err := recordMountPoint(record); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not record mount point %s: %v\n", mountPoint, err)
		}
	}

	fmt.Println("Done.")
	return nil
}

// probeMountPointInUse runs the findmnt query that answers "is path already an
// active mount point?". It is separate from the mountPointInUse seam so tests
// can exercise the real findmnt invocation (including the -T flag) against a
// capturing runOutputDirect stub.
func probeMountPointInUse(runOutputDirect func(name string, args ...string) ([]byte, error), path string) (bool, error) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	// -T (target) filters by the mount point directory, which is what "is this
	// path already an active mount point?" means. -S (source) would search by
	// the backing device/source instead and so never match a target directory,
	// silently bypassing the busy-mount refusal for every regular mount.
	out, err := runOutputDirect("findmnt", "-n", "-r", "-o", "TARGET", "-T", path)
	if len(parseFindmntTargets(out)) > 0 {
		return true, nil
	}
	if err != nil && !isFindmntNoMatch(err) {
		return false, err
	}
	return false, nil
}

// mountPointInUse reports whether path is currently an active mount point. It
// is a variable so tests can simulate findmnt's verdict without a live mount
// table. The probe follows the same exit-code discipline as the umount path:
// findmnt exit 1 is its documented "nothing matches" code and the only proof a
// target is free; any other failure proves nothing and is returned as an error.
var mountPointInUse = func(path string) (bool, error) {
	return probeMountPointInUse(runOutputDirect, path)
}

// parseFindmntTargets converts findmnt's raw -o TARGET output (run with -r, so
// spaces and other specials are literal) into a deduplicated list of mount-point
// targets. findmnt may repeat a TARGET when multiple stacked/bind mounts share a
// mount point; unmounting (and then removing) the same path twice only produces
// a spurious second-umount error, so each target is returned once.
func parseFindmntTargets(out []byte) []string {
	mounts := strings.Split(strings.TrimSpace(string(out)), "\n")
	seen := make(map[string]struct{}, len(mounts))
	targets := make([]string, 0, len(mounts))
	for _, m := range mounts {
		// Trim whitespace so a stray \r (CRLF) or indented line cannot produce
		// a failing umount/rmdir on a spurious path. Interior spaces are part
		// of the raw mount path and are preserved.
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

// isFindmntNoMatch reports whether err is findmnt's documented "no match"
// result: the probe actually ran and exited with status 1. A missing binary,
// a spawn error, or any other exit code is not evidence that nothing is
// mounted, so those must not be turned into a successful nothing-mounted note.
func isFindmntNoMatch(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

// probeIsLuks asks cryptsetup whether source is a LUKS device. cryptsetup
// exits 0 for LUKS and 1 for "not LUKS"; any other outcome (a missing
// cryptsetup binary, a spawn error, or a different failure exit code) means
// the probe produced no verdict, and is returned as an error rather than
// being misclassified as a plain, unencrypted source that then gets mounted
// as-is.
func probeIsLuks(runOutput func(name string, args ...string) ([]byte, error), source string) (bool, error) {
	_, err := runOutput("cryptsetup", "isLuks", source)
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 {
			return false, nil
		}
		// A device that cannot be opened (a missing node, or one the probe
		// cannot access) is not LUKS, no more than cryptsetup's exit-1 "not
		// LUKS" verdict is. cryptsetup 2.8+ reports such a device as exit 4
		// with "Device … does not exist or access denied." on stderr, while
		// older versions reported the same situation as exit 1; treating
		// cryptsetup's own inaccessible-device diagnostic as a clean not-LUKS
		// verdict keeps both behaviors interchangeable instead of turning a
		// missing device into a cryptic probe error.
		if strings.Contains(err.Error(), "does not exist or access denied") {
			return false, nil
		}
		return false, fmt.Errorf("cryptsetup isLuks probe failed for %s: %v", source, err)
	}
	if errors.Is(err, exec.ErrNotFound) {
		return false, fmt.Errorf("cryptsetup is not available; cannot tell whether %s is LUKS: %v", source, err)
	}
	// Neither a clean verdict nor a known "cannot run cryptsetup" condition:
	// the probe failed in a way we cannot interpret (e.g. exec denied), so
	// like a non-1 exit code it must not be read as "definitely not LUKS".
	return false, fmt.Errorf("cryptsetup isLuks probe could not run for %s: %v", source, err)
}

// mappingForSource finds the /dev/mapper/<name> mapping whose backing device
// carries the same LUKS header UUID as source. Matching on the header rather
// than on the path discovers a mapping the tool did not open itself (e.g. the
// container was opened as `cryptsetup luksOpen vol.img myvol`), or whose
// backing file moved after it was opened, both of which the default
// basename-derived mapping name would never find. Each open mapping's backing
// device is resolved through its dm block device's sysfs slaves, so only
// readable device nodes are probed. It returns "" when the source is not LUKS,
// a probe fails, or no mapping matches.
func mappingForSource(runOutput func(name string, args ...string) ([]byte, error), source string) string {
	srcOut, err := runOutput("cryptsetup", "luksUUID", source)
	if err != nil {
		return ""
	}
	srcUUID := bytes.TrimSpace(srcOut)
	if len(srcUUID) == 0 {
		return ""
	}
	entries, err := os.ReadDir(mapperDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := filepath.Base(e.Name())
		link, err := os.Readlink(filepath.Join(mapperDir, name))
		if err != nil {
			continue
		}
		slaves, err := os.ReadDir(filepath.Join(sysClassBlock, filepath.Base(link), "slaves"))
		if err != nil {
			continue
		}
		for _, s := range slaves {
			backing := "/dev/" + filepath.Base(s.Name())
			out, err := runOutput("cryptsetup", "luksUUID", backing)
			if err != nil {
				continue
			}
			if bytes.Equal(bytes.TrimSpace(out), srcUUID) {
				return name
			}
		}
	}
	return ""
}

func umountAndClose(checkMapped func(name string) bool, runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), runOutputDirect func(name string, args ...string) ([]byte, error), source string) error {
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

	// A LUKS container may be open under a mapping whose name this run cannot
	// derive (e.g. it was opened manually as `cryptsetup luksOpen vol.img
	// myvol`, or the backing file moved after being opened). Only the header
	// UUID can still link the source to its live mapping, so match every open
	// mapping's backing device against the source's LUKS UUID and, on a match,
	// treat the source as encrypted under that mapping.
	mappingName := name
	// sourceIsLuks records the verdict so it can be reused for the closing
	// "Nothing mounted" hint below: re-deriving it with the unprivileged
	// isLuksContainer would drop the hint for an unreadable source even
	// though the privileged probe already determined it is LUKS.
	sourceIsLuks := false
	if !encrypted {
		sourceIsLuks = luksForSource(runOutput, source)
		// The differently-named-mapping probe reads backing device headers
		// (luksUUID /dev/loopN), which needs the same read access on the device
		// nodes that luksOpen does, so it must go through the privileged
		// runOutput seam (sudo), not the unprivileged runOutputDirect reserved
		// for findmnt. A user outside the "disk" group cannot open the loop
		// node of a file-backed container, and a silently-failing probe would
		// leave the mapping open with a misleading "Nothing mounted." luksForSource
		// likewise uses the privileged probe for an unreadable block device, so a
		// LUKS container under a differently-named mapping is not skipped.
		if sourceIsLuks {
			if byUUID := mappingForSource(runOutput, source); byUUID != "" {
				mappingName = byUUID
				encrypted = true
			}
		}
	}

	// Validate the source the same way openAndMount does. A directory can
	// never back a mount and would otherwise be misread as an open mapping
	// (e.g. "." probes /dev/mapper/. == /dev/mapper) or hit a cryptic findmnt
	// failure, so catch it up front. Missing path-like sources error out
	// unless an open mapping (checked above) can still be detached. The same
	// override applies to a directory that merely shares the source's name:
	// the default mount point for a source is "~/<basename>", so a user
	// running "-u <basename>" from another directory where that name exists
	// (typically their home) would otherwise be falsely rejected as "not a
	// device or file" while a real mapping of that source stands open.
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
		} else if fi.IsDir() && !encrypted {
			return fmt.Errorf("source %s is a directory, not a device or file", source)
		}
	}

	search := source
	if encrypted {
		search = "/dev/mapper/" + mappingName
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
			}
			// A missing source cannot reach this point: a bare name has either
			// already been resolved to /dev/<name> by resolveSource (when that
			// device exists) or been rejected above, and a path-like source
			// that failed to stat was rejected too. Whatever path-like source
			// remains is probed as-is; findmnt reporting nothing means it is
			// simply not mounted.
		}
	}

	// -r asks findmnt for raw output and disables the tree layout: without it
	// findmnt escapes special characters in paths (a space becomes \040) and
	// formats the output as a tree, and umount would then be handed the escaped
	// spelling of a real mount path and fail to find it. -l (list) is NOT used:
	// newer util-linux (2.39+) treats -l/--list and -r/--raw as mutually
	// exclusive, and -r alone already disables the tree.
	out, findErr := runOutputDirect("findmnt", "-n", "-r", "-o", "TARGET", "-S", search)
	targets := parseFindmntTargets(out)
	if findErr != nil && !isFindmntNoMatch(findErr) && (len(targets) > 0 || encrypted) {
		// findmnt both listed targets and reported a genuine failure, or a
		// mapping probe says the LUKS device is open but findmnt failed for a
		// reason other than exit 1 (its documented "nothing matches" code). A
		// real no-match means nothing is mounted, so an open mapping can be
		// closed safely. Any other outcome — a spawn failure or a different
		// exit code — means we cannot tell whether a filesystem is still
		// mounted, and closing a LUKS mapping under an uncertain probe could
		// strand a live mount, so bail out without unmounting or closing.
		return fmt.Errorf("findmnt failed for %s: %v", search, findErr)
	}
	if !encrypted && len(targets) == 0 {
		// findmnt's own exit status is the evidence here: exit 1 is its
		// documented "nothing matches" code, so an empty match list really
		// means nothing is mounted. Any other failure (binary missing, a probe
		// error, exit code other than 1) proves nothing, and reporting
		// "Nothing mounted" from it would be a silent false negative; say so.
		if findErr != nil && !isFindmntNoMatch(findErr) {
			return fmt.Errorf("findmnt failed for %s: %v", search, findErr)
		}
		// A plain source that findmnt cannot find is simply not mounted; say so
		// rather than reporting the same success ("Done.") as a real unmount.
		// If the source is itself a LUKS file with no mapping open, distinguish
		// that too: a user expecting to close a mapping they left open (possibly
		// under a differently-named mapping) gets a hint instead of a pithy
		// "nothing mounted".
		msg := fmt.Sprintf("Nothing mounted at %s.", source)
		if sourceIsLuks || isLuksContainer(source) {
			msg += " (The source is a LUKS container but has no open /dev/mapper mapping.)"
		}
		fmt.Println(msg)
		return nil
	}
	var errs []string
	// Only directories lmount itself created may be removed after a successful
	// unmount. A pre-existing target (e.g. an explicit -m over a user's own
	// directory) is not lmount's to delete, mirroring openAndMount's
	// createdMountpoint ownership rule. Load the recorded set once and drop each
	// target from it as it is unmounted; an unreadable or missing record simply
	// means nothing is removable, never a hard failure.
	var created map[string]struct{}
	if len(targets) > 0 {
		// Hold the state lock across the load ... save span below so two
		// concurrent unmounts cannot each read the same starting set and the
		// later save drop the earlier one's removal. A lock failure degrades to
		// the pre-lock behavior (records left unremoved), never a hard failure.
		if release, lockErr := lockState(); lockErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot lock mount point records (%v); leaving empty mount point directories in place\n", lockErr)
		} else {
			defer release()
		}
		var stateErr error
		created, stateErr = loadMountPoints()
		if stateErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot read mount point records (%v); leaving empty mount point directories in place\n", stateErr)
		}
	}
	// Unmount deeper (nested) targets before shallower ones: umounting a parent
	// path while it still holds a child mount fails with "target is busy".
	// findmnt returns mounts in arbitrary order, so sort longest-path first. This
	// is safe because a mount point can only ever be a child of another mount.
	sort.Sort(sort.Reverse(sort.StringSlice(targets)))
	unmountFailed := false
	stateDirty := false
	for _, m := range targets {
		fmt.Printf("Unmounting %s...\n", m)
		if err := runCmd("umount", m); err != nil {
			errs = append(errs, fmt.Sprintf("umount %s: %v", m, err))
			unmountFailed = true
			continue
		}
		if _, ok := created[m]; ok {
			if err := removeIfEmpty(m); err != nil {
				errs = append(errs, fmt.Sprintf("rmdir %s: %v", m, err))
			}
			delete(created, m)
			stateDirty = true
		}
	}
	// Persist the dropped records: once a mount is gone the directory's
	// lmount-created contract has ended whether or not it was removed, so a
	// later unmount must not treat the path as removable. A failed write is a
	// warning rather than a cleanup failure.
	if stateDirty {
		if err := saveMountPoints(created); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not update mount point records: %v\n", err)
		}
	}

	// Only detach the LUKS mapping once every target was unmounted. Closing the
	// mapping while a filesystem is still mounted would strand a dangling mount
	// over a now-removed mapper device.
	if encrypted && !unmountFailed {
		fmt.Printf("Closing LUKS device %s...\n", mappingName)
		if err := luksClose(mappingName); err != nil {
			// Include the mapping name so a failure during a multiple-device
			// cleanup identifies which mapping could not be detached.
			errs = append(errs, fmt.Sprintf("luksClose %s: %v", mappingName, err))
		}
	} else if encrypted {
		// The umount errors already name their targets; add an explicit note so
		// the still-open mapping is not lost among them.
		errs = append(errs, fmt.Sprintf("LUKS mapping %s left open: a target is still mounted", mappingName))
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	fmt.Println("Done.")
	return nil
}

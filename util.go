package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const _1M = int64(1024 * 1024)
const _1G = int64(1024 * 1024 * 1024)

func sudoCmd(name string, args ...string) *exec.Cmd {
	return exec.Command("sudo", append([]string{name}, args...)...)
}

func runCmd(name string, args ...string) error {
	cmd := sudoCmd(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runOutput(name string, args ...string) ([]byte, error) {
	cmd := sudoCmd(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("%w\n%s", err, strings.TrimRight(stderr.String(), "\n"))
	}
	return out, err
}

// runOutputDirect runs a command without sudo and captures stdout. Use it for
// read-only probes that need no privileges (e.g. findmnt), so they work even
// when sudo does not allow them.
func runOutputDirect(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("%w\n%s", err, strings.TrimRight(stderr.String(), "\n"))
	}
	return out, err
}

func runDirect(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func checkMapped(name string) bool {
	_, err := os.Stat("/dev/mapper/" + name)
	return err == nil
}

func srcName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

// checkMapperName validates a device-mapper mapping name derived from a source
// basename before it is passed to cryptsetup luksOpen. A name containing
// whitespace or a path separator cannot be addressed as a single /dev/mapper
// entry, a leading dash would be misparsed as an option by cryptsetup, mount,
// and umount, and the names "." and ".." would collide with the /dev/mapper
// directory itself. Checking up front turns these into clear errors instead of
// cryptic cryptsetup / shell failures.
func checkMapperName(name string) error {
	if name != "" && name[0] == '-' {
		return fmt.Errorf("invalid device-mapper name %q", name)
	}
	if name == "." || name == ".." || strings.ContainsAny(name, " \t\r\n/") {
		return fmt.Errorf("invalid device-mapper name %q", name)
	}
	return nil
}

// trimTrailingSeparators removes trailing path separators from s so an
// argument like "dir/name/" is accepted wherever "dir/name" is. A root path
// ("/") is preserved: trimming it to "" would silently turn an explicit
// argument into an empty one.
func trimTrailingSeparators(s string) string {
	t := strings.TrimRight(s, "/")
	if t == "" {
		return s
	}
	return t
}

func resolveSource(raw string) string {
	if raw == "" {
		return ""
	}
	if _, err := os.Stat(raw); err == nil {
		return raw
	}
	withDev := "/dev/" + raw
	if _, err := os.Stat(withDev); err == nil {
		return withDev
	}
	return raw
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// expandHome resolves a leading "~/" (or a bare "~") in a user-supplied path
// to the invoking user's home directory, so a shell-quoted argument like
// "-m '~/data'" mounts where the user clearly intended instead of creating a
// literal directory named "~" in the current working directory. All other
// paths, including relative ones, are returned unchanged.
func expandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expanding %q: getting home directory: %w", p, err)
	}
	if p == "~" {
		return home, nil
	}
	return filepath.Join(home, p[2:]), nil
}

// resolveKeySize picks the effective key-file size from the -cks/--key-size
// short and long aliases. When both are set the short alias wins, matching the
// firstNonEmpty short-alias-wins rule used for the other merged flag pairs
// (rather than relying on flag.Visit's lexicographic iteration order).
func resolveKeySize(shortSet bool, shortVal int, longSet bool, longVal int, dflt int) (int, bool) {
	if shortSet {
		return shortVal, true
	}
	if longSet {
		return longVal, true
	}
	return dflt, false
}

// sameFilePath reports whether two paths refer to the same file. Resolving
// both to absolute, cleaned paths makes a relative and an absolute spelling of
// the same file collide (e.g. "c.img" vs "/work/c.img"), which a plain string
// comparison would miss. When a path exists, the whole path is resolved through
// symlinks (e.g. /var -> /private/var on macOS, or a key file that is itself a
// symlink to the container); when the leaf does not exist yet (a container
// being created), the parent directory is resolved instead so two spellings of
// one location still compare equal.
func sameFilePath(a, b string) bool {
	canonical := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return filepath.Clean(p)
		}
		if eval, evalErr := filepath.EvalSymlinks(abs); evalErr == nil {
			return eval
		}
		if dir := filepath.Dir(abs); dir != "" && dir != "." {
			if eval, evalErr := filepath.EvalSymlinks(dir); evalErr == nil {
				return filepath.Join(eval, filepath.Base(abs))
			}
		}
		return abs
	}
	return canonical(a) == canonical(b)
}

// checkKeyFile verifies that path exists and is not a directory, so a LUKS key
// (passphrase-less) fails with a clear message before any mapping is opened or
// a container file is grown rather than with a cryptic cryptsetup error.
func checkKeyFile(path, what string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s %q does not exist", what, path)
		}
		return fmt.Errorf("checking %s %q: %w", what, path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s %q is a directory", what, path)
	}
	if fi.Mode()&os.ModeNamedPipe != 0 || fi.Mode()&os.ModeSocket != 0 {
		// A key file must be a seekable regular file. cryptsetup would open a
		// FIFO/socket key for reading and block forever waiting for a writer,
		// so reject it before any mapping is opened or container is grown.
		return fmt.Errorf("%s %q is not a regular file", what, path)
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		// A character device (e.g. /dev/random) yields fresh bytes on every
		// read, so it can never match an existing keyslot and would fail
		// cryptically only after a privileged luksOpen. Block devices stay
		// allowed: a raw partition is a legitimate, stable key source.
		return fmt.Errorf("%s %q is a character device, not a regular file", what, path)
	}
	if fi.Mode().IsRegular() && fi.Size() == 0 {
		// A zero-length key file can never authenticate a LUKS device; reject
		// it before luksOpen returns its cryptic "no key available" error.
		return fmt.Errorf("%s %q is empty", what, path)
	}
	return nil
}

func removeIfEmpty(path string) error {
	if path == string(filepath.Separator) {
		fmt.Printf("Skipping removal of filesystem root %s.\n", path)
		return nil
	}
	cwdInfo, cwdErr := os.Stat(".")
	pathInfo, pathErr := os.Stat(path)
	if cwdErr == nil && pathErr == nil && os.SameFile(cwdInfo, pathInfo) {
		fmt.Printf("Skipping removal of current working directory %s.\n", path)
		return nil
	}
	if home, err := userHomeDir(); err == nil && home != "" {
		if homeInfo, homeErr := os.Stat(home); homeErr == nil && pathErr == nil && os.SameFile(homeInfo, pathInfo) {
			// A mount point set to the user's home directory must never be
			// removed by an unmount; even an empty home is not lmount's to
			// delete.
			fmt.Printf("Skipping removal of home directory %s.\n", path)
			return nil
		}
	}
	if pathErr == nil && !pathInfo.IsDir() {
		// The path exists but is not a directory (e.g. an unexpected mount
		// target that resolved elsewhere); there is nothing to remove.
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The mount point is already gone (e.g. a stale findmnt snapshot
			// or a concurrent unmount); nothing to remove.
			return nil
		}
		return err
	}
	if len(entries) > 0 {
		fmt.Printf("Mount point %s not empty, keeping it.\n", path)
		return nil
	}
	fmt.Printf("Removing mount point %s...\n", path)
	return os.Remove(path)
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid size %q: too short", s)
	}
	suffix := strings.ToUpper(s[len(s)-1:])
	numStr := s[:len(s)-1]

	if numStr != "" && (numStr[0] == '+' || numStr[0] == '-') {
		return 0, fmt.Errorf("invalid size %q: must be a positive integer with suffix M or G", s)
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if num <= 0 {
		return 0, fmt.Errorf("invalid size %q: must be positive", s)
	}

	switch suffix {
	case "M":
		if num > math.MaxInt64/(1024*1024) {
			return 0, fmt.Errorf("invalid size %q: too large", s)
		}
		return num * 1024 * 1024, nil
	case "G":
		if num > math.MaxInt64/(1024*1024*1024) {
			return 0, fmt.Errorf("invalid size %q: too large", s)
		}
		return num * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid size %q: suffix must be M or G", s)
	}
}

func calcBlockSize(total int64) int64 {
	switch {
	case total <= _1G:
		bsMib := (total + _1M - 1) / _1M
		if bsMib > 32 {
			bsMib = 32
		}
		if bsMib < 1 {
			bsMib = 1
		}
		return bsMib * _1M
	case total <= 10*_1G:
		return 256 * _1M
	case total <= 100*_1G:
		return 512 * _1M
	default:
		return 1024 * _1M
	}
}

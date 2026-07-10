package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

var runCmd = func(name string, args ...string) error {
	cmd := exec.Command("sudo", append([]string{name}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

var runOutput = func(name string, args ...string) ([]byte, error) {
	cmd := exec.Command("sudo", append([]string{name}, args...)...)
	cmd.Stderr = io.Discard
	return cmd.Output()
}

var isLuks = func(source string) bool {
	cmd := exec.Command("sudo", "cryptsetup", "isLuks", source)
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

var checkMapped = func(name string) bool {
	_, err := os.Stat("/dev/mapper/" + name)
	return err == nil
}

func srcName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
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

func openAndMount(source, keyFile, mountPoint string) (err error) {
	name := srcName(source)
	encrypted := isLuks(source)

	if encrypted {
		args := []string{"luksOpen"}
		if keyFile != "" {
			args = append(args, "--key-file", keyFile)
		}
		args = append(args, source, name)
		if err := runCmd("cryptsetup", args...); err != nil {
			return fmt.Errorf("cryptsetup luksOpen failed: %w", err)
		}
	}

	opened := encrypted
	defer func() {
		if opened {
			runCmd("cryptsetup", "luksClose", name)
		}
	}()

	if mountPoint == "" {
		if name == "" {
			return fmt.Errorf("cannot infer mount point name from empty source")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("getting home dir: %w", err)
		}
		mountPoint = filepath.Join(home, name)
	}

	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("creating mountpoint: %w", err)
	}

	device := source
	if encrypted {
		device = "/dev/mapper/" + name
	}
	if err := runCmd("mount", device, mountPoint); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}

	current, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot determine current user: %v\n", err)
	} else {
		if err := runCmd("chown", current.Uid+":"+current.Gid, mountPoint); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not set ownership: %v\n", err)
		}
	}

	opened = false
	return nil
}

func umountAndClose(source string) error {
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
		if search == source && !strings.Contains(source, "/") {
			search = "/dev/" + name
		}
	}

	out, _ := runOutput("findmnt", "-n", "-l", "-o", "TARGET", "-S", search)
	mounts := strings.Split(strings.TrimSpace(string(out)), "\n")

	var errs []string
	for _, m := range mounts {
		if m == "" {
			continue
		}
		if err := runCmd("umount", m); err != nil {
			errs = append(errs, fmt.Sprintf("umount %s: %v", m, err))
			continue
		}
		if err := os.Remove(m); err != nil {
			errs = append(errs, fmt.Sprintf("rmdir %s: %v", m, err))
		}
	}

	if encrypted {
		if err := runCmd("cryptsetup", "luksClose", name); err != nil {
			errs = append(errs, fmt.Sprintf("luksClose: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: lmount [flags] -s <source>\n\n")
	fmt.Fprintf(os.Stderr, "Mount a device or file (auto-detects LUKS encryption):\n")
	fmt.Fprintf(os.Stderr, "  lmount -s <source> [-k <keyfile>] [-m <mountpoint>]\n\n")
	fmt.Fprintf(os.Stderr, "Unmount and close:\n")
	fmt.Fprintf(os.Stderr, "  lmount -u -s <source>\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func main() {
	keyFile := flag.String("k", "", "Path to key file")
	keyFileLong := flag.String("key", "", "Path to key file")
	mountPoint := flag.String("m", "", "Mount point (default: ~/<source basename>)")
	mountPointLong := flag.String("mount", "", "Mount point (default: ~/<source basename>)")
	umount := flag.Bool("u", false, "Unmount and close")
	umountLong := flag.Bool("umount", false, "Unmount and close")
	sourceFlag := flag.String("s", "", "Source device or file")
	sourceFlagLong := flag.String("source", "", "Source device or file")
	help := flag.Bool("h", false, "Show help")
	helpLong := flag.Bool("help", false, "Show help")

	flag.Usage = usage
	flag.Parse()

	if *help || *helpLong {
		usage()
		os.Exit(0)
	}

	if *keyFile == "" {
		*keyFile = *keyFileLong
	}
	if *mountPoint == "" {
		*mountPoint = *mountPointLong
	}
	source := *sourceFlag
	if source == "" {
		source = *sourceFlagLong
	}
	*umount = *umount || *umountLong

	if source == "" {
		usage()
		os.Exit(1)
	}
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "Error: unexpected positional argument(s): %s\n", strings.Join(flag.Args(), " "))
		os.Exit(1)
	}

	if *umount {
		if err := umountAndClose(source); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fullSrc := resolveSource(source)
	if err := openAndMount(fullSrc, *keyFile, *mountPoint); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

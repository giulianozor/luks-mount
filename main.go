package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

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
	cmd.Stderr = io.Discard
	return cmd.Output()
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

func removeIfEmpty(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
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

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if num <= 0 {
		return 0, fmt.Errorf("invalid size %q: must be positive", s)
	}

	switch suffix {
	case "M":
		return num * 1024 * 1024, nil
	case "G":
		return num * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid size %q: suffix must be M or G", s)
	}
}

func createContainer(runSudo, runDirect func(name string, args ...string) error, name, size, keyFile string, keySize int) error {
	total, err := parseSize(size)
	if err != nil {
		return err
	}

	const minSize = int64(32 * 1024 * 1024)
	if total < minSize {
		return fmt.Errorf("minimum container size is 32M, got %s", size)
	}

	const _1M = int64(1024 * 1024)
	const _1G = int64(1024 * 1024 * 1024)

	var blockSize int64
	switch {
	case total <= _1G:
		totalMib := (total + _1M - 1) / _1M
		bsMib := totalMib
		if bsMib > 32 {
			bsMib = 32
		}
		if bsMib < 1 {
			bsMib = 1
		}
		blockSize = bsMib * _1M
	case total <= 10*_1G:
		blockSize = 256 * _1M
	case total <= 100*_1G:
		blockSize = 512 * _1M
	default:
		blockSize = 1024 * _1M
	}
	count := (total + blockSize - 1) / blockSize

	if keyFile != "" {
		fmt.Printf("Creating key file %s...\n", keyFile)
		if err := runDirect("dd", "if=/dev/urandom", "of="+keyFile, fmt.Sprintf("bs=%d", keySize), "count=1"); err != nil {
			return fmt.Errorf("creating key file: %w", err)
		}
	}

	fmt.Printf("Creating container %s...\n", name)
	bsStr := fmt.Sprintf("%dM", blockSize/_1M)
	if err := runDirect("dd", "if=/dev/zero", "of="+name, "bs="+bsStr, fmt.Sprintf("count=%d", count), "status=progress"); err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	absPath, err := filepath.Abs(name)
	if err != nil {
		return fmt.Errorf("resolving container path: %w", err)
	}
	fmt.Printf("Formatting LUKS container %s...\n", absPath)
	if err := runDirect("cryptsetup", "luksFormat", "--batch-mode", name); err != nil {
		return fmt.Errorf("luksFormat failed: %w", err)
	}

	if keyFile != "" {
		fmt.Printf("Adding key file %s to LUKS container...\n", keyFile)
		if err := runDirect("cryptsetup", "luksAddKey", name, keyFile); err != nil {
			return fmt.Errorf("luksAddKey failed: %w", err)
		}
	}

	fmt.Printf("Opening LUKS container %s...\n", name)
	luksArgs := []string{"luksOpen"}
	if keyFile != "" {
		luksArgs = append(luksArgs, "--key-file", keyFile)
	}
	luksArgs = append(luksArgs, name, name)
	if err := runSudo("cryptsetup", luksArgs...); err != nil {
		return fmt.Errorf("luksOpen failed: %w", err)
	}

	fmt.Printf("Creating ext4 filesystem on /dev/mapper/%s...\n", name)
	if err := runSudo("mkfs.ext4", "-m", "0", "/dev/mapper/"+name); err != nil {
		runSudo("cryptsetup", "luksClose", name)
		return fmt.Errorf("mkfs.ext4 failed: %w", err)
	}

	fmt.Printf("Closing LUKS container %s...\n", name)
	if err := runSudo("cryptsetup", "luksClose", name); err != nil {
		return fmt.Errorf("luksClose failed: %w", err)
	}

	fmt.Println("Done.")
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
			return fmt.Errorf("cannot infer mount point name from empty source")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("getting home directory: %w", err)
		}
		mountPoint = filepath.Join(home, name)
	}

	if fi, err := os.Stat(mountPoint); err == nil && !fi.IsDir() {
		mountPoint += ".mnt"
	}

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
			luksClose(name)
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

func umountAndClose(checkMapped func(name string) bool, runCmd func(name string, args ...string) error, runOutput func(name string, args ...string) ([]byte, error), source string) error {
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

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: lmount [flags] -s <source>\n\n")
	fmt.Fprintf(os.Stderr, "Mount a device or file (auto-detects LUKS encryption):\n")
	fmt.Fprintf(os.Stderr, "  lmount -s <source> [-k <keyfile>] [-m <mountpoint>]\n\n")
	fmt.Fprintf(os.Stderr, "Unmount and close:\n")
	fmt.Fprintf(os.Stderr, "  lmount -u <source>\n\n")
	fmt.Fprintf(os.Stderr, "Create a LUKS container:\n")
	fmt.Fprintf(os.Stderr, "  lmount -c <name> -cs <size> [-ck <keyfile>] [-cks <key-size>]\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  -c, --create <name>    Create a LUKS container\n")
	fmt.Fprintf(os.Stderr, "  -cs, --size <size>     Container size with suffix M or G (e.g. 100M, 2G)\n")
	fmt.Fprintf(os.Stderr, "  -ck, --create-key-file <path>  Path for the LUKS key file to create\n")
	fmt.Fprintf(os.Stderr, "  -cks, --key-size <n>   Key file size in bytes (default: 512)\n")
	fmt.Fprintf(os.Stderr, "  -k, --key <file>       Path to key file\n")
	fmt.Fprintf(os.Stderr, "  -m, --mount <dir>      Mount point (default: ~/<source basename>)\n")
	fmt.Fprintf(os.Stderr, "  -u, --umount <source>  Source to unmount and close\n")
	fmt.Fprintf(os.Stderr, "  -s, --source <path>    Source device or file\n")
	fmt.Fprintf(os.Stderr, "  -h, --help             Show help\n")
}

func main() {
	keyFile := flag.String("k", "", "Path to key file")
	keyFileLong := flag.String("key", "", "Path to key file")
	mountPoint := flag.String("m", "", "Mount point (default: ~/<source basename>)")
	mountPointLong := flag.String("mount", "", "Mount point (default: ~/<source basename>)")
	umount := flag.String("u", "", "Source to unmount and close")
	umountLong := flag.String("umount", "", "Source to unmount and close")
	sourceFlag := flag.String("s", "", "Source device or file")
	sourceFlagLong := flag.String("source", "", "Source device or file")
	createFlag := flag.String("c", "", "Create a LUKS container")
	createFlagLong := flag.String("create", "", "Create a LUKS container")
	sizeFlag := flag.String("cs", "", "Container size with suffix M or G")
	sizeFlagLong := flag.String("size", "", "Container size with suffix M or G")
	createKeyFile := flag.String("ck", "", "Path for the LUKS key file to create")
	createKeyFileLong := flag.String("create-key-file", "", "Path for the LUKS key file to create")
	createKeySize := flag.Int("cks", 512, "Key file size in bytes")
	createKeySizeLong := flag.Int("key-size", 512, "Key file size in bytes")
	help := flag.Bool("h", false, "Show help")
	helpLong := flag.Bool("help", false, "Show help")

	flag.Usage = usage
	flag.Parse()

	if *help || *helpLong {
		usage()
		os.Exit(0)
	}

	*keyFile = firstNonEmpty(*keyFile, *keyFileLong)
	*mountPoint = firstNonEmpty(*mountPoint, *mountPointLong)
	createVal := firstNonEmpty(*createFlag, *createFlagLong)
	sizeVal := firstNonEmpty(*sizeFlag, *sizeFlagLong)
	keyFileVal := firstNonEmpty(*createKeyFile, *createKeyFileLong)
	keySizeVal := *createKeySize
	if *createKeySizeLong != 512 {
		keySizeVal = *createKeySizeLong
	}

	if createVal != "" {
		if sizeVal == "" {
			fmt.Fprintf(os.Stderr, "Error: -cs/--size is required with -c/--create\n")
			os.Exit(1)
		}
		if len(flag.Args()) > 0 {
			fmt.Fprintf(os.Stderr, "Error: unexpected positional argument(s): %s\n", strings.Join(flag.Args(), " "))
			os.Exit(1)
		}
		runDirect := func(name string, args ...string) error {
			cmd := exec.Command(name, args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
		if err := createContainer(runCmd, runDirect, createVal, sizeVal, keyFileVal, keySizeVal); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	source := strings.TrimRight(firstNonEmpty(*sourceFlag, *sourceFlagLong), "/")
	umountVal := strings.TrimRight(firstNonEmpty(*umount, *umountLong), "/")
	if umountVal != "" {
		source = umountVal
	}
	if source == "" {
		usage()
		os.Exit(1)
	}
	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "Error: unexpected positional argument(s): %s\n", strings.Join(flag.Args(), " "))
		os.Exit(1)
	}

	if umountVal != "" {
		if err := umountAndClose(checkMapped, runCmd, runOutput, source); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fullSrc := resolveSource(source)
	if err := openAndMount(runCmd, runOutput, fullSrc, *keyFile, *mountPoint); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// goos is the runtime operating system name; overridable for testing.
var goos = runtime.GOOS

func linuxOnlyError() error {
	if goos == "linux" {
		return nil
	}
	return fmt.Errorf("lmount is Linux-only (requires cryptsetup, mount, findmnt, and /dev/mapper); unsupported OS: %s", goos)
}

// fatal reports err on stderr and exits with status 1. It is the single
// error-reporting path for flag/argument validation and operation failures.
func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

// fatalMsg reports a formatted validation message on stderr and exits with
// status 1, matching fatal for plain-text flag-validation errors.
func fatalMsg(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(format, args...))
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: lmount [flags] -s <source>\n\n")
	fmt.Fprintf(os.Stderr, "Mount a device or file (auto-detects LUKS encryption):\n")
	fmt.Fprintf(os.Stderr, "  lmount -s <source> [-k <keyfile>] [-m <mountpoint>]\n\n")
	fmt.Fprintf(os.Stderr, "Unmount and close:\n")
	fmt.Fprintf(os.Stderr, "  lmount -u <source>\n\n")
	fmt.Fprintf(os.Stderr, "Create a LUKS container:\n")
	fmt.Fprintf(os.Stderr, "  lmount -c <name> -cs <size> [-ck <keyfile>] [-k <keyfile>] [-cks <key-size>]\n\n")
	fmt.Fprintf(os.Stderr, "Expand a LUKS container:\n")
	fmt.Fprintf(os.Stderr, "  lmount -x <filename> -xs <size> [-k <keyfile>]\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-c, --create <name>", "Create a LUKS container")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-cs, --size <size>", "Container size with suffix M or G (e.g. 100M, 2G)")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-ck, --create-key-file <path>", "Path for the LUKS key file to create")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-cks, --key-size <n>", "Key file size in bytes (default: 512; only with -ck)")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-x, --expand <file>", "Expand a LUKS container file")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-xs, --expand-size <size>", "Expand size with suffix M or G (e.g. 100M, 2G)")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-k, --key <file>", "Path to key file")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-m, --mount <dir>", "Mount point (default: ~/<source basename>)")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-u, --umount <source>", "Source to unmount and close")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-s, --source <path>", "Source device or file")
	fmt.Fprintf(os.Stderr, "  %-27s %s\n", "-h, --help", "Show help")
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
	expandFlag := flag.String("x", "", "Expand a LUKS container file")
	expandFlagLong := flag.String("expand", "", "Expand a LUKS container file")
	expandSizeFlag := flag.String("xs", "", "Expand size with suffix M or G")
	expandSizeFlagLong := flag.String("expand-size", "", "Expand size with suffix M or G")
	help := flag.Bool("h", false, "Show help")
	helpLong := flag.Bool("help", false, "Show help")

	flag.Usage = usage
	flag.Parse()

	if *help || *helpLong {
		usage()
		os.Exit(0)
	}

	if err := linuxOnlyError(); err != nil {
		fatal(err)
	}

	expandVal := trimTrailingSeparators(firstNonEmpty(*expandFlag, *expandFlagLong))
	expandSizeVal := firstNonEmpty(*expandSizeFlag, *expandSizeFlagLong)

	createVal := trimTrailingSeparators(firstNonEmpty(*createFlag, *createFlagLong))
	createPresent := createVal != ""
	umountPresent := firstNonEmpty(*umount, *umountLong) != ""
	mountPresent := firstNonEmpty(*sourceFlag, *sourceFlagLong) != ""

	ops := 0
	if expandVal != "" {
		ops++
	}
	if createPresent {
		ops++
	}
	if umountPresent {
		ops++
	}
	if mountPresent {
		ops++
	}
	if ops > 1 {
		fatalMsg("only one of -s/--source, -u/--umount, -c/--create, -x/--expand may be used")
	}

	if (*mountPoint != "" || *mountPointLong != "") && !mountPresent {
		fatalMsg("-m/--mount is only valid with -s/--source")
	}

	*keyFile = firstNonEmpty(*keyFile, *keyFileLong)
	// Normalize a trailing separator on an explicit mount point ("-m /mnt/x/"),
	// matching the source/umount/create/expand arguments. A root path ("/") is
	// preserved by trimTrailingSeparators and remains an explicit choice.
	*mountPoint = trimTrailingSeparators(firstNonEmpty(*mountPoint, *mountPointLong))
	sizeVal := firstNonEmpty(*sizeFlag, *sizeFlagLong)
	keyFileVal := firstNonEmpty(*createKeyFile, *createKeyFileLong)
	shortKeySizeSet := false
	longKeySizeSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cks":
			shortKeySizeSet = true
		case "key-size":
			longKeySizeSet = true
		}
	})
	keySizeVal, keySizeSet := resolveKeySize(shortKeySizeSet, *createKeySize, longKeySizeSet, *createKeySizeLong, 512)

	if sizeVal != "" && createVal == "" {
		fatalMsg("-cs/--size is only valid with -c/--create")
	}
	if keyFileVal != "" && createVal == "" {
		fatalMsg("-ck/--create-key-file is only valid with -c/--create")
	}
	if keySizeSet && createVal == "" {
		fatalMsg("-cks/--key-size is only valid with -c/--create")
	}
	if keySizeSet && keyFileVal == "" {
		fatalMsg("-cks/--key-size is only valid with -ck/--create-key-file")
	}

	if expandSizeVal != "" && expandVal == "" {
		fatalMsg("-xs/--expand-size is only valid with -x/--expand")
	}

	if expandVal != "" {
		if expandSizeVal == "" {
			fatalMsg("-xs/--expand-size is required with -x/--expand")
		}
		if len(flag.Args()) > 0 {
			fatalMsg("unexpected positional argument(s): %s", strings.Join(flag.Args(), " "))
		}
		if err := expandContainer(runCmd, runDirect, expandVal, expandSizeVal, *keyFile); err != nil {
			fatal(err)
		}
		return
	}

	if createVal != "" {
		if sizeVal == "" {
			fatalMsg("-cs/--size is required with -c/--create")
		}
		if len(flag.Args()) > 0 {
			fatalMsg("unexpected positional argument(s): %s", strings.Join(flag.Args(), " "))
		}
		if keyFileVal != "" && *keyFile != "" {
			fatalMsg("-ck/--create-key-file and -k/--key cannot be used together")
		}
		if err := createContainer(runCmd, runDirect, createVal, sizeVal, *keyFile, keyFileVal, keySizeVal); err != nil {
			fatal(err)
		}
		return
	}

	source := trimTrailingSeparators(firstNonEmpty(*sourceFlag, *sourceFlagLong))
	umountVal := trimTrailingSeparators(firstNonEmpty(*umount, *umountLong))
	if umountVal != "" {
		source = umountVal
	}
	if source == "" {
		usage()
		os.Exit(1)
	}
	if len(flag.Args()) > 0 {
		fatalMsg("unexpected positional argument(s): %s", strings.Join(flag.Args(), " "))
	}

	if umountVal != "" {
		if *keyFile != "" {
			fatalMsg("-k/--key is not valid with -u/--umount (closing a LUKS mapping needs no key)")
		}
		// -m/--mount is rejected earlier ("only valid with -s/--source"); the
		// umount mount point is always discovered from the running mount.
		if err := umountAndClose(checkMapped, runCmd, runOutputDirect, source); err != nil {
			fatal(err)
		}
		return
	}

	fullSrc := resolveSource(source)
	if err := openAndMount(runCmd, runOutput, fullSrc, *keyFile, *mountPoint); err != nil {
		fatal(err)
	}
}

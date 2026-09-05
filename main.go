package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// goos is the runtime operating system name; overridable for testing.
var goos = runtime.GOOS

// Operation seams: runMain dispatches through these variables so tests can
// substitute stubs and exercise runMain's success/failure exit-code wiring
// without ever invoking a privileged command (sudo cryptsetup, mount, dd).
var (
	expandOperation = expandContainer
	createOperation = createContainer
	umountOperation = umountAndClose
	mountOperation  = openAndMount
)

func linuxOnlyError() error {
	if goos == "linux" {
		return nil
	}
	return fmt.Errorf("lmount is Linux-only (requires cryptsetup, mount, findmnt, and /dev/mapper); unsupported OS: %s", goos)
}

// usageTo prints the full command help to w. usage() is the stderr variant
// shown on argument errors (and by the flag package on a parse failure); an
// explicit -h/--help request routes to stdout via usageTo(os.Stdout).
func usageTo(w io.Writer) {
	fmt.Fprintf(w, "Usage: lmount [flags] -s <source>\n\n")
	fmt.Fprintf(w, "Mount a device or file (auto-detects LUKS encryption):\n")
	fmt.Fprintf(w, "  lmount -s <source> [-k <keyfile>] [-m <mountpoint>]\n\n")
	fmt.Fprintf(w, "Unmount and close:\n")
	fmt.Fprintf(w, "  lmount -u <source>\n\n")
	fmt.Fprintf(w, "Create a LUKS container:\n")
	fmt.Fprintf(w, "  lmount -c <name> -cs <size> [-ck <keyfile>] [-k <keyfile>] [-cks <key-size>]\n\n")
	fmt.Fprintf(w, "Expand a LUKS container:\n")
	fmt.Fprintf(w, "  lmount -x <filename> -xs <size> [-k <keyfile>]\n\n")
	fmt.Fprintf(w, "Flags:\n")
	fmt.Fprintf(w, "  %-29s %s\n", "-c, --create <name>", "Create a LUKS container")
	fmt.Fprintf(w, "  %-29s %s\n", "-cs, --size <size>", "Container size with suffix M or G (e.g. 100M, 2G)")
	fmt.Fprintf(w, "  %-29s %s\n", "-ck, --create-key-file <path>", "Path for the LUKS key file to create")
	fmt.Fprintf(w, "  %-29s %s\n", "-cks, --key-size <n>", "Key file size in bytes, a multiple of 8 (default: 512; only with -ck)")
	fmt.Fprintf(w, "  %-29s %s\n", "-x, --expand <file>", "Expand a LUKS container file")
	fmt.Fprintf(w, "  %-29s %s\n", "-xs, --expand-size <size>", "Expand size with suffix M or G (e.g. 100M, 2G)")
	fmt.Fprintf(w, "  %-29s %s\n", "-k, --key <file>", "Path to key file")
	fmt.Fprintf(w, "  %-29s %s\n", "-m, --mount <dir>", "Mount point (default: ~/<source basename>)")
	fmt.Fprintf(w, "  %-29s %s\n", "-u, --umount <source>", "Source to unmount and close")
	fmt.Fprintf(w, "  %-29s %s\n", "-s, --source <path>", "Source device or file")
	fmt.Fprintf(w, "  %-29s %s\n", "-h, --help", "Show help")
	fmt.Fprintf(w, "\nNotes:\n")
	fmt.Fprintf(w, "  Path arguments expand a leading ~/ (or a bare ~) to your home directory.\n")
}

func usage() {
	usageTo(os.Stderr)
}

func main() {
	os.Exit(runMain(os.Args[1:]))
}

// fail prints err in the same "Error: ..." form the CLI always uses and
// reports the failure exit status to runMain's caller.
func fail(err error) int {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	return 1
}

// failMsg is fail for formatted plain-text validation messages, so the
// flag-validation failures use the same "Error: ..." prefix as everything else.
func failMsg(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(format, args...))
	return 1
}

// runMain parses args (the invocation arguments after the program name) on a
// fresh flag set and returns the process exit status, so the whole CLI surface
// is testable without a subprocess.
func runMain(args []string) int {
	fs := flag.NewFlagSet("lmount", flag.ContinueOnError)
	keyFile := fs.String("k", "", "Path to key file")
	keyFileLong := fs.String("key", "", "Path to key file")
	mountPoint := fs.String("m", "", "Mount point (default: ~/<source basename>)")
	mountPointLong := fs.String("mount", "", "Mount point (default: ~/<source basename>)")
	umount := fs.String("u", "", "Source to unmount and close")
	umountLong := fs.String("umount", "", "Source to unmount and close")
	sourceFlag := fs.String("s", "", "Source device or file")
	sourceFlagLong := fs.String("source", "", "Source device or file")
	createFlag := fs.String("c", "", "Create a LUKS container")
	createFlagLong := fs.String("create", "", "Create a LUKS container")
	sizeFlag := fs.String("cs", "", "Container size with suffix M or G")
	sizeFlagLong := fs.String("size", "", "Container size with suffix M or G")
	createKeyFile := fs.String("ck", "", "Path for the LUKS key file to create")
	createKeyFileLong := fs.String("create-key-file", "", "Path for the LUKS key file to create")
	createKeySize := fs.Int("cks", 512, "Key file size in bytes")
	createKeySizeLong := fs.Int("key-size", 512, "Key file size in bytes")
	expandFlag := fs.String("x", "", "Expand a LUKS container file")
	expandFlagLong := fs.String("expand", "", "Expand a LUKS container file")
	expandSizeFlag := fs.String("xs", "", "Expand size with suffix M or G")
	expandSizeFlagLong := fs.String("expand-size", "", "Expand size with suffix M or G")
	help := fs.Bool("h", false, "Show help")
	helpLong := fs.Bool("help", false, "Show help")

	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *help || *helpLong {
		// An explicit help request is not an error; print the usage to stdout
		// (the flag package and argument errors keep using stderr).
		usageTo(os.Stdout)
		return 0
	}

	if err := linuxOnlyError(); err != nil {
		return fail(err)
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
		return failMsg("only one of -s/--source, -u/--umount, -c/--create, -x/--expand may be used")
	}

	if (*mountPoint != "" || *mountPointLong != "") && !mountPresent {
		return failMsg("-m/--mount is only valid with -s/--source")
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
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cks":
			shortKeySizeSet = true
		case "key-size":
			longKeySizeSet = true
		}
	})
	keySizeVal, keySizeSet := resolveKeySize(shortKeySizeSet, *createKeySize, longKeySizeSet, *createKeySizeLong, 512)

	// A leading "~/" (or bare "~") in a path-taking argument would otherwise
	// create or probe a literal "~" path: "-m '~/data'" mounts at a literal
	// "~" directory, "-c '~/vault.img'" fails with a confusing "directory ~ does
	// not exist", and an explicit "-s '~/img'" just reports a missing "~" file.
	// Expand the home prefix uniformly so a shell-quoted argument resolves to
	// the user's home everywhere, not only for the mount point.
	for _, pf := range []struct {
		label string
		value *string
	}{
		{"-k/--key", keyFile},
		{"-m/--mount", mountPoint},
		{"-c/--create", &createVal},
		{"-x/--expand", &expandVal},
		{"-ck/--create-key-file", &keyFileVal},
	} {
		if *pf.value == "" {
			continue
		}
		expanded, err := expandHome(*pf.value)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", pf.label, err))
		}
		*pf.value = expanded
	}

	if sizeVal != "" && createVal == "" {
		return failMsg("-cs/--size is only valid with -c/--create")
	}
	if keyFileVal != "" && createVal == "" {
		return failMsg("-ck/--create-key-file is only valid with -c/--create")
	}
	if keySizeSet && createVal == "" {
		return failMsg("-cks/--key-size is only valid with -c/--create")
	}
	if keySizeSet && keyFileVal == "" {
		return failMsg("-cks/--key-size is only valid with -ck/--create-key-file")
	}
	if keySizeSet && keySizeVal%8 != 0 {
		// cryptsetup key sizes are whole bytes; a non-multiple-of-8 bit size
		// could never open any keyslot, and dd would have written a key file
		// of that absurd length before cryptsetup rejected it cryptically.
		// Reject the value up front while the failure is cheap to recover from.
		return failMsg("-cks/--key-size must be a multiple of 8, got %d", keySizeVal)
	}

	if expandSizeVal != "" && expandVal == "" {
		return failMsg("-xs/--expand-size is only valid with -x/--expand")
	}

	if expandVal != "" {
		if expandSizeVal == "" {
			return failMsg("-xs/--expand-size is required with -x/--expand")
		}
		if len(fs.Args()) > 0 {
			return failMsg("unexpected positional argument(s): %s", strings.Join(fs.Args(), " "))
		}
		if err := expandOperation(runCmd, runDirect, expandVal, expandSizeVal, *keyFile); err != nil {
			return fail(err)
		}
		return 0
	}

	if createVal != "" {
		if sizeVal == "" {
			return failMsg("-cs/--size is required with -c/--create")
		}
		if len(fs.Args()) > 0 {
			return failMsg("unexpected positional argument(s): %s", strings.Join(fs.Args(), " "))
		}
		if keyFileVal != "" && *keyFile != "" {
			return failMsg("-ck/--create-key-file and -k/--key cannot be used together")
		}
		if err := createOperation(runCmd, runDirect, createVal, sizeVal, *keyFile, keyFileVal, keySizeVal); err != nil {
			return fail(err)
		}
		return 0
	}

	source := trimTrailingSeparators(firstNonEmpty(*sourceFlag, *sourceFlagLong))
	umountVal := trimTrailingSeparators(firstNonEmpty(*umount, *umountLong))
	if umountVal != "" {
		source = umountVal
	}
	if source == "" {
		usage()
		return 1
	}
	// Expand a quoted "-s '~/img'" / "-u '~/mnt'" the same way the other path
	// arguments were expanded above (the umount/source locals are only computed
	// after the operation-specific validations).
	srcLabel := "-s/--source"
	if umountVal != "" {
		srcLabel = "-u/--umount"
	}
	if expanded, err := expandHome(source); err != nil {
		return fail(fmt.Errorf("%s: %w", srcLabel, err))
	} else {
		source = expanded
	}
	if len(fs.Args()) > 0 {
		return failMsg("unexpected positional argument(s): %s", strings.Join(fs.Args(), " "))
	}

	if umountVal != "" {
		if *keyFile != "" {
			return failMsg("-k/--key is not valid with -u/--umount (closing a LUKS mapping needs no key)")
		}
		// -m/--mount is rejected earlier ("only valid with -s/--source"); the
		// umount mount point is always discovered from the running mount.
		if err := umountOperation(checkMapped, runCmd, runOutputDirect, source); err != nil {
			return fail(err)
		}
		return 0
	}

	fullSrc := resolveSource(source)
	mp := *mountPoint // already expanded above
	if err := mountOperation(runCmd, runOutput, fullSrc, *keyFile, mp); err != nil {
		return fail(err)
	}
	return 0
}

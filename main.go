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

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: lmount [flags] -s <source>\n\n")
	fmt.Fprintf(os.Stderr, "Mount a device or file (auto-detects LUKS encryption):\n")
	fmt.Fprintf(os.Stderr, "  lmount -s <source> [-k <keyfile>] [-m <mountpoint>]\n\n")
	fmt.Fprintf(os.Stderr, "Unmount and close:\n")
	fmt.Fprintf(os.Stderr, "  lmount -u <source>\n\n")
	fmt.Fprintf(os.Stderr, "Create a LUKS container:\n")
	fmt.Fprintf(os.Stderr, "  lmount -c <name> -cs <size> [-ck <keyfile>] [-cks <key-size>] [-k <existing-keyfile>]\n\n")
	fmt.Fprintf(os.Stderr, "Expand a LUKS container:\n")
	fmt.Fprintf(os.Stderr, "  lmount -x <filename> -xs <size> [-k <keyfile>]\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  -c, --create <name>    Create a LUKS container\n")
	fmt.Fprintf(os.Stderr, "  -cs, --size <size>     Container size with suffix M or G (e.g. 100M, 2G)\n")
	fmt.Fprintf(os.Stderr, "  -ck, --create-key-file <path>  Path for the LUKS key file to create\n")
	fmt.Fprintf(os.Stderr, "  -cks, --key-size <n>   Key file size in bytes (default: 512)\n")
	fmt.Fprintf(os.Stderr, "  -x, --expand <file>    Expand a LUKS container file\n")
	fmt.Fprintf(os.Stderr, "  -xs, --expand-size <size>  Expand size with suffix M or G (e.g. 100M, 2G)\n")
	fmt.Fprintf(os.Stderr, "  -k, --key <file>       Path to key file\n")
	fmt.Fprintf(os.Stderr, "  -m, --mount <dir>      Mount point (default: ~/<source basename>)\n")
	fmt.Fprintf(os.Stderr, "  -u, --umount <source>  Source to unmount and close\n")
	fmt.Fprintf(os.Stderr, "  -s, --source <path>    Source device or file\n")
	fmt.Fprintf(os.Stderr, "  -h, --help             Show help\n")
}

func main() {
	if goos != "linux" {
		fmt.Fprintf(os.Stderr, "Error: lmount is Linux-only (requires cryptsetup, mount, findmnt, and /dev/mapper); unsupported OS: %s\n", goos)
		os.Exit(1)
	}

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

	expandVal := firstNonEmpty(*expandFlag, *expandFlagLong)
	expandSizeVal := firstNonEmpty(*expandSizeFlag, *expandSizeFlagLong)

	createPresent := firstNonEmpty(*createFlag, *createFlagLong) != ""
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
		fmt.Fprintf(os.Stderr, "Error: only one of -s/--source, -u/--umount, -c/--create, -x/--expand may be used\n")
		os.Exit(1)
	}

	if (*mountPoint != "" || *mountPointLong != "") && !mountPresent {
		fmt.Fprintf(os.Stderr, "Error: -m/--mount is only valid with -s/--source\n")
		os.Exit(1)
	}

	*keyFile = firstNonEmpty(*keyFile, *keyFileLong)
	*mountPoint = firstNonEmpty(*mountPoint, *mountPointLong)
	createVal := firstNonEmpty(*createFlag, *createFlagLong)
	sizeVal := firstNonEmpty(*sizeFlag, *sizeFlagLong)
	keyFileVal := firstNonEmpty(*createKeyFile, *createKeyFileLong)
	keySizeVal := 512
	keySizeSet := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "cks":
			keySizeVal = *createKeySize
			keySizeSet = true
		case "key-size":
			keySizeVal = *createKeySizeLong
			keySizeSet = true
		}
	})

	if sizeVal != "" && createVal == "" {
		fmt.Fprintf(os.Stderr, "Error: -cs/--size is only valid with -c/--create\n")
		os.Exit(1)
	}
	if keyFileVal != "" && createVal == "" {
		fmt.Fprintf(os.Stderr, "Error: -ck/--create-key-file is only valid with -c/--create\n")
		os.Exit(1)
	}
	if keySizeSet && createVal == "" {
		fmt.Fprintf(os.Stderr, "Error: -cks/--key-size is only valid with -c/--create\n")
		os.Exit(1)
	}
	if keySizeSet && keyFileVal == "" {
		fmt.Fprintf(os.Stderr, "Error: -cks/--key-size is only valid with -ck/--create-key-file\n")
		os.Exit(1)
	}

	if expandSizeVal != "" && expandVal == "" {
		fmt.Fprintf(os.Stderr, "Error: -xs/--expand-size is only valid with -x/--expand\n")
		os.Exit(1)
	}

	if expandVal != "" {
		if expandSizeVal == "" {
			fmt.Fprintf(os.Stderr, "Error: -xs/--expand-size is required with -x/--expand\n")
			os.Exit(1)
		}
		if len(flag.Args()) > 0 {
			fmt.Fprintf(os.Stderr, "Error: unexpected positional argument(s): %s\n", strings.Join(flag.Args(), " "))
			os.Exit(1)
		}
		*keyFile = firstNonEmpty(*keyFile, *keyFileLong)
		if err := expandContainer(runCmd, runDirect, expandVal, expandSizeVal, *keyFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
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
		if keyFileVal != "" && *keyFile != "" {
			fmt.Fprintf(os.Stderr, "Error: -ck/--create-key-file and -k/--key cannot be used together\n")
			os.Exit(1)
		}
		if err := createContainer(runCmd, runDirect, createVal, sizeVal, *keyFile, keyFileVal, keySizeVal); err != nil {
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
		if *keyFile != "" {
			fmt.Fprintf(os.Stderr, "Error: -k/--key is not valid with -u/--umount (closing a LUKS mapping needs no key)\n")
			os.Exit(1)
		}
		if err := umountAndClose(checkMapped, runCmd, runOutputDirect, source); err != nil {
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

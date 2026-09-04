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
	if path == string(filepath.Separator) {
		fmt.Printf("Skipping removal of filesystem root %s.\n", path)
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSrcName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/dev/__test_dev__", "__test_dev__"},
		{"__test_dev__", "__test_dev__"},
		{"/path/to/file.img", "file.img"},
		{"file.img", "file.img"},
		{"/", "/"},
		{"", ""},
	}
	for _, tt := range tests {
		got := srcName(tt.path)
		if got != tt.want {
			t.Errorf("srcName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestResolveSource(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		fp := resolveSource("")
		if fp != "" {
			t.Errorf("expected empty, got %q", fp)
		}
	})

	t.Run("existing file", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.img")
		if err := os.WriteFile(f, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		fp := resolveSource(f)
		if fp != f {
			t.Errorf("got %q, want %q", fp, f)
		}
	})

	t.Run("nonexistent falls back", func(t *testing.T) {
		fp := resolveSource("nonexistent")
		if fp != "nonexistent" {
			t.Errorf("got %q, want %q", fp, "nonexistent")
		}
	})
}

func TestCheckMapperName(t *testing.T) {
	tests := []struct {
		name string
		want error
	}{
		{"sda1", nil},
		{"container.img", nil},
		{"some-name_with.dots", nil},
		{".", fmt.Errorf("")},
		{"..", fmt.Errorf("")},
		{"/", fmt.Errorf("")},
		{"my container.img", fmt.Errorf("")},
		{"a\tb", fmt.Errorf("")},
		{"a\nb", fmt.Errorf("")},
		{"a/b", fmt.Errorf("")},
	}
	for _, tt := range tests {
		err := checkMapperName(tt.name)
		if (err != nil) != (tt.want != nil) {
			t.Errorf("checkMapperName(%q) error = %v, want error: %v", tt.name, err, tt.want != nil)
		}
	}
}

func TestSameFilePath(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	if err := os.MkdirAll(real, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"same absolute path", filepath.Join(real, "img"), filepath.Join(real, "img"), true},
		{"absolute and dot-slash spelling", filepath.Join(real, "img"), filepath.Join(real, ".", "img"), true},
		{"absolute and symlinked parent", filepath.Join(link, "img"), filepath.Join(real, "img"), true},
		{"symlinked parent with missing leaf", filepath.Join(link, "new"), filepath.Join(real, "new"), true},
		{"different leafs", filepath.Join(real, "a"), filepath.Join(real, "b"), false},
		{"empty vs non-empty", "", filepath.Join(real, "a"), false},
	}
	// A symlinked leaf that exists must resolve to the same file as the target:
	// a key file that is itself a symlink to the container should collide.
	target := filepath.Join(real, "container.img")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	leafLink := filepath.Join(real, "keylink.img")
	if err := os.Symlink(target, leafLink); err != nil {
		t.Fatal(err)
	}
	tests = append(tests,
		struct {
			name string
			a    string
			b    string
			want bool
		}{"symlinked leaf resolves to its target", leafLink, target, true},
		struct {
			name string
			a    string
			b    string
			want bool
		}{"symlinked leaf vs itself", leafLink, leafLink, true},
	)
	for _, tt := range tests {
		if got := sameFilePath(tt.a, tt.b); got != tt.want {
			t.Errorf("sameFilePath(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCalcBlockSize(t *testing.T) {
	miB := int64(1024 * 1024)
	giB := int64(1024 * 1024 * 1024)
	tests := []struct {
		name  string
		total int64
		want  int64
	}{
		{"zero clamps to 1M", 0, 1 * miB},
		{"under 1M is clamped to 1M", 1*miB - 1, 1 * miB},
		{"small tier uses whole MiB up to 32", 1 * miB, 1 * miB},
		{"small tier with remainder", 33 * miB, 32 * miB},
		{"small tier caps at 32M", 999 * miB, 32 * miB},
		{"1G stays in the small tier", 1 * giB, 32 * miB},
		{"just over 1G moves to 256M", 1*giB + 1, 256 * miB},
		{"10G stays at 256M", 10 * giB, 256 * miB},
		{"just over 10G moves to 512M", 10*giB + 1, 512 * miB},
		{"100G stays at 512M", 100 * giB, 512 * miB},
		{"just over 100G moves to 1024M", 100*giB + 1, 1024 * miB},
		{"large sizes use the 1G tier", 5 * 100 * giB, 1024 * miB},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calcBlockSize(tt.total); got != tt.want {
				t.Errorf("calcBlockSize(%d) = %d, want %d", tt.total, got, tt.want)
			}
		})
	}
}

func TestRemoveIfEmpty(t *testing.T) {
	t.Run("never removes filesystem root", func(t *testing.T) {
		err := removeIfEmpty(string(filepath.Separator))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("removes empty directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "empty")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := removeIfEmpty(dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Error("empty directory should have been removed")
		}
	})

	t.Run("ignores a non-directory path", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := removeIfEmpty(file); err != nil {
			t.Fatalf("expected non-directory to be ignored, got error: %v", err)
		}
		if _, statErr := os.Stat(file); os.IsNotExist(statErr) {
			t.Error("non-directory must not be removed")
		}
	})

	t.Run("keeps non-empty directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := removeIfEmpty(dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			t.Error("non-empty directory should not have been removed")
		}
	})

	t.Run("never removes current working directory", func(t *testing.T) {
		dir := t.TempDir()
		oldWd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer os.Chdir(oldWd)

		if err := removeIfEmpty(dir); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			t.Error("current working directory should not have been removed")
		}
	})

	t.Run("succeeds when the directory is already gone", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist")
		if err := removeIfEmpty(missing); err != nil {
			t.Fatalf("unexpected error for missing mount point: %v", err)
		}
	})
}

func TestTrimTrailingSeparators(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"a.img", "a.img"},
		{"a.img/", "a.img"},
		{"dir/a.img//", "dir/a.img"},
		{"/", "/"},
		{"//", "//"},
		{"", ""},
	}
	for _, tt := range tests {
		got := trimTrailingSeparators(tt.input)
		if got != tt.want {
			t.Errorf("trimTrailingSeparators(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolveKeySize(t *testing.T) {
	tests := []struct {
		name              string
		shortSet, longSet bool
		shortVal, longVal int
		want              int
		wantSet           bool
	}{
		{"neither set", false, false, 128, 256, 512, false},
		{"short only", true, false, 128, 256, 128, true},
		{"long only", false, true, 128, 256, 256, true},
		{"both set, short wins", true, true, 128, 256, 128, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotSet := resolveKeySize(tt.shortSet, tt.shortVal, tt.longSet, tt.longVal, 512)
			if got != tt.want || gotSet != tt.wantSet {
				t.Errorf("resolveKeySize() = (%d, %v), want (%d, %v)", got, gotSet, tt.want, tt.wantSet)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
		err   bool
	}{
		{"100M", 100 * 1024 * 1024, false},
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"1M", 1 * 1024 * 1024, false},
		{"256M", 256 * 1024 * 1024, false},
		{"", 0, true},
		{"M", 0, true},
		{"100", 0, true},
		{"100K", 0, true},
		{"-1M", 0, true},
		{"+1M", 0, true},
		{"100.5M", 0, true},
		{"100 M", 0, true},
		{"abcM", 0, true},
		{"0M", 0, true},
		{"999999999999999999G", 0, true},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("parseSize(%q) expected error, got %d", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseSize(%q) unexpected error: %v", tt.input, err)
			} else if got != tt.want {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		}
	}
}

func TestParseSizeRejectsByteOverflow(t *testing.T) {
	for _, input := range []string{"8589934592G", "8796093022208M"} {
		_, err := parseSize(input)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Errorf("parseSize(%q) expected a too-large error, got %v", input, err)
		}
	}
}

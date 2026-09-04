package main

import (
	"os"
	"path/filepath"
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

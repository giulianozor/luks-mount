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

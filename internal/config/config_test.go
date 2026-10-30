package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExpandsDatabaseURLAndReadsStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PW_TEST_DB", "postgres://localhost/edvora")
	write(t, dir, "database_url: ${PW_TEST_DB}\nstore: out/pathwise.db\n")

	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://localhost/edvora" {
		t.Errorf("database_url not expanded: %q", c.DatabaseURL)
	}
	if c.Store != "out/pathwise.db" {
		t.Errorf("store = %q", c.Store)
	}
}

func TestLoadMissingFileIsZeroConfig(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "" || c.Store != "" {
		t.Errorf("missing file should yield zero config, got %+v", c)
	}
}

func write(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

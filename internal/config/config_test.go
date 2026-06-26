package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFileUsesExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	if err := os.WriteFile(path, []byte("threads: 7\nscan_profile: passive\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Threads != 7 || cfg.ScanProfile != "passive" {
		t.Fatalf("explicit config not loaded: %#v", cfg)
	}
}

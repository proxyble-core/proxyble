package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRioDBDefaultHomeUsesOptRioDB(t *testing.T) {
	cfg := &Config{Data: map[string]map[string]string{}}

	if got := riodbInstallDir(cfg); got != "/opt" {
		t.Fatalf("riodbInstallDir default = %q, want /opt", got)
	}
	if got := riodbHome(cfg); got != "/opt/riodb" {
		t.Fatalf("riodbHome default = %q, want /opt/riodb", got)
	}
	if got := policySQLDir(cfg); got != "/opt/riodb/sql" {
		t.Fatalf("policySQLDir default = %q, want /opt/riodb/sql", got)
	}
}

func TestEnableRioDBConfigMigratesLegacyInstallRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte("[riodb]\ninstall_dir=/opt/riodb-01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Path: path,
		Data: map[string]map[string]string{
			"riodb": {"install_dir": legacyDefaultRioDBInstallDir},
		},
	}

	if err := enableRioDBConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Get("riodb", "install_dir", ""); got != "/opt" {
		t.Fatalf("migrated install_dir = %q, want /opt", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "install_dir=/opt\n") {
		t.Fatalf("config file was not migrated:\n%s", data)
	}
}

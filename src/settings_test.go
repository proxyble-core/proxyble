package main

// settings_test.go covers runtime settings behavior that lets release metadata
// change without recompiling Proxyble.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRuntimeSettingsJavaPackageUsesDebianFallback ensures apt-based OS
// families use the default OpenJDK package.
func TestRuntimeSettingsJavaPackageUsesDebianFallback(t *testing.T) {
	settings := defaultRuntimeSettings()
	pkg, err := settings.JavaPackage(platformFamilyDebian)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "openjdk-17-jre-headless" {
		t.Fatalf("debian Java package = %q, want default OpenJDK package", pkg.Package)
	}
}

// TestRuntimeSettingsJavaPackageUsesAmazonOverride ensures Amazon Linux keeps
// the Corretto override.
func TestRuntimeSettingsJavaPackageUsesAmazonOverride(t *testing.T) {
	settings := defaultRuntimeSettings()
	pkg, err := settings.JavaPackage(platformFamilyAmazon)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "java-17-amazon-corretto-headless" {
		t.Fatalf("amazon Java package = %q, want Corretto package", pkg.Package)
	}
}

func TestRuntimeSettingsJavaPackageUsesRHELOverride(t *testing.T) {
	settings := defaultRuntimeSettings()
	pkg, err := settings.JavaPackage(platformFamilyRHEL)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "java-17-openjdk-headless" {
		t.Fatalf("rhel Java package = %q, want OpenJDK headless package", pkg.Package)
	}
}

func TestRuntimeSettingsJavaPackageUsesAzureOverride(t *testing.T) {
	settings := defaultRuntimeSettings()
	pkg, err := settings.JavaPackage(platformFamilyAzure)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "msopenjdk-17" {
		t.Fatalf("azure Java package = %q, want Microsoft OpenJDK package", pkg.Package)
	}
}

func TestRuntimeSettingsUsesCurrentRioDBArchive(t *testing.T) {
	settings := defaultRuntimeSettings()
	if settings.RioDB.ArchivePath != "riodb-lin-x86.2026-3.tar.gz" {
		t.Fatalf("RioDB archive path = %q, want current 2026-3 archive", settings.RioDB.ArchivePath)
	}
}

func TestRuntimeSettingsIncludesRioDBDownloadServers(t *testing.T) {
	settings := defaultRuntimeSettings()
	if len(settings.RioDB.DownloadServers) == 0 {
		t.Fatalf("default settings should include RioDB download servers")
	}
}

func TestRuntimeSettingsLoadsRioDBDownloadServers(t *testing.T) {
	root := t.TempDir()
	settingsPath := filepath.Join(root, "bin", defaultSettingsName)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{
  "riodb": {
    "archive_path": "riodb-test.tar.gz",
    "download_servers": ["http://downloads.example.test/riodb/"]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	settings, _, err := loadRuntimeSettings(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.RioDB.DownloadServers) != 1 || settings.RioDB.DownloadServers[0] != "http://downloads.example.test/riodb/" {
		t.Fatalf("download servers = %#v", settings.RioDB.DownloadServers)
	}
}

// Proxyble protects APIs, web applications, and TCP services.
// Copyright (C) 2026 Lucio D'Orazio Pedro de Matos
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package main

// settings_test.go covers dependency settings behavior that lets release metadata
// change without recompiling Proxyble.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDependencySettingsJavaPackageUsesDebianFallback ensures apt-based OS
// families use the default OpenJDK package.
func TestDependencySettingsJavaPackageUsesDebianFallback(t *testing.T) {
	settings := defaultDependencySettings()
	pkg, err := settings.JavaPackage(platformFamilyDebian)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "openjdk-17-jre-headless" {
		t.Fatalf("debian Java package = %q, want default OpenJDK package", pkg.Package)
	}
}

// TestDependencySettingsJavaPackageUsesAmazonOverride ensures Amazon Linux keeps
// the Corretto override.
func TestDependencySettingsJavaPackageUsesAmazonOverride(t *testing.T) {
	settings := defaultDependencySettings()
	pkg, err := settings.JavaPackage(platformFamilyAmazon)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "java-17-amazon-corretto-headless" {
		t.Fatalf("amazon Java package = %q, want Corretto package", pkg.Package)
	}
}

func TestDependencySettingsJavaPackageUsesRHELOverride(t *testing.T) {
	settings := defaultDependencySettings()
	pkg, err := settings.JavaPackage(platformFamilyRHEL)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "java-17-openjdk-headless" {
		t.Fatalf("rhel Java package = %q, want OpenJDK headless package", pkg.Package)
	}
}

func TestDependencySettingsJavaPackageUsesAzureOverride(t *testing.T) {
	settings := defaultDependencySettings()
	pkg, err := settings.JavaPackage(platformFamilyAzure)
	if err != nil {
		t.Fatalf("JavaPackage returned error: %v", err)
	}
	if pkg.Package != "msopenjdk-17" {
		t.Fatalf("azure Java package = %q, want Microsoft OpenJDK package", pkg.Package)
	}
}

func TestDependencySettingsUsesCurrentRioDBArchive(t *testing.T) {
	settings := defaultDependencySettings()
	if settings.Dependencies.RioDB.ArchivePath != "riodb-lin-x86.2026-3.tar.gz" {
		t.Fatalf("RioDB archive path = %q, want current 2026-3 archive", settings.Dependencies.RioDB.ArchivePath)
	}
}

func TestDependencySettingsIncludesRioDBDownloadServers(t *testing.T) {
	settings := defaultDependencySettings()
	if len(settings.Dependencies.RioDB.DownloadServers) == 0 {
		t.Fatalf("default settings should include RioDB download servers")
	}
}

func TestDependencySettingsLoadsRioDBDownloadServers(t *testing.T) {
	root := t.TempDir()
	settingsPath := filepath.Join(root, "bin", defaultDependenciesName)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{
  "dependencies": {
    "haproxy": {
      "package": "haproxy",
      "min_version_supported": "2.8.0",
      "max_version_exclusive": "3.1.0"
    },
    "riodb": {
    "archive_path": "riodb-test.tar.gz",
    "download_servers": ["http://downloads.example.test/riodb/"]
  }
  }
}`
	if err := os.WriteFile(settingsPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	settings, _, err := loadDependencySettings(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.Dependencies.RioDB.DownloadServers) != 1 || settings.Dependencies.RioDB.DownloadServers[0] != "http://downloads.example.test/riodb/" {
		t.Fatalf("download servers = %#v", settings.Dependencies.RioDB.DownloadServers)
	}
}

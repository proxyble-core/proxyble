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

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDependencySettings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bin", defaultDependenciesName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{
  "dependencies": {
    "haproxy": {
      "package": "haproxy",
      "min_version_supported": "2.8.0",
      "max_version_exclusive": "3.1.0"
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	settings, loadedPath, err := loadDependencySettings(root)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != path {
		t.Fatalf("loaded path = %q, want %q", loadedPath, path)
	}
	for _, version := range []string{"HAProxy version 2.8.0", "2.9.9-1", "3.0.25"} {
		supported, err := settings.Dependencies.HAProxy.supports(version)
		if err != nil || !supported {
			t.Fatalf("version %q supported = %v, err = %v", version, supported, err)
		}
	}
	for _, version := range []string{"2.7.99", "3.1.0"} {
		supported, err := settings.Dependencies.HAProxy.supports(version)
		if err != nil {
			t.Fatal(err)
		}
		if supported {
			t.Fatalf("version %q should not be supported", version)
		}
	}
}

func TestDependencySettingsRejectsInvalidRange(t *testing.T) {
	settings := testDependencySettings()
	settings.Dependencies.HAProxy.MinVersionSupported = "3.1.0"
	if err := settings.validate(); err == nil {
		t.Fatal("expected invalid HAProxy version range to fail")
	}
}

func TestPackageVersionParsers(t *testing.T) {
	apt := parseAPTPackageVersions(" haproxy | 3.0.25-1 | http://example.test stable/main amd64 Packages\n", "haproxy")
	if len(apt) != 1 || apt[0] != "3.0.25-1" {
		t.Fatalf("apt versions = %#v", apt)
	}
	rpm := parseRPMPackageVersions("Available Packages\nhaproxy.x86_64 3.0.25-1.el9 appstream\n", "haproxy")
	if len(rpm) != 1 || rpm[0] != "3.0.25-1.el9" {
		t.Fatalf("rpm versions = %#v", rpm)
	}
}

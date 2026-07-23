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

// system_test.go covers filesystem helper behavior from system.go. The current
// tests focus on safe binary installation because Proxyble may copy the running
// executable over an installed path during local staging.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformFromOSReleaseSupportedFamilies(t *testing.T) {
	has := fakeCommandDetector("apt-get", "dnf", "tdnf", "yum")
	tests := []struct {
		name    string
		values  map[string]string
		family  string
		manager string
	}{
		{
			name:    "ubuntu",
			values:  map[string]string{"ID": "ubuntu", "ID_LIKE": "debian", "PRETTY_NAME": "Ubuntu 24.04", "VERSION_CODENAME": "noble"},
			family:  platformFamilyDebian,
			manager: "apt-get",
		},
		{
			name:    "debian",
			values:  map[string]string{"ID": "debian", "PRETTY_NAME": "Debian GNU/Linux 12"},
			family:  platformFamilyDebian,
			manager: "apt-get",
		},
		{
			name:    "amazon",
			values:  map[string]string{"ID": "amzn", "ID_LIKE": "fedora", "PRETTY_NAME": "Amazon Linux 2023"},
			family:  platformFamilyAmazon,
			manager: "dnf",
		},
		{
			name:    "rhel",
			values:  map[string]string{"ID": "rhel", "ID_LIKE": "fedora", "PRETTY_NAME": "Red Hat Enterprise Linux 9"},
			family:  platformFamilyRHEL,
			manager: "dnf",
		},
		{
			name:    "oracle",
			values:  map[string]string{"ID": "ol", "ID_LIKE": "fedora", "PRETTY_NAME": "Oracle Linux Server 9"},
			family:  platformFamilyRHEL,
			manager: "dnf",
		},
		{
			name:    "almalinux",
			values:  map[string]string{"ID": "almalinux", "ID_LIKE": "rhel centos fedora", "PRETTY_NAME": "AlmaLinux 9"},
			family:  platformFamilyRHEL,
			manager: "dnf",
		},
		{
			name:    "rocky",
			values:  map[string]string{"ID": "rocky", "ID_LIKE": "rhel centos fedora", "PRETTY_NAME": "Rocky Linux 9"},
			family:  platformFamilyRHEL,
			manager: "dnf",
		},
		{
			name:    "azure",
			values:  map[string]string{"ID": "azurelinux", "PRETTY_NAME": "Microsoft Azure Linux 3.0"},
			family:  platformFamilyAzure,
			manager: "tdnf",
		},
		{
			name:    "id_like_debian",
			values:  map[string]string{"ID": "pop", "ID_LIKE": "ubuntu debian", "PRETTY_NAME": "Pop!_OS"},
			family:  platformFamilyDebian,
			manager: "apt-get",
		},
		{
			name:    "id_like_rhel",
			values:  map[string]string{"ID": "acme-linux", "ID_LIKE": "rhel fedora", "PRETTY_NAME": "Acme Linux"},
			family:  platformFamilyRHEL,
			manager: "dnf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := platformFromOSRelease(tt.values, has)
			if err != nil {
				t.Fatalf("platformFromOSRelease returned error: %v", err)
			}
			if p.Family != tt.family || p.PackageManager != tt.manager {
				t.Fatalf("platform = family %q manager %q, want family %q manager %q", p.Family, p.PackageManager, tt.family, tt.manager)
			}
			if tt.name == "ubuntu" && p.Codename != "noble" {
				t.Fatalf("platform codename = %q, want noble", p.Codename)
			}
		})
	}
}

func TestPlatformFromOSReleaseRejectsUnsupportedOrIncompleteHosts(t *testing.T) {
	if _, err := platformFromOSRelease(map[string]string{"ID": "clear-linux-os", "PRETTY_NAME": "Clear Linux OS"}, fakeCommandDetector("swupd")); err == nil {
		t.Fatalf("Clear Linux should require a dedicated adapter")
	}
	if _, err := platformFromOSRelease(map[string]string{"ID": "ubuntu", "PRETTY_NAME": "Ubuntu"}, fakeCommandDetector()); err == nil {
		t.Fatalf("ubuntu without apt-get should fail")
	}
	if _, err := platformFromOSRelease(map[string]string{"ID": "arch", "PRETTY_NAME": "Arch Linux"}, fakeCommandDetector("pacman")); err == nil {
		t.Fatalf("unsupported families should fail")
	}
}

func fakeCommandDetector(names ...string) func(string) bool {
	available := map[string]bool{}
	for _, name := range names {
		available[name] = true
	}
	return func(name string) bool {
		return available[name]
	}
}

func TestAPTNonInteractiveEnvironment(t *testing.T) {
	env := aptNonInteractiveEnv()
	for _, want := range []string{
		"DEBIAN_FRONTEND=noninteractive",
		"DEBIAN_PRIORITY=critical",
		"NEEDRESTART_MODE=a",
		"APT_LISTCHANGES_FRONTEND=none",
	} {
		found := false
		for _, got := range env {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("aptNonInteractiveEnv missing %q in %#v", want, env)
		}
	}
}

func TestAPTCommandArgsDisableDpkgPTYAndWaitForLock(t *testing.T) {
	got := aptCommandArgs("install", "-y", "haproxy")
	want := []string{"-o", "Dpkg::Use-Pty=0", "-o", "DPkg::Lock::Timeout=120", "install", "-y", "haproxy"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("aptCommandArgs = %#v, want %#v", got, want)
	}
}

func TestDNFPackageCommandsWaitForLock(t *testing.T) {
	binDir := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "dnf.log")
	dnfScript := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\n", commandLog)
	if err := os.WriteFile(filepath.Join(binDir, "dnf"), []byte(dnfScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	p := Platform{Family: platformFamilyRHEL, PackageManager: "dnf"}
	if err := packageInstall(context.Background(), p, &strings.Builder{}, "haproxy"); err != nil {
		t.Fatal(err)
	}
	if err := packageRemove(context.Background(), p, &strings.Builder{}, "haproxy"); err != nil {
		t.Fatal(err)
	}
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(commands), "--setopt=exit_on_lock=False"); got != 2 {
		t.Fatalf("DNF lock-wait option count = %d, want 2; commands:\n%s", got, commands)
	}
}

func TestPackageInstalledPropagatesPackageDatabaseFailure(t *testing.T) {
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "dpkg-query"), []byte("#!/bin/sh\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	installed, err := packageInstalled(context.Background(), Platform{Family: platformFamilyDebian}, "haproxy")
	if err == nil {
		t.Fatalf("package database failure returned installed=%v without an error", installed)
	}
}

func TestPackageMetadataSessionRefreshesOnlyOnce(t *testing.T) {
	binDir := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "apt-get.log")
	aptScript := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\n", commandLog)
	if err := os.WriteFile(filepath.Join(binDir, "apt-get"), []byte(aptScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	session := &packageMetadataSession{}
	p := Platform{PackageManager: "apt-get"}
	for i := 0; i < 2; i++ {
		if err := session.update(context.Background(), p, &strings.Builder{}); err != nil {
			t.Fatalf("package metadata refresh %d failed: %v", i+1, err)
		}
	}

	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(commands), "update"); got != 1 {
		t.Fatalf("apt-get update count = %d, want 1; commands:\n%s", got, commands)
	}
}

// TestCopyFileSamePathDoesNotRewrite protects against truncating the running
// binary when source and destination resolve to the same file.
func TestCopyFileSamePathDoesNotRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxyble")
	if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(path, path, 0o700); err != nil {
		t.Fatalf("copyFile same path failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "binary" {
		t.Fatalf("copyFile changed same-path contents: %q", data)
	}
}

func TestAtomicWriteFileRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(link, []byte("replace"), 0o600); err == nil {
		t.Fatalf("atomicWriteFile should reject symlink target")
	}
	data, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("atomicWriteFile followed symlink; real file = %q", data)
	}
}

func TestTouchFileRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := touchFile(link, 0o600); err == nil {
		t.Fatalf("touchFile should reject symlink target")
	}
}

func TestCopyFileRejectsDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, link, 0o600); err == nil {
		t.Fatalf("copyFile should reject symlink destination")
	}
	data, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("copyFile followed symlink; real file = %q", data)
	}
}

func TestChmodRecursiveRejectsSymlinkChild(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := chmodRecursive(dir, 0o700); err == nil {
		t.Fatalf("chmodRecursive should reject symlink children")
	}
}

func TestCreateAllocatedFileWritesRequestedSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allocated")
	if err := createAllocatedFile(path, 8192, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 8192 {
		t.Fatalf("allocated file size = %d, want 8192", info.Size())
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("allocated file mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestPreparePackageSwapFileRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "swap")
	if err := os.WriteFile(real, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := preparePackageSwapFile(context.Background(), nil, link, 8192); err == nil {
		t.Fatalf("preparePackageSwapFile should reject symlink targets")
	}
	data, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep" {
		t.Fatalf("preparePackageSwapFile followed symlink; real file = %q", data)
	}
}

func TestSafeRemovePathRejectsSymlinkParent(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	child := filepath.Join(real, "child")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := safeRemovePath(filepath.Join(link, "child"), ""); err == nil {
		t.Fatalf("safeRemovePath should reject paths through symlink parents")
	}
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("real child should remain: %v", err)
	}
}

func TestNormalizeRuleAgentPathsMigratesLegacyDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	body := "[rule_agent]\nrule_dir=/var/tmp/rules\nwatch_file=/var/tmp/rules/inbox.tmp\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := normalizeRuleAgentPaths(cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get("rule_agent", "rule_dir", ""); got != defaultRuleDir {
		t.Fatalf("rule_dir = %q, want %q", got, defaultRuleDir)
	}
	if got := reloaded.Get("rule_agent", "watch_file", ""); got != defaultRuleInbox {
		t.Fatalf("watch_file = %q, want %q", got, defaultRuleInbox)
	}
}

func TestRenderRuleAgentServiceIncludesSandboxing(t *testing.T) {
	body := renderRuleAgentService("/usr/local/bin/proxyble-rule-agent", "tcp", defaultRuleInbox)
	for _, want := range []string{
		"Type=oneshot",
		"User=root",
		"Group=root",
		"RuntimeDirectory=proxyble-rule-agent proxyble/locks",
		"RuntimeDirectoryMode=0700",
		"RuntimeDirectoryPreserve=yes",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN",
		"RestrictAddressFamilies=AF_UNIX AF_NETLINK",
		"IPAddressDeny=any",
		"ReadWritePaths=/var/spool/proxyble/rules",
		"ReadWritePaths=/var/lib/proxyble-rule-agent",
		"ReadWritePaths=/var/log/proxyble-rule-agent",
		"ReadWritePaths=/run/proxyble-rule-agent",
		"ReadWritePaths=/run/proxyble/locks",
		"ReadWritePaths=/etc/haproxy/maps",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rule-agent service is missing %q\n%s", want, body)
		}
	}
}

func TestRioDBHardeningModes(t *testing.T) {
	if got := riodbReadOnlyMode(os.ModeDir | 0o777); got != 0o750 {
		t.Fatalf("read-only directory mode = %#o, want 0750", got)
	}
	if got := riodbReadOnlyMode(0o755); got != 0o750 {
		t.Fatalf("read-only executable mode = %#o, want 0750", got)
	}
	if got := riodbReadOnlyMode(0o644); got != 0o640 {
		t.Fatalf("read-only file mode = %#o, want 0640", got)
	}
	if got := riodbWritableMode(os.ModeDir | 0o755); got != 0o700 {
		t.Fatalf("writable directory mode = %#o, want 0700", got)
	}
	if got := riodbWritableMode(0o755); got != 0o700 {
		t.Fatalf("writable executable mode = %#o, want 0700", got)
	}
	if got := riodbWritableMode(0o644); got != 0o600 {
		t.Fatalf("writable file mode = %#o, want 0600", got)
	}
}

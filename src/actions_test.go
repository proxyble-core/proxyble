package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicenseDisplayLinesIncludeOpenSourceNoticeAndRioDBEULA(t *testing.T) {
	root := t.TempDir()
	licenseDir := filepath.Join(root, "LICENSES")
	if err := os.Mkdir(licenseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(licenseDir, "GPL-2.0.txt"), []byte("GPLv2 text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := testAppWithRioDBArchive(t, root, "RioDB EULA body\n")

	lines, err := licenseDisplayLines(app)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n")
	for _, want := range []string{
		"Proxyble Core",
		"Purpose: Setup wizard, rule activation and state management",
		"License: GPLv2",
		"Notice: /opt/proxyble/LICENSES/GPL-2.0.txt",
		"Website: https://www.proxyble.com/",
		"HAProxy",
		"Website: https://www.haproxy.org/",
		"nftables / netfilter",
		"Website: https://www.nftables.org/",
		"RioDB",
		"Website: https://www.riodb.co/",
		"Java JDK: OpenJDK or Amazon Corretto",
		"Purpose: Java dependency required to run RioDB analytics",
		"Installed when: RioDB analytics is selected and no working Java runtime is already present",
		"Package: Java 17 headless runtime from the operating system package manager",
		"Distribution: OpenJDK Java 17 (headless)",
		"Settings: The exact Java version and package are configured in proxyble/bin/riodb-settings.json",
		"Notice: This dependency is not installed for Core only",
		"RioDB End User License Agreement:",
		"RioDB EULA body",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("license display missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "Distribution: Amazon Corretto") {
		t.Fatalf("default Java distribution should remain OpenJDK\n%s", body)
	}
}

func TestOpenSourceNoticeDisplayLinesExcludeRioDBEULA(t *testing.T) {
	root := t.TempDir()
	licenseDir := filepath.Join(root, "LICENSES")
	if err := os.Mkdir(licenseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(licenseDir, "GPL-2.0.txt"), []byte("GPLv2 text\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	lines, err := openSourceNoticeDisplayLines(&App{SourceRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n")
	for _, want := range []string{
		"Proxyble Core",
		"Purpose: Setup wizard, rule activation and state management",
		"HAProxy",
		"nftables / netfilter",
		"Website: https://www.proxyble.com/",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("open-source notices missing %q\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"RioDB", "RioDB End User License Agreement", "Java Runtime"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("open-source notices should not include %q\n%s", forbidden, body)
		}
	}
}

func TestRioDBLicenseDisplayLinesExcludeCoreNotices(t *testing.T) {
	root := t.TempDir()
	app := testAppWithRioDBArchive(t, root, "RioDB EULA body\n")

	lines, err := rioDBLicenseDisplayLines(app)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n")
	for _, want := range []string{
		"RioDB",
		"Purpose: Real-time analytics and policy workflows",
		"License: RioDB End User License Agreement",
		"LICENSES/RIODB-EULA.txt",
		"Website: https://www.riodb.co/",
		"Java JDK: OpenJDK or Amazon Corretto",
		"Installed when: RioDB analytics is selected and no working Java runtime is already present",
		"Settings: The exact Java version and package are configured in proxyble/bin/riodb-settings.json",
		"Notice: This dependency is not installed for Core only",
		"RioDB EULA body",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("RioDB license display missing %q\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"Proxyble Core", "HAProxy", "nftables"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("RioDB add-on notice should not include %q\n%s", forbidden, body)
		}
	}
}

func TestRioDBLicenseDisplayLinesCanOmitJavaNotice(t *testing.T) {
	root := t.TempDir()
	app := testAppWithRioDBArchive(t, root, "RioDB EULA body\n")

	lines, err := rioDBLicenseDisplayLinesWithJavaNotice(app, javaNoticeOptions{IncludeJava: false})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n")
	if !strings.Contains(body, "RioDB") || !strings.Contains(body, "RioDB EULA body") {
		t.Fatalf("RioDB notice and EULA should still be shown\n%s", body)
	}
	if strings.Contains(body, "Java JDK") || strings.Contains(body, "Amazon Corretto") {
		t.Fatalf("Java notice should be omitted only when explicitly disabled\n%s", body)
	}
}

func TestReadRioDBEULAFromArchiveRequiresEULA(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "bin", "riodb-test.tar.gz")
	writeTestTarGz(t, archivePath, map[string]string{
		"README.txt": "missing eula\n",
	})

	_, _, err := readRioDBEULAFromArchive(context.Background(), archivePath)
	if err == nil || !strings.Contains(err.Error(), "LICENSES/RIODB-EULA.txt") {
		t.Fatalf("missing EULA error = %v", err)
	}
}

func TestArchiveMemberMatchesRioDBRootFolderEULA(t *testing.T) {
	for _, member := range []string{
		"LICENSES/RIODB-EULA.txt",
		"./LICENSES/RIODB-EULA.txt",
		"riodb/LICENSES/RIODB-EULA.txt",
		"./riodb/LICENSES/RIODB-EULA.txt",
	} {
		if !archiveMemberMatches(member, rioDBEULAPath) {
			t.Fatalf("archive member %q should match %s", member, rioDBEULAPath)
		}
	}
	if archiveMemberMatches("riodb-old/LICENSES/OTHER.txt", rioDBEULAPath) {
		t.Fatalf("unrelated archive member should not match")
	}
}

func testAppWithRioDBArchive(t *testing.T, root, eula string) *App {
	t.Helper()
	archiveName := "riodb-test.tar.gz"
	writeTestTarGz(t, filepath.Join(root, "bin", archiveName), map[string]string{
		path.Join("riodb", rioDBEULAPath): eula,
	})
	return &App{
		SourceRoot: root,
		Settings: RuntimeSettings{RioDB: SettingsRioDB{
			ArchivePath: archiveName,
		}},
	}
}

func writeTestTarGz(t *testing.T, archivePath string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o600,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJavaNoticeOptionsForInstallHidesInstallNoticeWhenJavaExists(t *testing.T) {
	binDir := t.TempDir()
	javaPath := filepath.Join(binDir, "java")
	if err := os.WriteFile(javaPath, []byte("#!/bin/sh\nprintf '%s\\n' 'openjdk version \"17.0.10\"' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	notice := javaNoticeOptionsForInstall(context.Background(), &App{})
	if notice.IncludeJava {
		t.Fatalf("Java install notice should be hidden when a working java command exists")
	}
}

func TestJavaDependencyNoticeOptionsShowsDisclosureWhenJavaExists(t *testing.T) {
	binDir := t.TempDir()
	javaPath := filepath.Join(binDir, "java")
	if err := os.WriteFile(javaPath, []byte("#!/bin/sh\nprintf '%s\\n' 'openjdk version \"17.0.10\"' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	notice := javaDependencyNoticeOptions(context.Background(), &App{})
	if !notice.IncludeJava {
		t.Fatalf("Java dependency notice should be shown for RioDB review even when a working java command exists")
	}
}

func TestJavaRemovalCandidateAllowsKnownPackageWithoutProxybleOwnership(t *testing.T) {
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "java"), []byte("#!/bin/sh\nprintf '%s\\n' 'openjdk version \"17.0.10\"' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "dpkg-query"), []byte("#!/bin/sh\nprintf '%s' 'install ok installed'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	app := &App{Config: &Config{Data: map[string]map[string]string{
		"java": {"installed_by_proxyble": "false"},
	}}}
	if !javaRemovalCandidate(context.Background(), app, Platform{Family: platformFamilyDebian}) {
		t.Fatalf("known Java package should be offered for removal even when this install did not mark ownership")
	}
}

func TestJavaRemovalCandidateRejectsUnknownPackage(t *testing.T) {
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "java"), []byte("#!/bin/sh\nprintf '%s\\n' 'openjdk version \"17.0.10\"' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "dpkg-query"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	if javaRemovalCandidate(context.Background(), &App{}, Platform{Family: platformFamilyDebian}) {
		t.Fatalf("unknown Java package should not be offered for removal")
	}
}

func TestRioDBInstalledForRemovalUsesConfigAndFilesystemMarkers(t *testing.T) {
	if riodbInstalledForRemoval(&Config{Data: map[string]map[string]string{
		"riodb": {"enabled": "true"},
	}}) != true {
		t.Fatalf("enabled RioDB config should require Java removal choice")
	}

	root := t.TempDir()
	home := filepath.Join(root, "riodb")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if !riodbInstalledForRemoval(&Config{Data: map[string]map[string]string{
		"riodb": {"install_dir": root, "app_subdir": "riodb"},
	}}) {
		t.Fatalf("existing RioDB home should require Java removal choice")
	}
}

func TestPromptJavaRemovalRequiresExplicitChoiceWithAssumeYesCLI(t *testing.T) {
	_, err := promptJavaRemoval(&App{CommandLine: true, AssumeYes: true})
	if err == nil || !strings.Contains(err.Error(), "--remove-java or --keep-java") {
		t.Fatalf("promptJavaRemoval error = %v, want explicit Java choice requirement", err)
	}
}

// TestDefaultSelfSignedPEMPathUsesSubject keeps generated HTTPS PEM filenames
// recognizable from the hostname, FQDN, or IP selected by the operator.
func TestDefaultSelfSignedPEMPathUsesSubject(t *testing.T) {
	tests := map[string]string{
		"host.proxyble.com": "/etc/proxyble/host.proxyble.com-self-signed.pem",
		"10.10.10.10":       "/etc/proxyble/10.10.10.10-self-signed.pem",
		"Example-Host.":     "/etc/proxyble/example-host-self-signed.pem",
		"bad name.example":  "/etc/proxyble/bad-name.example-self-signed.pem",
		"....":              "/etc/proxyble/listener-self-signed.pem",
	}
	for subject, want := range tests {
		if got := defaultSelfSignedPEMPath(subject); got != want {
			t.Fatalf("defaultSelfSignedPEMPath(%q) = %q, want %q", subject, got, want)
		}
	}
}

// TestListenerCertificateMessageNamesCertificateType keeps HTTPS listener
// completion notices clear for generated and user-provided PEM bundles.
func TestListenerCertificateMessageNamesCertificateType(t *testing.T) {
	if got, want := listenerCertificateMessage("/etc/proxyble/host-self-signed.pem", true), "Listener configured with self-signed certificate /etc/proxyble/host-self-signed.pem"; got != want {
		t.Fatalf("self-signed listenerCertificateMessage = %q, want %q", got, want)
	}
	if got, want := listenerCertificateMessage("/etc/pki/example.pem", false), "Listener configured with provided certificate /etc/pki/example.pem"; got != want {
		t.Fatalf("provided listenerCertificateMessage = %q, want %q", got, want)
	}
}

func TestTrafficModeChangeNoticeSkipsFreshTemplateDefault(t *testing.T) {
	hasExisting := listenerConfigurationExists("", "", "tcp")
	if hasExisting {
		t.Fatalf("empty listener with default tcp mode should be treated as first-time setup")
	}
	if trafficModeChangedAfterExistingListener(hasExisting, "tcp", "https") {
		t.Fatalf("fresh HTTPS listener setup should not be described as a tcp-to-https change")
	}
	if shouldPromptRuleResetForModeChange(hasExisting, false, "tcp", "https") {
		t.Fatalf("fresh listener setup should not offer to reset active rules")
	}
}

func TestTrafficModeChangeResetPromptRequiresCompleteExistingRuntime(t *testing.T) {
	hasExisting := listenerConfigurationExists("80", "", "tcp")
	if !trafficModeChangedAfterExistingListener(hasExisting, "tcp", "https") {
		t.Fatalf("existing listener mode changes should be reported")
	}
	if shouldPromptRuleResetForModeChange(hasExisting, false, "tcp", "https") {
		t.Fatalf("incomplete runtime config should not offer to reset active rules")
	}
	if !shouldPromptRuleResetForModeChange(hasExisting, true, "tcp", "https") {
		t.Fatalf("complete existing runtime config should offer to reset active rules after mode change")
	}
}

func TestListenerConfiguredNoticeIncludesHTTPSCertificatePath(t *testing.T) {
	got := listenerConfiguredNotice("443", "30s", "/etc/proxyble/10.0.0.66-self-signed.pem")
	want := "Listener configured for port 443 with 30s timeout, and TLS certificate: /etc/proxyble/10.0.0.66-self-signed.pem"
	if got != want {
		t.Fatalf("listenerConfiguredNotice = %q, want %q", got, want)
	}
}

func TestValidateListenerCLIOptionsRequiresExplicitParameters(t *testing.T) {
	opts := listenerOptions{mode: "tcp", port: "80"}
	if _, err := validateListenerCLIOptions(&opts, "", "", "", ""); err == nil {
		t.Fatalf("listener CLI validation should require --timeout")
	}

	opts = listenerOptions{mode: "https", port: "443", timeout: "60s"}
	if _, err := validateListenerCLIOptions(&opts, "", "", "", ""); err == nil {
		t.Fatalf("HTTPS listener CLI validation should require certificate input")
	}
}

func TestValidateBackendCLIOptionsRequiresPrimaryBackend(t *testing.T) {
	opts := backendOptions{primaryHost: "127.0.0.1"}
	if _, _, err := validateBackendCLIOptions(opts, "80", "", ""); err == nil {
		t.Fatalf("backend CLI validation should require --primary-port")
	}
}

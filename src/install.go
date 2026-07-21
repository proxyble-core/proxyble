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

// install.go is the ordered installation and service-control engine. It turns
// the wizard's "install" intent into filesystem preparation, dependency
// installation, RioDB extraction, HAProxy/nftables setup, rule-agent systemd
// units, SQL asset sync, and start/stop workflows. Future maintainers should
// keep release-specific RioDB archive, download server, and Java package values
// in bin/riodb-settings.json when possible, not hardcoded in this file.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type installStep struct {
	label string
	fn    func() error
}

const serviceControlTimeoutSeconds = 60

// runInstall executes the selected Proxyble installation profile and records
// each step in the action log.
func runInstall(ctx context.Context, a *App) error {
	if err := a.PrepareLog("install"); err != nil {
		return err
	}
	defer a.CloseLog()
	profile := selectedInstallProfile(a)
	withRioDB := profileIncludesRioDB(profile)
	if !a.Silent {
		fmt.Printf("\n%s\n\n", installProfileTitle(profile))
	}
	fmt.Fprintln(a.LogFile, "[INFO] ========== STARTING HOST CONFIGURATION =================")
	fmt.Fprintf(a.LogFile, "[INFO] Install profile: %s\n", profile)
	p, err := detectPlatform()
	if err != nil {
		return err
	}
	packageSession := &packageMetadataSession{}
	fmt.Fprintf(a.LogFile, "[INFO] Detected platform: %s\n[INFO] OS family        : %s\n[INFO] Package manager  : %s\n", p.PrettyName, p.Family, p.PackageManager)
	steps := []installStep{
		{"Preparing filesystem", func() error { return prepareFilesystem(ctx, a) }},
	}
	if withRioDB {
		steps = append(steps,
			installStep{"Checking Java", func() error { return installJava(ctx, a, p, packageSession) }},
			installStep{"Installing RioDB", func() error { return installRioDB(ctx, a) }},
		)
	} else {
		steps = append(steps, installStep{"Refreshing package metadata", func() error { return packageSession.update(ctx, p, stepOutput(a)) }})
	}
	steps = append(steps,
		installStep{"Installing HAProxy", func() error { return installHAProxy(ctx, a, p, packageSession) }},
		installStep{"Configuring nftables", func() error { return configureNFTables(ctx, a, p, packageSession) }},
		installStep{"Configuring Proxyble Rule Agent", func() error { return configureRuleAgent(ctx, a, "") }},
	)
	if withRioDB {
		steps = append(steps, installStep{"Copying RioDB SQL templates", func() error { return syncRioDBSQL(a, "") }})
	} else {
		fmt.Fprintln(a.LogFile, "[NOTICE] RioDB analytics not selected; Java, RioDB, and SQL templates were skipped.")
	}
	for _, step := range steps {
		if err := runStep(a, step.label, step.fn); err != nil {
			return err
		}
	}
	if configIsTrue(a.Config.Get("haproxy", "enabled", "false")) {
		if err := runStep(a, "Starting services", func() error { return startServices(ctx, a) }); err != nil {
			return err
		}
	} else {
		if !a.Silent {
			fmt.Printf("  %-34s [%sSKIPPED%s]\n", "Starting services", colorDim, colorReset)
		}
		fmt.Fprintln(a.LogFile, "[NOTICE] Service start skipped; listener and backend configuration must be completed first.")
	}
	fmt.Fprintln(a.LogFile, "[INFO] ========== CONFIGURATION COMPLETE =================")
	if !a.Silent {
		fmt.Printf("\nComplete. Full log: %s\n", a.LogPath)
	}
	return nil
}

func selectedInstallProfile(a *App) installProfile {
	if a == nil {
		return installProfileFull
	}
	switch a.InstallProfile {
	case installProfileCore, installProfileFull:
		return a.InstallProfile
	}
	if a.Config != nil && a.ConfigFileExistedAtStart && !riodbEnabled(a.Config) {
		return installProfileCore
	}
	return installProfileFull
}

func profileIncludesRioDB(profile installProfile) bool {
	return profile != installProfileCore
}

func installProfileTitle(profile installProfile) string {
	if profile == installProfileCore {
		return "Proxyble Core installation"
	}
	return "Proxyble + RioDB installation"
}

func installProfileDescription(profile installProfile) string {
	if profile == installProfileCore {
		return "Install Proxyble Core for manual rule enforcement."
	}
	return "Install Proxyble Core plus RioDB analytics for dynamic protection."
}

func applyInstallProfileConfig(a *App, profile installProfile) error {
	if a == nil || a.Config == nil {
		return fmt.Errorf("configuration is not loaded")
	}
	if profileIncludesRioDB(profile) {
		return enableRioDBConfig(a.Config)
	}
	return disableRioDBConfig(a.Config)
}

// addRioDBAnalytics enables the commercial analytics component after a core
// install. It intentionally leaves the existing Proxyble/HAProxy/nftables setup
// intact and only adds the RioDB-dependent pieces.
func addRioDBAnalytics(ctx context.Context, a *App) error {
	if err := a.PrepareLog("[proxyble] Installation -> Add RioDB"); err != nil {
		return err
	}
	defer a.CloseLog()
	if !a.Silent {
		fmt.Printf("\nEnable RioDB analytics\n\n")
	}
	if riodbEnabled(a.Config) {
		a.Printf("[NOTICE] RioDB analytics is already enabled in %s.\n", defaultConfigFile)
		return nil
	}
	p, err := detectPlatform()
	if err != nil {
		return err
	}
	packageSession := &packageMetadataSession{}
	steps := []installStep{
		{"Enabling RioDB configuration", func() error { return enableRioDBConfig(a.Config) }},
		{"Checking Java", func() error { return installJava(ctx, a, p, packageSession) }},
		{"Installing RioDB", func() error { return installRioDB(ctx, a) }},
		{"Configuring Proxyble Rule Agent", func() error { return configureRuleAgent(ctx, a, "") }},
		{"Copying RioDB SQL templates", func() error { return syncRioDBSQL(a, "") }},
		{"Refreshing HAProxy RioDB logging", func() error {
			if !configIsTrue(a.Config.Get("haproxy", "enabled", "false")) {
				fmt.Fprintf(stepOutput(a), "[NOTICE] HAProxy is disabled in %s; UDP log sink will be applied after listener/backend configuration is complete.\n", a.Config.Path)
				return nil
			}
			return applyHAProxyIfEnabledWithPackageSession(ctx, a, p, packageSession)
		}},
	}
	for _, step := range steps {
		if err := runStep(a, step.label, step.fn); err != nil {
			return err
		}
	}
	if configIsTrue(a.Config.Get("haproxy", "enabled", "false")) {
		if err := runStep(a, "Starting services", func() error { return startServices(ctx, a) }); err != nil {
			return err
		}
	}
	if !a.Silent {
		fmt.Printf("\nRioDB analytics enabled. Full log: %s\n", a.LogPath)
	}
	return nil
}

// runStep wraps one install/uninstall step with consistent terminal status and
// log output.
func runStep(a *App, label string, fn func() error) error {
	fmt.Fprintf(a.LogFile, "\n[STEP] %s\n", label)
	err := fn()
	if err == nil {
		if !a.Silent {
			fmt.Printf("  %-34s [%sOK%s]\n", label, colorBlueLight, colorReset)
		}
		return nil
	}
	if !a.Silent {
		fmt.Printf("  %-34s [%sFAILED%s]\n", label, colorRed, colorReset)
		fmt.Printf("\n[ERROR] %s failed. Review log: %s\n", label, a.LogPath)
	}
	fmt.Fprintf(a.LogFile, "[ERROR] %s failed: %v\n", label, err)
	return err
}

// prepareFilesystem creates root-owned Proxyble directories, initial state
// files, config.ini, and the installed proxyble command.
func prepareFilesystem(ctx context.Context, a *App) error {
	out := stepOutput(a)
	printHR(out, 79)
	fmt.Fprintln(out, "[INFO] Starting controlled bootstrap session")
	fmt.Fprintln(out, "[INFO] Component : Proxyble Rule Agent Environment")
	fmt.Fprintln(out, "[INFO] Purpose   : Secure directory and state initialization")
	printHR(out, 79)
	for _, dir := range []string{"/etc/proxyble", defaultAllowListDir, "/var/lib/proxyble-rule-agent", "/var/log/proxyble-rule-agent"} {
		if err := mkdirOwned(dir, 0o700, "root", "root"); err != nil {
			return err
		}
	}
	if err := rejectSymlinkIfExists(filepath.Dir(defaultRuleDir)); err != nil {
		return err
	}
	if err := mkdirOwned(filepath.Dir(defaultRuleDir), 0o755, "root", "root"); err != nil {
		return err
	}
	cfg, _, err := initConfig(true)
	if err != nil {
		return err
	}
	a.Config = cfg
	if err := normalizeRuleAgentPaths(a.Config); err != nil {
		return err
	}
	if err := applyInstallProfileConfig(a, selectedInstallProfile(a)); err != nil {
		return err
	}
	for _, file := range []string{"/var/lib/proxyble-rule-agent/rule_state_nft.json", "/var/lib/proxyble-rule-agent/rule_state_haproxy.json", "/var/lib/proxyble-rule-agent/last_reload"} {
		if err := touchFile(file, 0o600); err != nil {
			return err
		}
		_ = chownPath(file, "root", "root")
	}
	if err := ensureBasicAllowListStore(); err != nil {
		return err
	}
	if err := ensureEndpointAllowListStore(); err != nil {
		return err
	}
	if err := mkdirAllNoSymlink("/usr/local/bin", 0o755); err != nil {
		return err
	}
	if err := installProxybleCommand(ctx, a); err != nil {
		return err
	}
	printHR(out, 79)
	fmt.Fprintln(out, " BOOTSTRAP STATUS - VERIFIED")
	printHR(out, 79)
	fmt.Fprintf(out, " Input Directory   : %s   (710 root:%s)\n", defaultRuleDir, ruleInboxGroup(a.Config))
	fmt.Fprintf(out, " Allow-list Sources: %s (600)\n", defaultBasicAllowListFile)
	fmt.Fprintf(out, " Allow-list Batch  : %s (600)\n", defaultBasicAllowListNFTFile)
	fmt.Fprintln(out, " State Directory   : /var/lib/proxyble-rule-agent    (700)")
	fmt.Fprintln(out, " Log Directory     : /var/log/proxyble-rule-agent      (700)")
	fmt.Fprintln(out, " Config File       : /etc/proxyble/config.ini (600)")
	fmt.Fprintln(out, " Binary Path       : /usr/local/bin")
	fmt.Fprintln(out, " Launcher          : /usr/local/bin/proxyble")
	fmt.Fprintln(out, " Application Path  : /opt/proxyble")
	fmt.Fprintln(out, " Ownership         : root:root")
	fmt.Fprintln(out, " Change Control    : APPLIED SUCCESSFULLY")
	printHR(out, 79)
	return nil
}

// normalizeRuleAgentPaths migrates legacy default handoff paths to the dedicated
// spool location while preserving operator-customized paths.
func normalizeRuleAgentPaths(c *Config) error {
	ruleDir := strings.TrimSpace(c.Raw("rule_agent", "rule_dir"))
	if ruleDir == "" || filepath.Clean(ruleDir) == legacyDefaultRuleDir {
		if err := c.Set("rule_agent", "rule_dir", defaultRuleDir); err != nil {
			return err
		}
	}
	watchFile := strings.TrimSpace(c.Raw("rule_agent", "watch_file"))
	if watchFile == "" || filepath.Clean(watchFile) == legacyDefaultRuleInbox {
		if err := c.Set("rule_agent", "watch_file", defaultRuleInbox); err != nil {
			return err
		}
	}
	return nil
}

// ensureRuleInbox creates the rule-agent handoff. When RioDB is enabled it can
// open and write the inbox file, but cannot create, delete, rename, or list
// files in the containing directory. Core-only installs keep the handoff
// root-only until RioDB is later enabled.
func ensureRuleInbox(c *Config) error {
	if err := normalizeRuleAgentPaths(c); err != nil {
		return err
	}
	ruleDir := c.Get("rule_agent", "rule_dir", defaultRuleDir)
	watchFile := c.Get("rule_agent", "watch_file", defaultRuleInbox)
	if filepath.Clean(filepath.Dir(watchFile)) != filepath.Clean(ruleDir) {
		return fmt.Errorf("rule_agent watch_file must live under rule_dir: %s is not in %s", watchFile, ruleDir)
	}
	if err := rejectSymlinkIfExists(filepath.Dir(ruleDir)); err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(ruleDir); err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(watchFile); err != nil {
		return err
	}
	if filepath.Clean(ruleDir) == defaultRuleDir {
		if err := mkdirOwned(filepath.Dir(ruleDir), 0o755, "root", "root"); err != nil {
			return err
		}
	}
	groupName := ruleInboxGroup(c)
	if err := mkdirOwned(ruleDir, 0o710, "root", groupName); err != nil {
		return err
	}
	f, err := openFileNoFollow(watchFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o620)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := chownPath(watchFile, "root", groupName); err != nil {
		return err
	}
	return chmodPath(watchFile, 0o620)
}

func ruleInboxGroup(c *Config) string {
	if riodbEnabled(c) {
		return riodbGroup(c)
	}
	return "root"
}

// installProxybleCommand installs the currently running Go binary plus bundled
// metadata/assets into the canonical Proxyble locations.
func installProxybleCommand(ctx context.Context, a *App) error {
	out := stepOutput(a)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	installRoot := a.Config.Get("proxyble", "install_dir", "/opt/proxyble")
	launcherPath := a.Config.Get("proxyble", "launcher_path", "/usr/local/bin/proxyble")
	if installRoot != "/opt/proxyble" {
		return fmt.Errorf("refusing unsupported Proxyble install root: %s", installRoot)
	}
	if launcherPath != "/usr/local/bin/proxyble" {
		return fmt.Errorf("refusing unsupported Proxyble launcher path: %s", launcherPath)
	}
	if err := mkdirAllNoSymlink(installRoot, 0o755); err != nil {
		return err
	}
	_ = chownPath(installRoot, "root", "root")
	if err := copyFile(exe, filepath.Join(installRoot, "proxyble"), 0o700); err != nil {
		return err
	}
	_ = chownPath(filepath.Join(installRoot, "proxyble"), "root", "root")
	if err := copyFile(exe, launcherPath, 0o755); err != nil {
		return err
	}
	_ = chownPath(launcherPath, "root", "root")
	for _, name := range []string{"README.md"} {
		src := filepath.Join(a.SourceRoot, name)
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(installRoot, name)
			if err := copyFile(src, dst, 0o600); err != nil {
				return err
			}
			_ = chownPath(dst, "root", "root")
		}
	}
	for _, stale := range []string{"PRODUCT-LAYOUT.md", "DESIGN.md"} {
		_ = os.Remove(filepath.Join(installRoot, stale))
	}
	srcLicenses := filepath.Join(a.SourceRoot, "LICENSES")
	st, err := os.Stat(srcLicenses)
	if err != nil {
		return fmt.Errorf("license bundle not found: %s", srcLicenses)
	}
	if !st.IsDir() {
		return fmt.Errorf("license bundle is not a directory: %s", srcLicenses)
	}
	dstLicenses := filepath.Join(installRoot, "LICENSES")
	if err := copyDir(srcLicenses, dstLicenses, nil); err != nil {
		return err
	}
	if err := chownRecursive(dstLicenses, "root", "root"); err != nil {
		return err
	}
	if err := chmodLicenseBundle(dstLicenses); err != nil {
		return err
	}
	for _, stale := range []string{"LICENSE", "NOTICE"} {
		_ = os.Remove(filepath.Join(installRoot, stale))
	}
	srcBin := filepath.Join(a.SourceRoot, "bin")
	if st, err := os.Stat(srcBin); err == nil && st.IsDir() {
		_ = copyDir(srcBin, filepath.Join(installRoot, "bin"), nil)
		_ = chownRecursive(filepath.Join(installRoot, "bin"), "root", "root")
		_ = chmodRecursive(filepath.Join(installRoot, "bin"), 0o700)
	}
	srcTemplates := filepath.Join(a.SourceRoot, "templates")
	if st, err := os.Stat(srcTemplates); err == nil && st.IsDir() {
		dstTemplates := filepath.Join(installRoot, "templates")
		if err := copyDir(srcTemplates, dstTemplates, nil); err != nil {
			return err
		}
		_ = chownRecursive(dstTemplates, "root", "root")
		_ = chmodTemplateBundle(dstTemplates)
	}
	if a.SettingsPath != "" {
		settingsDst := filepath.Join(installRoot, "bin", defaultSettingsName)
		_ = copyFile(a.SettingsPath, settingsDst, 0o600)
		_ = chownPath(settingsDst, "root", "root")
	}
	fmt.Fprintf(out, "[PASS] Proxyble command installed (%s)\n", launcherPath)
	if ctx != nil {
		_ = ctx.Err()
	}
	return nil
}

func chmodLicenseBundle(path string) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to chmod symlinked path: %s", p)
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Type() != 0 {
			return nil
		}
		return os.Chmod(p, 0o600)
	})
}

func chmodTemplateBundle(path string) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to chmod symlinked path: %s", p)
		}
		if d.IsDir() {
			return os.Chmod(p, 0o700)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Type() != 0 {
			return nil
		}
		return os.Chmod(p, 0o600)
	})
}

// installJava verifies an existing Java runtime or installs the settings-selected
// package only when this host does not already have Java available.
func installJava(ctx context.Context, a *App, p Platform, packageSession *packageMetadataSession) error {
	out := stepOutput(a)
	javaPkg, err := a.Settings.JavaPackage(p.Family)
	if err != nil {
		return err
	}
	existing := probeExistingJavaRuntime(ctx)
	ownedBefore := javaInstalledByProxyble(a.Config)
	printHR(out, 79)
	fmt.Fprintln(out, "[INFO] Starting controlled installation session")
	fmt.Fprintln(out, "[INFO] Component : Java Runtime Environment")
	fmt.Fprintf(out, "[INFO] Version   : %s\n", javaPkg.Label)
	fmt.Fprintf(out, "[INFO] Platform  : %s\n", p.PrettyName)
	printHR(out, 79)
	if existing.Available {
		if existing.VersionLine != "" {
			fmt.Fprintf(out, "[INFO] Detected  : %s\n", existing.VersionLine)
		}
		if ownedBefore {
			fmt.Fprintln(out, "[NOTICE] Proxyble-managed Java is already present; package installation skipped.")
		} else {
			fmt.Fprintln(out, "[NOTICE] Host Java runtime already present; package installation skipped.")
		}
		if err := setJavaInstalledByProxyble(a.Config, ownedBefore); err != nil {
			return err
		}
		fmt.Fprintln(out, "[PASS] Java runtime verification successful")
		return nil
	}
	if existing.Detail != "" {
		fmt.Fprintf(out, "[NOTICE] Existing Java runtime not usable: %s\n", existing.Detail)
	}
	fmt.Fprintln(out, "[INFO] Refreshing package metadata")
	if err := packageSession.update(ctx, p, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "[PASS] Package metadata refresh step completed")
	fmt.Fprintf(out, "[INFO] Installing %s\n", javaPkg.Label)
	if err := packageInstall(ctx, p, out, javaPkg.Package); err != nil {
		return err
	}
	fmt.Fprintln(out, "[PASS] Java package installation completed")
	fmt.Fprintln(out, "[INFO] Verifying Java installation")
	if err := runCommand(ctx, out, "java", "-version"); err != nil {
		return err
	}
	if err := setJavaInstalledByProxyble(a.Config, true); err != nil {
		return err
	}
	fmt.Fprintln(out, "[PASS] Java runtime verification successful")
	return nil
}

type javaRuntimeProbe struct {
	Available   bool
	VersionLine string
	Detail      string
}

func probeExistingJavaRuntime(ctx context.Context) javaRuntimeProbe {
	if ctx == nil {
		ctx = context.Background()
	}
	if !commandExists("java") {
		return javaRuntimeProbe{Detail: "java command not found"}
	}
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "java", "-version")
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	line := firstNonEmptyLine(buf.String())
	if err != nil {
		detail := fmt.Sprintf("java -version failed: %v", err)
		if line != "" {
			detail = fmt.Sprintf("%s (%v)", line, err)
		}
		return javaRuntimeProbe{VersionLine: line, Detail: detail}
	}
	return javaRuntimeProbe{Available: true, VersionLine: line}
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func setJavaInstalledByProxyble(c *Config, owned bool) error {
	if c == nil {
		return nil
	}
	value := "false"
	if owned {
		value = "true"
	}
	return c.Set("java", "installed_by_proxyble", value)
}

// installRioDB extracts the settings-selected RioDB archive, creates its
// configured user/group, and installs the systemd unit.
func installRioDB(ctx context.Context, a *App) error {
	out := stepOutput(a)
	home := riodbHome(a.Config)
	installDir := riodbInstallDir(a.Config)
	logDir := riodbLogDir(a.Config)
	userName := riodbUser(a.Config)
	groupName := riodbGroup(a.Config)
	serviceName := riodbServiceName(a.Config)
	if !groupExists(groupName) {
		if err := runCommand(ctx, out, "groupadd", "-r", groupName); err != nil {
			return err
		}
		fmt.Fprintf(out, "[PASS] Group '%s' created\n", groupName)
	} else {
		fmt.Fprintf(out, "[NOTICE] Group '%s' already exists\n", groupName)
	}
	if !userExists(userName) {
		if err := runCommand(ctx, out, "useradd", "-r", "-s", "/bin/false", "-d", home, "-g", groupName, userName); err != nil {
			return err
		}
		fmt.Fprintf(out, "[PASS] User '%s' created\n", userName)
	} else {
		fmt.Fprintf(out, "[NOTICE] User '%s' already exists\n", userName)
	}
	if st, err := os.Stat(home); err == nil && st.IsDir() {
		fmt.Fprintln(out, "[INFO] RioDB 1.0 found. Skipping archive extraction step.")
		if err := hardenRioDBFilesystem(a.Config); err != nil {
			return err
		}
		fmt.Fprintln(out, "[PASS] RioDB filesystem permissions hardened")
		return nil
	}
	archive, err := ensureRioDBArchive(ctx, a)
	if err != nil {
		return err
	}
	if _, _, err := readRioDBEULAFromArchive(ctx, archive); err != nil {
		return err
	}
	installRootMode := os.FileMode(0o700)
	if filepath.Clean(installDir) == defaultRioDBInstallDir {
		installRootMode = 0o755
	}
	if err := mkdirAllNoSymlink(installDir, installRootMode); err != nil {
		return err
	}
	if err := mkdirAllNoSymlink(logDir, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(out, "[INFO] Extracting RioDB archive to %s\n", installDir)
	if err := runCommand(ctx, out, "tar", "-xvf", archive, "-C", installDir); err != nil {
		return err
	}
	_ = os.Remove(riodbKeystorePath(a.Config))
	if err := runCommand(ctx, out, "keytool", "-genkeypair", "-keyalg", "RSA", "-alias", "selfsigned",
		"-keystore", riodbKeystorePath(a.Config),
		"-storepass", riodbKeystorePassword(a.Config),
		"-dname", riodbKeystoreDistinguishedName(a.Config)); err != nil {
		return err
	}
	if err := runCommand(ctx, out, riodbJVMOptionsScript(a.Config), riodbConfDir(a.Config)); err != nil {
		return err
	}
	if err := hardenRioDBFilesystem(a.Config); err != nil {
		return err
	}
	fmt.Fprintln(out, "[PASS] RioDB filesystem permissions hardened")
	service := fmt.Sprintf(`[Unit]
Description=RioDB
After=network.target

[Service]
WorkingDirectory=%s
ExecStart=%s/riodb.sh --accept-license --logger %s
Restart=on-failure
TimeoutStopSec=5s
KillMode=control-group

ProtectSystem=full
ProtectHome=yes
PrivateTmp=true
PrivateDevices=yes
NoNewPrivileges=yes

User=%s
Group=%s

MemoryDenyWriteExecute=no

[Install]
WantedBy=multi-user.target
`, home, home, riodbLoggerConfig(a.Config), userName, groupName)
	servicePath := filepath.Join("/etc/systemd/system", serviceName)
	if _, err := os.Stat(servicePath); os.IsNotExist(err) {
		if err := atomicWriteFile(servicePath, []byte(service), 0o644); err != nil {
			return err
		}
		if err := systemctl(ctx, out, "daemon-reload"); err != nil {
			return err
		}
		if err := systemctl(ctx, out, "enable", serviceName); err != nil {
			return err
		}
		fmt.Fprintln(out, "[PASS] systemd service registered and enabled")
	} else {
		fmt.Fprintf(out, "[NOTICE] Service file %s already exists - skipping creation\n", servicePath)
	}
	return nil
}

// hardenRioDBFilesystem keeps RioDB's executable/application tree read-only to
// the RioDB service user while preserving the writable areas RioDB needs for
// operator-authored SQL objects and runtime logs.
func hardenRioDBFilesystem(c *Config) error {
	installDir := riodbInstallDir(c)
	home := riodbHome(c)
	userName := riodbUser(c)
	groupName := riodbGroup(c)

	if st, err := os.Stat(installDir); err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("RioDB install root is not a directory: %s", installDir)
	} else if filepath.Clean(installDir) != defaultRioDBInstallDir {
		if err := chownPath(installDir, "root", "root"); err != nil {
			return err
		}
		if err := chmodPath(installDir, 0o755); err != nil {
			return err
		}
	}

	if st, err := os.Stat(home); err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("RioDB home is not a directory: %s", home)
	}
	if err := applyRioDBTreeOwnership(home, "root", groupName, riodbReadOnlyMode); err != nil {
		return err
	}
	for _, dir := range riodbWritableDirs(c) {
		if err := mkdirAllNoSymlink(dir, 0o700); err != nil {
			return err
		}
		if err := applyRioDBTreeOwnership(dir, userName, groupName, riodbWritableMode); err != nil {
			return err
		}
	}
	return nil
}

func riodbWritableDirs(c *Config) []string {
	return []string{
		filepath.Join(riodbHome(c), "sql"),
		riodbLogDir(c),
	}
}

func applyRioDBTreeOwnership(path, ownerName, groupName string, modeFor func(os.FileMode) os.FileMode) error {
	uid, gid, err := lookupOwnerGroup(ownerName, groupName)
	if err != nil {
		return err
	}
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if err := os.Lchown(p, uid, gid); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		return chmodPath(p, modeFor(info.Mode()))
	})
}

func riodbReadOnlyMode(mode os.FileMode) os.FileMode {
	if mode.IsDir() {
		return 0o750
	}
	if mode&0o111 != 0 {
		return 0o750
	}
	return 0o640
}

func riodbWritableMode(mode os.FileMode) os.FileMode {
	if mode.IsDir() {
		return 0o700
	}
	if mode&0o111 != 0 {
		return 0o700
	}
	return 0o600
}

// ensureRioDBArchive returns the configured RioDB archive, downloading it into
// the installed/source bin directory when the release archive did not include
// the proprietary payload.
func ensureRioDBArchive(ctx context.Context, a *App) (string, error) {
	archive, err := findRioDBArchive(a)
	if err == nil {
		return archive, nil
	}
	archivePath := strings.TrimSpace(a.Settings.RioDB.ArchivePath)
	if archivePath == "" {
		return "", fmt.Errorf("RioDB archive path is empty in %s", defaultSettingsName)
	}
	if len(a.Settings.RioDB.DownloadServers) == 0 {
		return "", fmt.Errorf("%w; no riodb.download_servers configured in %s", err, defaultSettingsName)
	}
	return downloadRioDBArchive(ctx, a, archivePath)
}

// findRioDBArchive searches installed, settings-relative, and development
// resource locations for the configured RioDB distribution archive.
func findRioDBArchive(a *App) (string, error) {
	archivePath := strings.TrimSpace(a.Settings.RioDB.ArchivePath)
	if archivePath == "" {
		return "", fmt.Errorf("RioDB archive path is empty in %s", defaultSettingsName)
	}
	candidates := []string{}
	if filepath.IsAbs(archivePath) {
		candidates = append(candidates, archivePath)
	} else {
		for _, dir := range rioDBArchiveBinDirs(a) {
			candidates = append(candidates, filepath.Join(dir, archivePath))
		}
		candidates = append(candidates,
			filepath.Join(a.SourceRoot, archivePath),
		)
	}
	for _, candidate := range candidates {
		matches, _ := filepath.Glob(candidate)
		for _, match := range matches {
			if st, err := os.Stat(match); err == nil && !st.IsDir() {
				return match, nil
			}
		}
	}
	return "", fmt.Errorf("RioDB archive not found; configured archive_path=%s", archivePath)
}

func downloadRioDBArchive(ctx context.Context, a *App, archivePath string) (string, error) {
	archiveName, err := rioDBArchiveDownloadName(archivePath)
	if err != nil {
		return "", err
	}
	dstDir, err := rioDBArchiveDownloadDir(a)
	if err != nil {
		return "", err
	}
	dst := filepath.Join(dstDir, archiveName)
	out := stepOutput(a)
	var failures []string
	for _, server := range a.Settings.RioDB.DownloadServers {
		downloadURL, err := rioDBArchiveDownloadURL(server, archiveName)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		fmt.Fprintf(out, "[INFO] RioDB archive not found; downloading %s\n", downloadURL)
		if err := downloadFile(ctx, out, downloadURL, dst, 0o600); err == nil {
			_ = chownPath(dst, "root", "root")
			return dst, nil
		} else {
			fmt.Fprintf(out, "[NOTICE] RioDB archive download failed from %s: %v\n", downloadURL, err)
			failures = append(failures, fmt.Sprintf("%s: %v", downloadURL, err))
		}
	}
	return "", fmt.Errorf("RioDB archive not found and download failed for archive_path=%s (%s)", archivePath, strings.Join(failures, "; "))
}

func rioDBArchiveBinDirs(a *App) []string {
	var dirs []string
	seen := map[string]bool{}
	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		clean := filepath.Clean(dir)
		if seen[clean] {
			return
		}
		seen[clean] = true
		dirs = append(dirs, clean)
	}
	if a != nil && a.Config != nil {
		add(filepath.Join(a.Config.Get("proxyble", "install_dir", "/opt/proxyble"), "bin"))
	}
	if a != nil && a.SettingsPath != "" {
		add(filepath.Dir(a.SettingsPath))
	}
	if a != nil && a.SourceRoot != "" {
		add(filepath.Join(a.SourceRoot, "bin"))
	}
	add(filepath.Join("/opt/proxyble", "bin"))
	return dirs
}

func rioDBArchiveDownloadDir(a *App) (string, error) {
	for _, dir := range rioDBArchiveBinDirs(a) {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir, nil
		}
	}
	dirs := rioDBArchiveBinDirs(a)
	if len(dirs) == 0 {
		return "", fmt.Errorf("no RioDB archive download directory is configured")
	}
	return dirs[0], nil
}

func rioDBArchiveDownloadName(archivePath string) (string, error) {
	name := strings.TrimSpace(archivePath)
	if name == "" {
		return "", fmt.Errorf("RioDB archive path is empty in %s", defaultSettingsName)
	}
	if filepath.IsAbs(name) || filepath.Clean(name) != filepath.Base(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("riodb.archive_path must be a file name to download automatically: %s", archivePath)
	}
	return name, nil
}

func rioDBArchiveDownloadURL(server, archiveName string) (string, error) {
	base := strings.TrimSpace(server)
	if base == "" {
		return "", fmt.Errorf("empty RioDB download server")
	}
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("unsupported RioDB download URL scheme: %s", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("RioDB download server is missing a host: %s", server)
	}
	u.Path += url.PathEscape(archiveName)
	return u.String(), nil
}

// installHAProxy installs HAProxy and renders/enables it only when listener and
// backend configuration are complete.
func installHAProxy(ctx context.Context, a *App, p Platform, packageSession *packageMetadataSession) error {
	if err := installHAProxySoftware(ctx, a, p, packageSession); err != nil {
		return err
	}
	if err := updateHAProxyEnabled(a.Config); err != nil {
		return err
	}
	if configIsTrue(a.Config.Get("haproxy", "enabled", "false")) {
		if err := renderHAProxyConfig(ctx, a); err != nil {
			return err
		}
		_ = systemctl(ctx, stepOutput(a), "enable", "haproxy")
	} else if a.InstalledNow {
		_ = systemctl(ctx, stepOutput(a), "disable", "--now", "haproxy")
	}
	return nil
}

// configureNFTables installs nftables and configures its hardened systemd
// pre-start hook to create Proxyble's managed table/chain/set.
func configureNFTables(ctx context.Context, a *App, p Platform, packageSession *packageMetadataSession) error {
	out := stepOutput(a)
	fmt.Fprintln(out, "[INFO] Starting controlled configuration session")
	fmt.Fprintln(out, "[INFO] Component: nftables host firewall")
	fmt.Fprintln(out, "[INFO] Ensuring nftables package is installed")
	installedBefore, err := packageInstalled(ctx, p, defaultNFTablesPackage)
	if err != nil {
		return fmt.Errorf("detect existing nftables package ownership: %w", err)
	}
	if err := packageSession.update(ctx, p, out); err != nil {
		return err
	}
	if err := packageInstall(ctx, p, out, defaultNFTablesPackage); err != nil {
		return err
	}
	if !installedBefore {
		if err := recordPackageInstalledByProxyble(a.Config, "nftables"); err != nil {
			return fmt.Errorf("record nftables package ownership: %w", err)
		}
	}
	overrideDir := "/etc/systemd/system/nftables.service.d"
	overrideFile := filepath.Join(overrideDir, "override.conf")
	if err := mkdirOwned(overrideDir, 0o750, "root", "root"); err != nil {
		return err
	}
	override := `[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
PrivateDevices=yes
IPAddressDeny=any
MemoryDenyWriteExecute=yes
LockPersonality=yes
ExecStartPre=+/usr/local/bin/proxyble --internal-nft-init
`
	if err := atomicWriteFile(overrideFile, []byte(override), 0o600); err != nil {
		return err
	}
	_ = chownPath(overrideFile, "root", "root")
	if err := systemctl(ctx, out, "daemon-reload"); err != nil {
		return err
	}
	return systemctl(ctx, out, "enable", "nftables")
}

// internalNFTInit is invoked by systemd before nftables starts to idempotently
// create the Proxyble managed firewall structure.
func internalNFTInit(ctx context.Context, out io.Writer) error {
	return withNFTablesCoordinationLock(func() error {
		return internalNFTInitLocked(ctx, out)
	})
}

func internalNFTInitLocked(ctx context.Context, out io.Writer) error {
	commands := [][]string{
		{"add", "table", "inet", "pmgr"},
		{"add", "chain", "inet", "pmgr", "managed_rules"},
		{"add", "chain", "inet", "pmgr", "input", "{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}"},
		{"add", "set", "inet", "pmgr", "blacklist", "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
	}
	for _, args := range commands {
		if err := runNFTAllowExists(ctx, out, args...); err != nil {
			return err
		}
	}
	hasJump, err := nftChainContains(ctx, "inet", "pmgr", "input", "jump managed_rules")
	if err != nil {
		return err
	}
	if !hasJump {
		if err := runCommand(ctx, out, "nft", "insert", "rule", "inet", "pmgr", "input", "jump", "managed_rules"); err != nil {
			return err
		}
	}
	hasDrop, err := nftChainContains(ctx, "inet", "pmgr", "managed_rules", "@blacklist drop")
	if err != nil {
		return err
	}
	if !hasDrop {
		if err := runCommand(ctx, out, "nft", "add", "rule", "inet", "pmgr", "managed_rules", "ip", "saddr", "@blacklist", "drop"); err != nil {
			return err
		}
	}
	if cfg, err := loadConfig(defaultConfigFile); err == nil {
		if err := applyBasicAllowListFromDiskLocked(ctx, out, cfg); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintln(out, "[PASS] nftables structure configured")
	return nil
}

// runNFTAllowExists runs nft and treats already-exists responses as successful
// because the nftables bootstrap is intentionally idempotent.
func runNFTAllowExists(ctx context.Context, out io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "nft", args...)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if buf.Len() > 0 {
		fmt.Fprint(out, buf.String())
	}
	if err == nil {
		return nil
	}
	lower := strings.ToLower(buf.String())
	if strings.Contains(lower, "file exists") || strings.Contains(lower, "already exists") {
		return nil
	}
	return err
}

// nftChainContains returns whether a rendered nftables chain contains a text
// fragment, used to avoid adding duplicate jump/drop rules.
func nftChainContains(ctx context.Context, family, table, chain, text string) (bool, error) {
	cmd := exec.CommandContext(ctx, "nft", "list", "chain", family, table, chain)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return false, err
	}
	return strings.Contains(buf.String(), text), nil
}

// configureRuleAgent installs the rule-agent binary and creates its service,
// path, and timer units for immediate and periodic rule enforcement.
func configureRuleAgent(ctx context.Context, a *App, modeOverride string) error {
	out := stepOutput(a)
	mode := modeOverride
	if mode == "" {
		trafficMode, err := a.Config.TrafficMode()
		if err != nil {
			return err
		}
		mode, err = ruleAgentModeForTraffic(trafficMode)
		if err != nil {
			return err
		}
	}
	binPath := a.Config.Get("rule_agent", "binary_path", "/usr/local/bin/proxyble-rule-agent")
	if err := ensureRuleInbox(a.Config); err != nil {
		return err
	}
	watchFile := a.Config.Get("rule_agent", "watch_file", defaultRuleInbox)
	src, err := findRuleAgentBinary(a)
	if err != nil {
		return err
	}
	if err := mkdirAllNoSymlink(filepath.Dir(binPath), 0o755); err != nil {
		return err
	}
	if err := copyFile(src, binPath, 0o700); err != nil {
		return err
	}
	_ = chownPath(binPath, "root", "root")
	_ = a.Config.Set("rule_agent", "binary_path", binPath)
	_ = a.Config.Set("rule_agent", "watch_file", watchFile)
	service := renderRuleAgentService(binPath, mode, watchFile)
	pathUnit := fmt.Sprintf(`[Unit]
Description=Monitor inbox.tmp for security rule updates

[Path]
PathChanged=%s
Unit=proxyble-rule-agent.service

[Install]
WantedBy=multi-user.target
`, watchFile)
	timerUnit := `[Unit]
Description=Run Proxyble Rule Agent every minute for rule expiration

[Timer]
OnCalendar=*:0/1
AccuracySec=1s
Unit=proxyble-rule-agent.service

[Install]
WantedBy=timers.target
`
	units := map[string]string{
		"/etc/systemd/system/proxyble-rule-agent.service": service,
		"/etc/systemd/system/proxyble-rule-agent.path":    pathUnit,
		"/etc/systemd/system/proxyble-rule-agent.timer":   timerUnit,
	}
	for path, body := range units {
		if err := atomicWriteFile(path, []byte(body), 0o644); err != nil {
			return err
		}
		_ = chownPath(path, "root", "root")
	}
	if err := systemctl(ctx, out, "daemon-reload"); err != nil {
		return err
	}
	_ = systemctl(ctx, out, "enable", "proxyble-rule-agent.path")
	_ = systemctl(ctx, out, "enable", "proxyble-rule-agent.timer")
	return nil
}

func renderRuleAgentService(binPath, mode, watchFile string) string {
	return fmt.Sprintf(`[Unit]
Description=Proxyble Rule Agent Enforcement Service (NFTables & HAProxy)
After=network.target nftables.service haproxy.service
Wants=nftables.service haproxy.service

[Service]
Type=oneshot
ExecStart=%s %s
User=root
Group=root
UMask=0077
RuntimeDirectory=proxyble-rule-agent
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
ReadWritePaths=%s
ReadWritePaths=/var/lib/proxyble-rule-agent
ReadWritePaths=/var/log/proxyble-rule-agent
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, binPath, mode, filepath.Dir(watchFile), defaultRuleAgentRuntimeDir)
}

// findRuleAgentBinary searches bundled and installed resource locations for the
// canonical rule-agent binary.
func findRuleAgentBinary(a *App) (string, error) {
	candidates := []string{
		filepath.Join(a.SourceRoot, "bin", defaultRuleAgentBinaryName),
		filepath.Join("/opt/proxyble/bin", defaultRuleAgentBinaryName),
	}
	for _, candidate := range candidates {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("proxyble-rule-agent binary not found; expected bin/%s", defaultRuleAgentBinaryName)
}

// syncRioDBSQL ensures the mandatory RioDB bootstrap SQL template is present.
// Policy deployment copies additional templates and dependencies as needed.
func syncRioDBSQL(a *App, _ string) error {
	out := stepOutput(a)
	if !riodbEnabled(a.Config) {
		fmt.Fprintln(out, "[NOTICE] RioDB analytics disabled; SQL templates were not copied")
		return nil
	}
	riodbHome := riodbHome(a.Config)
	sqlDir := filepath.Join(riodbHome, "sql")
	if st, err := os.Stat(riodbHome); err != nil || !st.IsDir() {
		fmt.Fprintf(out, "[NOTICE] RioDB installation not found at %s; SQL templates were not copied\n", riodbHome)
		return nil
	}
	if err := mkdirAllNoSymlink(sqlDir, 0o700); err != nil {
		return err
	}
	_ = chownPath(sqlDir, riodbUser(a.Config), riodbGroup(a.Config))
	if err := removeLegacyGeneratedSQL(a, sqlDir); err != nil {
		return err
	}
	root := policyTemplateRoot(a)
	src, err := safePolicyTemplatePath(root, mandatoryRuleQueueSQLFile)
	if err != nil {
		return err
	}
	dst := filepath.Join(sqlDir, mandatoryRuleQueueSQLFile)
	if err := copyFile(src, dst, 0o600); err != nil {
		return fmt.Errorf("copy %s: %w", mandatoryRuleQueueSQLFile, err)
	}
	_ = chownPath(dst, riodbUser(a.Config), riodbGroup(a.Config))
	fmt.Fprintf(out, "[PASS] RioDB SQL template copied from %s\n", src)
	return nil
}

func removeLegacyGeneratedSQL(a *App, sqlDir string) error {
	for _, name := range []string{"10-rule-queue.sql", "20-tcp-log-input.sql", "20-http-log-input.sql", "200-data-exfiltration.sql"} {
		path := filepath.Join(sqlDir, name)
		if err := rejectSymlinkIfExists(path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		fmt.Fprintf(stepOutput(a), "[NOTICE] Removed legacy generated RioDB SQL file: %s\n", path)
	}
	return nil
}

// timeNow is a narrow wrapper so tests can override time behavior if needed.
func timeNow() time.Time {
	return time.Now()
}

// groupExists reports whether a Unix group exists.
func groupExists(name string) bool {
	return exec.Command("getent", "group", name).Run() == nil
}

// userExists reports whether a Unix user exists.
func userExists(name string) bool {
	return exec.Command("id", name).Run() == nil
}

// stopServices confirms with the operator and stops all Proxyble runtime units.
func stopServices(ctx context.Context, a *App) error {
	if ok, err := appConfirm(a, "Stop all Proxyble services now?"); err != nil {
		return err
	} else if !ok {
		if !a.Silent {
			fmt.Println("[NOTICE] Service stop cancelled.")
		}
		return errActionCancelled
	}
	out := stepOutput(a)
	type serviceUnit struct {
		unit  string
		label string
	}
	units := []serviceUnit{
		{"proxyble-rule-agent.path", "Proxyble Rule Agent path"},
		{"proxyble-rule-agent.timer", "Proxyble Rule Agent timer"},
		{"proxyble-rule-agent.service", "Proxyble Rule Agent service"},
	}
	if riodbEnabled(a.Config) {
		units = append(units, serviceUnit{riodbServiceName(a.Config), "RioDB"})
	}
	units = append(units,
		serviceUnit{"haproxy.service", "HAProxy"},
		serviceUnit{"nftables.service", "nftables"},
	)
	for _, u := range units {
		if !systemctlQuiet(ctx, "cat", u.unit) {
			continue
		}
		if err := timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "stop", u.unit); err != nil {
			return fmt.Errorf("failed to stop %s: %w", u.unit, err)
		}
		if !a.Silent {
			fmt.Printf("[OK] %s stopped\n", u.label)
		}
	}
	if !a.Silent {
		fmt.Println("[OK] Proxyble services stopped")
	}
	return nil
}

// startServices confirms with the operator, starts runtime services in the
// required order, and reports success/failure for each visible unit.
func startServices(ctx context.Context, a *App) error {
	if ok, err := appConfirm(a, "Start all Proxyble services now?"); err != nil {
		return err
	} else if !ok {
		if !a.Silent {
			fmt.Println("[NOTICE] Service start cancelled.")
		}
		return errActionCancelled
	}
	return startRuntimeServices(ctx, a)
}

// restartServices remains as a compatibility wrapper for the old CLI action.
func restartServices(ctx context.Context, a *App) error {
	return startServices(ctx, a)
}

// startRuntimeServices performs the actual systemd work without prompting. It
// uses stop/start rather than start-only so freshly rendered config is applied.
func startRuntimeServices(ctx context.Context, a *App) error {
	out := stepOutput(a)
	riodbUnit := strings.TrimSuffix(riodbServiceName(a.Config), ".service")
	_ = timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "stop", "proxyble-rule-agent.service")
	_ = timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "stop", "proxyble-rule-agent.path")
	_ = timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "stop", "proxyble-rule-agent.timer")
	type runtimeUnit struct {
		unit    string
		label   string
		process string
	}
	units := []runtimeUnit{
		{"nftables", "nftables", ""},
	}
	if riodbEnabled(a.Config) {
		units = append(units, runtimeUnit{riodbUnit, "RioDB", riodbUnit})
	}
	units = append(units, runtimeUnit{"haproxy", "HAProxy", "haproxy"})
	for _, u := range units {
		startUnit := func() error {
			return startRuntimeUnit(ctx, a, u)
		}
		if u.unit == "haproxy" {
			if err := withHAProxyCoordinationLock(startUnit); err != nil {
				return err
			}
			continue
		}
		if err := startUnit(); err != nil {
			return err
		}
	}
	if err := enableRuntimeUnit(ctx, out, "proxyble-rule-agent.path"); err != nil {
		printServiceStatus(a, "Starting Proxyble Rule Agent", "FAILED", colorRed)
		return err
	}
	if err := enableRuntimeUnit(ctx, out, "proxyble-rule-agent.timer"); err != nil {
		printServiceStatus(a, "Starting Proxyble Rule Agent", "FAILED", colorRed)
		return err
	}
	if err := timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "start", "proxyble-rule-agent.path"); err != nil {
		printServiceStatus(a, "Starting Proxyble Rule Agent", "FAILED", colorRed)
		return err
	}
	if err := timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "start", "proxyble-rule-agent.timer"); err != nil {
		printServiceStatus(a, "Starting Proxyble Rule Agent", "FAILED", colorRed)
		return err
	}
	if !systemctlQuiet(ctx, "is-active", "--quiet", "proxyble-rule-agent.path") || !systemctlQuiet(ctx, "is-active", "--quiet", "proxyble-rule-agent.timer") {
		printServiceStatus(a, "Starting Proxyble Rule Agent", "FAILED", colorRed)
		return fmt.Errorf("proxyble-rule-agent monitors failed to become active")
	}
	printServiceStatus(a, "Starting Proxyble Rule Agent", "OK", colorBlueLight)
	a.Printf("[PASS] Proxyble services started successfully.\n")
	fmt.Fprintln(out, "[PASS] proxyble-rule-agent started successfully")
	return nil
}

func startRuntimeUnit(ctx context.Context, a *App, u struct {
	unit    string
	label   string
	process string
}) error {
	out := stepOutput(a)
	_ = timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "stop", u.unit)
	if u.process != "" {
		_ = runCommand(ctx, out, "pkill", "-9", u.process)
	}
	if err := enableRuntimeUnit(ctx, out, u.unit); err != nil {
		printServiceStatus(a, "Starting "+u.label, "FAILED", colorRed)
		return fmt.Errorf("%s failed to enable: %w", u.unit, err)
	}
	if err := timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "start", u.unit); err != nil {
		printServiceStatus(a, "Starting "+u.label, "FAILED", colorRed)
		return fmt.Errorf("%s failed to start: %w", u.unit, err)
	}
	if !systemctlQuiet(ctx, "is-active", "--quiet", u.unit) {
		printServiceStatus(a, "Starting "+u.label, "FAILED", colorRed)
		return fmt.Errorf("%s service failed to become active", u.unit)
	}
	printServiceStatus(a, "Starting "+u.label, "OK", colorBlueLight)
	fmt.Fprintf(out, "[PASS] %s started successfully\n", u.unit)
	return nil
}

// enableRuntimeUnit avoids repeating systemd's compatibility enablement work
// for units that are already enabled. On slower hosts that work may invoke a
// distribution SysV helper, so a real enable operation gets the full service
// control timeout.
func enableRuntimeUnit(ctx context.Context, out io.Writer, unit string) error {
	if timeoutCommand(ctx, io.Discard, serviceControlTimeoutSeconds, "systemctl", "is-enabled", "--quiet", unit) == nil {
		fmt.Fprintf(out, "[PASS] %s already enabled\n", unit)
		return nil
	}
	return timeoutCommand(ctx, out, serviceControlTimeoutSeconds, "systemctl", "enable", unit)
}

// printServiceStatus prints one aligned service-control status row and writes a
// plain copy to the log.
func printServiceStatus(a *App, label, status, color string) {
	if !a.Silent {
		fmt.Printf("  %-34s [%s%s%s]\n", label, color, status, colorReset)
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "  %-34s [%s]\n", label, status)
	}
}

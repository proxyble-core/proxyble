package main

// actions.go contains user-facing management actions that are not the core
// installation sequence: component inventory, config/license viewing, listener
// setup, backend setup, status reporting, self-signed certificate generation,
// and uninstall. The text and flow here should stay aligned with the legacy
// bash wizard unless the product intentionally changes the CLI experience.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// showComponentVersions prints one-line version/status details for each runtime
// component Proxyble depends on.
func showComponentVersions(ctx context.Context, a *App) error {
	riodbVersionPath := filepath.Join(riodbHome(a.Config), "riodb.sh")
	a.Printf("Proxyble component versions\n\n")
	components := []struct {
		label string
		cmd   string
		args  []string
	}{
		{"java", "java", []string{"--version"}},
		{"haproxy", "haproxy", []string{"-v"}},
		{"nftables", "nft", []string{"-v"}},
		{"proxyble-rule-agent", "proxyble-rule-agent", []string{"--version"}},
		{"riodb", riodbVersionPath, []string{"--version"}},
	}
	for _, c := range components {
		a.Printf("  %-16s %s\n", c.label+":", firstLineCommand(ctx, c.cmd, c.args...))
	}
	return nil
}

// viewConfig prints config.ini for non-interactive CLI use, truncating very long
// files so command output remains manageable.
func viewConfig(a *App) error {
	a.Printf("Path       : %s\n", defaultConfigFile)
	a.Printf("Owner/mode : root:root 0600\n\n")
	data, err := os.ReadFile(defaultConfigFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 220 {
		lines = lines[:220]
	}
	a.Printf("%s", strings.Join(lines, "\n"))
	if !strings.HasSuffix(strings.Join(lines, "\n"), "\n") {
		a.Printf("\n")
	}
	return nil
}

// viewConfigInteractive opens config.ini in the full-screen scrollable viewer.
func viewConfigInteractive(a *App) error {
	data, err := os.ReadFile(defaultConfigFile)
	if err != nil {
		return err
	}
	body := fmt.Sprintf("Path       : %s\nOwner/mode : root:root 0600\n\n%s", defaultConfigFile, string(data))
	return scrollableText("[proxyble] Config -> View", "View the current Proxyble configuration file.", strings.Split(strings.TrimRight(body, "\n"), "\n"))
}

const (
	gplV2Path              = "LICENSES/GPL-2.0.txt"
	rioDBEULAPath          = "LICENSES/RIODB-EULA.txt"
	installedGPLV2Path     = "/opt/proxyble/LICENSES/GPL-2.0.txt"
	proxybleWebsite        = "https://www.proxyble.com/"
	haproxyWebsite         = "https://www.haproxy.org/"
	nftablesWebsite        = "https://www.nftables.org/"
	riodbWebsite           = "https://www.riodb.co/"
	acceptLicenses         = "I acknowledge the component notices and accept the RioDB EULA"
	acknowledgeNotices     = "I acknowledge the component notices"
	acceptRioDBLicense     = "I acknowledge the RioDB notice and accept the RioDB EULA"
	acceptRioDBJavaLicense = "I acknowledge the RioDB and Java notices and accept the RioDB EULA"
	declineLicenses        = "I do not accept"
)

// viewLicense prints the bundled component notices and archive RioDB EULA for
// non-interactive CLI use.
func viewLicense(a *App) error {
	lines, err := licenseDisplayLinesWithJavaNotice(a, javaDependencyNoticeOptions(context.Background(), a))
	if err != nil {
		return err
	}
	a.Printf("%s\n", strings.Join(lines, "\n"))
	return nil
}

// viewLicenseInteractive opens the license in the full-screen scrollable viewer.
func viewLicenseInteractive(a *App) error {
	lines, err := licenseDisplayLinesWithJavaNotice(a, javaDependencyNoticeOptions(context.Background(), a))
	if err != nil {
		return err
	}
	return scrollableText("[proxyble] Installation -> License", "Review component notices and the RioDB EULA.", lines)
}

// reviewAndAcceptLicenseInteractive requires wizard users to reach the end of
// the license before the accept/decline choice is shown.
func reviewAndAcceptLicenseInteractive(a *App) (bool, error) {
	return reviewAndAcceptLicenseInteractiveWithJavaNotice(a, defaultJavaNoticeOptions(a))
}

func reviewAndAcceptLicenseInteractiveWithJavaNotice(a *App, notice javaNoticeOptions) (bool, error) {
	lines, err := licenseDisplayLinesWithJavaNotice(a, notice)
	if err != nil {
		return false, err
	}
	if err := scrollableTextRequiredEnd("[proxyble] Installation -> License", "Review component notices and the RioDB EULA. Scroll to the end to continue.", lines); err != nil {
		return false, err
	}
	choice, err := choiceMenu("[proxyble] Installation -> License", "You have reached the end of the component notices and RioDB EULA.", licenseAcceptanceMenuItems(), declineLicenses)
	if err != nil {
		return false, err
	}
	switch choice {
	case acceptLicenses:
		return true, nil
	case declineLicenses, "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown license acceptance selection: %s", choice)
	}
}

// reviewAndAcceptRioDBLicenseInteractive is used when RioDB is added after a
// core install, so it shows only the RioDB notice, Java dependency notice, and
// EULA.
func reviewAndAcceptRioDBLicenseInteractive(a *App) (bool, error) {
	notice := javaDependencyNoticeOptions(context.Background(), a)
	lines, err := rioDBLicenseDisplayLinesWithJavaNotice(a, notice)
	if err != nil {
		return false, err
	}
	if err := scrollableTextRequiredEnd("[proxyble] Installation -> Add RioDB", rioDBReviewPrompt(notice.IncludeJava), lines); err != nil {
		return false, err
	}
	choice, err := choiceMenu("[proxyble] Installation -> Add RioDB", rioDBReachedEndPrompt(notice.IncludeJava), rioDBLicenseAcceptanceMenuItems(notice.IncludeJava), declineLicenses)
	if err != nil {
		return false, err
	}
	switch choice {
	case rioDBAcceptText(notice.IncludeJava):
		return true, nil
	case declineLicenses, "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown RioDB license acceptance selection: %s", choice)
	}
}

// reviewAndAcknowledgeOpenSourceNoticesInteractive lets core-install users see
// the core component notices without accepting the separate RioDB EULA.
func reviewAndAcknowledgeOpenSourceNoticesInteractive(a *App) (bool, error) {
	lines, err := openSourceNoticeDisplayLines(a)
	if err != nil {
		return false, err
	}
	if err := scrollableTextRequiredEnd("[proxyble] Installation -> Notice", "Review component notices. Scroll to the end to continue.", lines); err != nil {
		return false, err
	}
	choice, err := choiceMenu("[proxyble] Installation -> Notice", "You have reached the end of the component notices.", openSourceNoticeAcceptanceMenuItems(), declineLicenses)
	if err != nil {
		return false, err
	}
	switch choice {
	case acknowledgeNotices:
		return true, nil
	case declineLicenses, "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown open-source notice acknowledgement selection: %s", choice)
	}
}

// reviewAndConfirmInstallInteractive is the first-run install path: review the
// required notice/EULA, then make the acceptance choice the install action.
func reviewAndConfirmInstallInteractive(ctx context.Context, a *App, profile installProfile) (bool, error) {
	title := "[proxyble] Installation -> Notice"
	prompt := "Review component notices. Scroll to the end to continue."
	var lines []string
	var err error
	if profileIncludesRioDB(profile) {
		notice := javaDependencyNoticeOptions(ctx, a)
		title = "[proxyble] Installation -> Notice & EULA"
		prompt = "Review component notices and the RioDB EULA. Scroll to the end to continue."
		lines, err = licenseDisplayLinesWithJavaNoticeContext(ctx, a, notice)
	} else {
		lines, err = openSourceNoticeDisplayLines(a)
	}
	if err != nil {
		return false, err
	}
	if err := scrollableTextRequiredEnd(title, prompt, lines); err != nil {
		return false, err
	}
	choice, err := choiceMenu("[proxyble] Installation -> Install", installAcceptPrompt(profile), installAcceptanceMenuItems(profile), "install")
	if err != nil {
		return false, err
	}
	switch choice {
	case "install":
		return true, nil
	case "cancel", "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown install acceptance selection: %s", choice)
	}
}

func installAcceptPrompt(profile installProfile) string {
	if profileIncludesRioDB(profile) {
		return "Accept notice/EULA and install Proxyble + RioDB now?"
	}
	return "Accept notice and install Proxyble Core now?"
}

func installAcceptanceMenuItems(profile installProfile) [][2]string {
	action := "Accept notice and install Proxyble Core now"
	if profileIncludesRioDB(profile) {
		action = "Accept notice/EULA and install Proxyble + RioDB now"
	}
	return [][2]string{
		{"install|" + action, ""},
		{"cancel|Cancel", ""},
	}
}

func licenseAcceptanceMenuItems() [][2]string {
	return [][2]string{
		{acceptLicenses, ""},
		{declineLicenses, ""},
	}
}

func openSourceNoticeAcceptanceMenuItems() [][2]string {
	return [][2]string{
		{acknowledgeNotices, ""},
		{declineLicenses, ""},
	}
}

func rioDBAcceptText(includeJava bool) string {
	if includeJava {
		return acceptRioDBJavaLicense
	}
	return acceptRioDBLicense
}

func rioDBLicenseAcceptanceMenuItems(includeJava bool) [][2]string {
	return [][2]string{
		{rioDBAcceptText(includeJava), ""},
		{declineLicenses, ""},
	}
}

func openSourceNoticeDisplayLines(a *App) ([]string, error) {
	body := strings.Join(coreComponentNoticeBlocks(), "\n\n")
	return strings.Split(strings.TrimRight(body, "\n"), "\n"), nil
}

func licenseDisplayLines(a *App) ([]string, error) {
	return licenseDisplayLinesWithJavaNotice(a, defaultJavaNoticeOptions(a))
}

func licenseDisplayLinesWithJavaNotice(a *App, notice javaNoticeOptions) ([]string, error) {
	return licenseDisplayLinesWithJavaNoticeContext(context.Background(), a, notice)
}

func licenseDisplayLinesWithJavaNoticeContext(ctx context.Context, a *App, notice javaNoticeOptions) ([]string, error) {
	notices, err := openSourceNoticeDisplayLines(a)
	if err != nil {
		return nil, err
	}
	riodb, err := rioDBLicenseDisplayLinesWithJavaNoticeContext(ctx, a, notice)
	if err != nil {
		return nil, err
	}
	body := fmt.Sprintf(`%s

%s`, strings.Join(notices, "\n"), strings.Join(riodb, "\n"))
	return strings.Split(strings.TrimRight(body, "\n"), "\n"), nil
}

func rioDBLicenseDisplayLines(a *App) ([]string, error) {
	return rioDBLicenseDisplayLinesWithJavaNotice(a, defaultJavaNoticeOptions(a))
}

func rioDBLicenseDisplayLinesWithJavaNotice(a *App, notice javaNoticeOptions) ([]string, error) {
	return rioDBLicenseDisplayLinesWithJavaNoticeContext(context.Background(), a, notice)
}

func rioDBLicenseDisplayLinesWithJavaNoticeContext(ctx context.Context, a *App, notice javaNoticeOptions) ([]string, error) {
	eula, err := loadRioDBEULA(ctx, a)
	if err != nil {
		return nil, err
	}
	noticeBlocks := []string{rioDBComponentNoticeBlock(eula.Source)}
	if notice.IncludeJava {
		noticeBlocks = append(noticeBlocks, javaRuntimeNoticeBlock(notice))
	}
	body := fmt.Sprintf(`%s

The RioDB free tier allows a limited number of active RioSQL stream processing
queries. Additional active queries or commercial features may require a RioDB
license key.

RioDB End User License Agreement:
%s

%s`, strings.Join(noticeBlocks, "\n\n"), eula.Source, eula.Text)
	return strings.Split(strings.TrimRight(body, "\n"), "\n"), nil
}

func coreComponentNoticeBlocks() []string {
	return []string{
		componentNoticeBlock("Proxyble Core", "Setup wizard, rule activation and state management", "GPLv2", installedGPLV2Path, proxybleWebsite),
		componentNoticeBlock("HAProxy", "Proxying, access logging, and rule enforcement", "GPLv2-compatible open-source terms", installedGPLV2Path, haproxyWebsite),
		componentNoticeBlock("nftables / netfilter", "Kernel-level packet filtering", "GPLv2 and compatible licenses", installedGPLV2Path, nftablesWebsite),
	}
}

func rioDBComponentNoticeBlock(eulaSource string) string {
	if strings.TrimSpace(eulaSource) == "" {
		eulaSource = "RioDB archive " + rioDBEULAPath
	}
	return componentNoticeBlock("RioDB", "Real-time analytics and policy workflows", "RioDB End User License Agreement", eulaSource, riodbWebsite)
}

type javaNoticeOptions struct {
	IncludeJava bool
	Package     SettingsJavaPackage
	Version     string
}

func defaultJavaNoticeOptions(a *App) javaNoticeOptions {
	settings := defaultRuntimeSettings()
	if a != nil {
		settings = a.Settings
		settings.fillDefaults()
	}
	return javaNoticeOptions{
		IncludeJava: true,
		Package:     settings.Java.Default,
		Version:     settings.Java.Version,
	}
}

func javaNoticeOptionsForInstall(ctx context.Context, a *App) javaNoticeOptions {
	notice := defaultJavaNoticeOptions(a)
	settings := defaultRuntimeSettings()
	if a != nil {
		settings = a.Settings
		settings.fillDefaults()
	}
	if p, err := detectPlatform(); err == nil {
		if pkg, err := settings.JavaPackage(p.Family); err == nil {
			notice.Package = pkg
		}
	}
	notice.IncludeJava = !probeExistingJavaRuntime(ctx).Available
	return notice
}

func javaDependencyNoticeOptions(ctx context.Context, a *App) javaNoticeOptions {
	notice := javaNoticeOptionsForInstall(ctx, a)
	notice.IncludeJava = true
	return notice
}

func javaRuntimeNoticeBlock(notice javaNoticeOptions) string {
	pkg := notice.Package
	if pkg.Label == "" {
		pkg = defaultRuntimeSettings().Java.Default
	}
	version := strings.TrimSpace(notice.Version)
	if version == "" {
		version = defaultRuntimeSettings().Java.Version
	}
	return fmt.Sprintf(`Java JDK: OpenJDK or Amazon Corretto
Purpose: Java dependency required to run RioDB analytics
Installed when: RioDB analytics is selected and no working Java runtime is already present
Package: Java %s headless runtime from the operating system package manager
Distribution: %s
Settings: The exact Java version and package are configured in proxyble/bin/riodb-settings.json
Notice: This dependency is not installed for Core only`, version, pkg.Label)
}

func rioDBReviewPrompt(includeJava bool) string {
	if includeJava {
		return "Review the RioDB notice, Java runtime dependency notice, and EULA. Scroll to the end to continue."
	}
	return "Review the RioDB notice and EULA. Scroll to the end to continue."
}

func rioDBReachedEndPrompt(includeJava bool) string {
	if includeJava {
		return "You have reached the end of the RioDB notice, Java runtime dependency notice, and EULA."
	}
	return "You have reached the end of the RioDB notice and EULA."
}

func rioDBCLIConfirmPrompt(includeJava bool) string {
	if includeJava {
		return "Acknowledge the RioDB and Java notices, accept the RioDB EULA, and enable RioDB?"
	}
	return "Acknowledge the RioDB notice, accept the RioDB EULA, and enable RioDB?"
}

func componentNoticeBlock(name, purpose, license, notice, website string) string {
	return fmt.Sprintf(`%s
Purpose: %s
License: %s
Notice: %s
Website: %s`, name, purpose, license, notice, website)
}

func findGPLLicense(a *App) string {
	candidates := []string{
		filepath.Join(a.SourceRoot, gplV2Path),
		filepath.Join("/opt/proxyble", gplV2Path),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return filepath.Join(a.SourceRoot, gplV2Path)
}

type rioDBEULAContent struct {
	Source string
	Text   string
}

func loadRioDBEULA(ctx context.Context, a *App) (rioDBEULAContent, error) {
	archive, err := ensureRioDBArchive(ctx, a)
	if err != nil {
		return rioDBEULAContent{}, err
	}
	text, member, err := readRioDBEULAFromArchive(ctx, archive)
	if err != nil {
		return rioDBEULAContent{}, err
	}
	return rioDBEULAContent{
		Source: fmt.Sprintf("%s:%s", archive, member),
		Text:   text,
	}, nil
}

func readRioDBEULAFromArchive(ctx context.Context, archive string) (string, string, error) {
	member, err := findArchiveMember(ctx, archive, rioDBEULAPath)
	if err != nil {
		return "", "", err
	}
	cmd := exec.CommandContext(ctx, "tar", "-xOf", archive, member)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("read %s from RioDB archive %s: %w%s", rioDBEULAPath, archive, err, commandStderrSuffix(stderr.String()))
	}
	return string(out), member, nil
}

func findArchiveMember(ctx context.Context, archive, wanted string) (string, error) {
	cmd := exec.CommandContext(ctx, "tar", "-tf", archive)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("list RioDB archive %s: %w%s", archive, err, commandStderrSuffix(stderr.String()))
	}
	for _, entry := range strings.Split(string(out), "\n") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		normalized := path.Clean(strings.TrimPrefix(entry, "./"))
		if archiveMemberMatches(normalized, wanted) {
			return entry, nil
		}
	}
	return "", fmt.Errorf("RioDB archive %s does not contain %s", archive, wanted)
}

func archiveMemberMatches(member, wanted string) bool {
	member = path.Clean(strings.TrimPrefix(member, "./"))
	wanted = path.Clean(strings.TrimPrefix(wanted, "./"))
	return member == wanted || strings.HasSuffix(member, "/"+wanted)
}

func commandStderrSuffix(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}

// listenerOptions captures CLI flags and interactive choices for public
// listener configuration.
type listenerOptions struct {
	cli                   bool
	mode                  string
	port                  string
	timeout               string
	certificate           string
	certificateSelfSigned bool
	generateSelfSigned    bool
	selfSignedFor         string
	selfSignedFQDN        string
	selfSignedOutput      string
	startServices         *bool
	resetActiveRules      *bool
}

// configureListenerAction validates listener input, persists config.ini values,
// refreshes dependent rule-agent/RioDB assets, and optionally starts all
// Proxyble runtime services.
func configureListenerAction(ctx context.Context, a *App, args []string) error {
	opts, err := parseListenerOptions(args)
	if err != nil {
		return err
	}
	opts.cli = opts.cli || a.CommandLine
	p, _ := detectPlatform()
	c := a.Config
	previousMode, _ := c.TrafficMode()
	previousRuntimeComplete := runtimeConfigComplete(c)
	existingPort := c.Get("haproxy", "listener_port", "")
	existingTimeout := c.Get("haproxy", "timeout", "60s")
	existingCert := c.Get("haproxy", "certificate_path", "")
	existingPrimaryHost := c.Get("haproxy", "backend_primary_host", "")
	existingPrimaryPort := c.Get("haproxy", "backend_primary_port", "")
	existingSecondaryHost := c.Get("haproxy", "backend_secondary_host", "")
	existingSecondaryPort := c.Get("haproxy", "backend_secondary_port", "")

	mode := opts.mode
	if opts.cli {
		mode, err = validateListenerCLIOptions(&opts, existingPrimaryHost, existingPrimaryPort, existingSecondaryHost, existingSecondaryPort)
		if err != nil {
			return err
		}
	}
	hasExisting := listenerConfigurationExists(existingPort, existingCert, previousMode)
	if hasExisting {
		a.Printf("\nExisting listener configuration\n")
		a.Printf("  %-24s %s\n", "Traffic mode:", displayValue(previousMode))
		a.Printf("  %-24s %s\n", "Listener port:", displayValue(existingPort))
		a.Printf("  %-24s %s\n", "Timeout:", displayValue(existingTimeout))
		a.Printf("  %-24s %s\n", "TLS certificate:", displayValue(existingCert))
		ok, err := appConfirm(a, "Change listener configuration?")
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Listener configuration unchanged.\n")
			return errActionCancelled
		}
	}

	if !opts.cli {
		defMode := "https"
		defTimeout := "60s"
		if hasExisting {
			defMode = previousMode
			defTimeout = existingTimeout
		}
		for {
			mode, err = promptMode(defMode)
			if err != nil {
				return err
			}
			actionPage("[proxyble] Config -> Listener", "Configure the public listener that receives client traffic.")
			defPort := "80"
			if mode == "https" {
				defPort = "443"
			}
			opts.port, err = promptPort("Listener port", firstNonEmpty(existingPort, defPort))
			if err != nil {
				return err
			}
			opts.timeout, err = promptValue("Timeout (for example, 60s)", defTimeout, true)
			if err != nil {
				return err
			}
			if err := validateBackendPortConflict(opts.port, existingPrimaryHost, existingPrimaryPort, "Primary backend"); err != nil {
				retry, err := promptConfigRetry("[proxyble] Config -> Listener", "Configure the public listener that receives client traffic.", err)
				if err != nil {
					return err
				}
				if !retry {
					return errActionCancelled
				}
				continue
			}
			if err := validateBackendPortConflict(opts.port, existingSecondaryHost, existingSecondaryPort, "Secondary backend"); err != nil {
				retry, err := promptConfigRetry("[proxyble] Config -> Listener", "Configure the public listener that receives client traffic.", err)
				if err != nil {
					return err
				}
				if !retry {
					return errActionCancelled
				}
				continue
			}
			if mode == "https" {
				opts.certificate, opts.certificateSelfSigned, err = promptHTTPSCertificate(existingCert)
				if err != nil {
					return err
				}
				actionPage("[proxyble] Config -> Listener", "Configure the public listener that receives client traffic.")
			}
			break
		}
	}
	certPath := ""
	if mode == "https" {
		if opts.generateSelfSigned {
			subject, err := selfSignedSubject(opts.selfSignedFor, opts.selfSignedFQDN)
			if err != nil {
				return err
			}
			certPath, err = createSelfSignedPEM(opts.selfSignedFor, subject, opts.selfSignedOutput)
			if err != nil {
				return err
			}
			opts.certificateSelfSigned = true
			a.Printf("[PASS] Self-signed PEM bundle created: %s\n", certPath)
		} else {
			certPath = opts.certificate
		}
	}
	if err := c.Set("traffic", "mode", mode); err != nil {
		return err
	}
	_ = c.Set("haproxy", "listener_port", opts.port)
	savedTimeout := haproxyTimeoutValue(opts.timeout)
	_ = c.Set("haproxy", "timeout", savedTimeout)
	_ = c.Set("haproxy", "certificate_path", certPath)
	if riodbEnabled(c) {
		if err := validateConfiguredRioDBUDPLogPorts(c); err != nil {
			return err
		}
	}

	raPathActive := systemctlQuiet(ctx, "is-active", "--quiet", "proxyble-rule-agent.path")
	raTimerActive := systemctlQuiet(ctx, "is-active", "--quiet", "proxyble-rule-agent.timer")
	_ = systemctl(ctx, stepOutput(a), "stop", "proxyble-rule-agent.path")
	_ = systemctl(ctx, stepOutput(a), "stop", "proxyble-rule-agent.timer")
	if err := configureRuleAgent(ctx, a, ""); err != nil {
		return err
	}
	if err := syncRioDBSQL(a, mode); err != nil {
		return err
	}
	modeChangedOnExistingConfig := trafficModeChangedAfterExistingListener(hasExisting, previousMode, mode)
	if modeChangedOnExistingConfig {
		if mode == "https" && certPath != "" {
			a.Printf("[NOTICE] Traffic mode changed from %s to %s. TLS certificate: %s\n", previousMode, mode, certPath)
		} else {
			a.Printf("[NOTICE] Traffic mode changed from %s to %s.\n", previousMode, mode)
		}
	}
	if shouldPromptRuleResetForModeChange(hasExisting, previousRuntimeComplete, previousMode, mode) {
		reset := false
		if opts.resetActiveRules != nil {
			reset = *opts.resetActiveRules
		} else {
			reset, _ = appConfirm(a, "Reset currently active rules for the new traffic mode?")
		}
		if reset {
			var ok bool
			var err error
			if a.CommandLine {
				ok, err = appConfirm(a, "Remove all currently active Proxyble rules?")
			} else {
				ok, err = confirmKeyword("Type RESET to remove all currently active Proxyble rules: ", "RESET", a.AssumeYes)
			}
			if err != nil {
				return err
			}
			if ok {
				if err := resetRules(ctx, a, []string{"--type", "ALL", "--yes"}); err != nil {
					a.Printf("[NOTICE] Rule reset did not complete cleanly: %v\n", err)
				}
			}
		}
	}
	if raPathActive {
		_ = systemctl(ctx, stepOutput(a), "start", "proxyble-rule-agent.path")
	}
	if raTimerActive {
		_ = systemctl(ctx, stepOutput(a), "start", "proxyble-rule-agent.timer")
	}
	if err := updateHAProxyEnabled(c); err != nil {
		return err
	}
	if configIsTrue(c.Get("haproxy", "enabled", "false")) {
		if err := applyHAProxyIfEnabled(ctx, a, p); err != nil {
			return err
		}
		if shouldStartServices(a, opts.cli, opts.startServices) {
			if err := startRuntimeServices(ctx, a); err != nil {
				return err
			}
		} else {
			a.Printf("[NOTICE] Proxyble service start skipped.\n")
		}
	} else {
		a.Printf("[NOTICE] HAProxy remains disabled until backend configuration is complete.\n")
	}
	a.Printf("[NOTICE] %s.\n", listenerConfiguredNotice(opts.port, savedTimeout, certPath))
	a.Printf("[PASS] Listener configuration complete.\n")
	return nil
}

// parseListenerOptions converts --config-listener flags into listenerOptions
// while preserving whether the caller used CLI mode at all.
func parseListenerOptions(args []string) (listenerOptions, error) {
	var o listenerOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := func() (string, error) {
			if strings.Contains(arg, "=") {
				return strings.SplitN(arg, "=", 2)[1], nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}
		setBool := func(v bool) *bool { b := v; return &b }
		switch {
		case arg == "--mode":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.mode = v
		case strings.HasPrefix(arg, "--mode="):
			o.cli = true
			o.mode, _ = value()
		case arg == "--port" || arg == "--listener-port":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.port = v
		case strings.HasPrefix(arg, "--port=") || strings.HasPrefix(arg, "--listener-port="):
			o.cli = true
			o.port, _ = value()
		case arg == "--timeout":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.timeout = v
		case strings.HasPrefix(arg, "--timeout="):
			o.cli = true
			o.timeout, _ = value()
		case arg == "--certificate" || arg == "--cert" || arg == "--pem":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.certificate = v
		case strings.HasPrefix(arg, "--certificate=") || strings.HasPrefix(arg, "--cert=") || strings.HasPrefix(arg, "--pem="):
			o.cli = true
			o.certificate, _ = value()
		case arg == "--generate-self-signed":
			o.cli = true
			o.generateSelfSigned = true
		case strings.HasPrefix(arg, "--generate-self-signed="):
			o.cli = true
			o.generateSelfSigned = true
			o.selfSignedFor, _ = value()
		case arg == "--self-signed-for":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.selfSignedFor = v
		case strings.HasPrefix(arg, "--self-signed-for="):
			o.cli = true
			o.selfSignedFor, _ = value()
		case arg == "--self-signed-fqdn" || arg == "--fqdn":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.selfSignedFQDN = v
		case strings.HasPrefix(arg, "--self-signed-fqdn=") || strings.HasPrefix(arg, "--fqdn="):
			o.cli = true
			o.selfSignedFQDN, _ = value()
		case arg == "--self-signed-output" || arg == "--certificate-output":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.selfSignedOutput = v
		case strings.HasPrefix(arg, "--self-signed-output=") || strings.HasPrefix(arg, "--certificate-output="):
			o.cli = true
			o.selfSignedOutput, _ = value()
		case arg == "--start-services" || arg == "--start-listener":
			o.cli = true
			o.startServices = setBool(true)
		case arg == "--no-start":
			o.cli = true
			o.startServices = setBool(false)
		case arg == "--reset-active-rules" || arg == "--reset-rules":
			o.cli = true
			o.resetActiveRules = setBool(true)
		case arg == "--keep-active-rules" || arg == "--no-reset-rules":
			o.cli = true
			o.resetActiveRules = setBool(false)
		default:
			return o, fmt.Errorf("unknown option for --config-listener: %s", arg)
		}
	}
	return o, nil
}

// validateListenerCLIOptions requires all command-line listener inputs before
// any confirmation prompt or system change is attempted.
func validateListenerCLIOptions(o *listenerOptions, existingPrimaryHost, existingPrimaryPort, existingSecondaryHost, existingSecondaryPort string) (string, error) {
	if strings.TrimSpace(o.mode) == "" {
		return "", fmt.Errorf("--config-listener requires --mode tcp|http|https")
	}
	mode, err := normalizeTrafficMode(o.mode)
	if err != nil {
		return "", fmt.Errorf("invalid --mode value; allowed values: tcp, http, https")
	}
	if strings.TrimSpace(o.port) == "" {
		return "", fmt.Errorf("--config-listener requires --port")
	}
	if strings.TrimSpace(o.timeout) == "" {
		return "", fmt.Errorf("--config-listener requires --timeout")
	}
	if err := validatePort(o.port, "--port"); err != nil {
		return "", err
	}
	if mode == "https" {
		if o.certificate != "" && o.generateSelfSigned {
			return "", fmt.Errorf("use either --certificate PATH or --generate-self-signed, not both")
		}
		if o.certificate == "" && !o.generateSelfSigned {
			return "", fmt.Errorf("HTTPS listener mode requires --certificate PATH or --generate-self-signed")
		}
		if o.certificate != "" {
			if _, err := os.Stat(o.certificate); err != nil {
				return "", fmt.Errorf("certificate file not found: %s", o.certificate)
			}
		}
		if o.generateSelfSigned {
			if _, err := selfSignedSubject(o.selfSignedFor, o.selfSignedFQDN); err != nil {
				return "", err
			}
		}
	} else if o.certificate != "" || o.generateSelfSigned || o.selfSignedFor != "" || o.selfSignedFQDN != "" || o.selfSignedOutput != "" {
		return "", fmt.Errorf("certificate options can only be used with --mode https")
	}
	if err := validateBackendPortConflict(o.port, existingPrimaryHost, existingPrimaryPort, "Primary backend"); err != nil {
		return "", err
	}
	if err := validateBackendPortConflict(o.port, existingSecondaryHost, existingSecondaryPort, "Secondary backend"); err != nil {
		return "", err
	}
	o.mode = mode
	return mode, nil
}

// backendOptions captures CLI flags and interactive choices for protected
// backend configuration.
type backendOptions struct {
	cli           bool
	primaryHost   string
	primaryPort   string
	secondarySet  bool
	secondaryHost string
	secondaryPort string
	noSecondary   bool
	startServices *bool
}

// configureBackendAction validates backend input, persists config.ini values,
// renders HAProxy when possible, and optionally starts all Proxyble runtime
// services.
func configureBackendAction(ctx context.Context, a *App, args []string) error {
	opts, err := parseBackendOptions(args)
	if err != nil {
		return err
	}
	opts.cli = opts.cli || a.CommandLine
	p, _ := detectPlatform()
	c := a.Config
	listenerPort := c.Get("haproxy", "listener_port", "")
	existingPrimaryHost := c.Get("haproxy", "backend_primary_host", "")
	existingPrimaryPort := c.Get("haproxy", "backend_primary_port", "")
	existingSecondaryHost := c.Get("haproxy", "backend_secondary_host", "")
	existingSecondaryPort := c.Get("haproxy", "backend_secondary_port", "")
	secondaryHost, secondaryPort := existingSecondaryHost, existingSecondaryPort
	if opts.cli {
		secondaryHost, secondaryPort, err = validateBackendCLIOptions(opts, listenerPort, existingSecondaryHost, existingSecondaryPort)
		if err != nil {
			return err
		}
	}
	hasExisting := existingPrimaryHost != "" || existingPrimaryPort != "" || existingSecondaryHost != "" || existingSecondaryPort != ""
	if hasExisting {
		a.Printf("\nExisting backend configuration\n")
		a.Printf("  %-24s %s\n", "Primary host:", displayValue(existingPrimaryHost))
		a.Printf("  %-24s %s\n", "Primary port:", displayValue(existingPrimaryPort))
		a.Printf("  %-24s %s\n", "Secondary host:", displayValue(existingSecondaryHost))
		a.Printf("  %-24s %s\n", "Secondary port:", displayValue(existingSecondaryPort))
		ok, err := appConfirm(a, "Change backend configuration?")
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Backend configuration unchanged.\n")
			return errActionCancelled
		}
	}
	if !opts.cli {
		for {
			actionPage("[proxyble] Config -> Backend", "Define the backend server that receives allowed traffic.")
			opts.secondarySet = false
			opts.primaryHost, err = promptValue("Primary backend host", firstNonEmpty(existingPrimaryHost, "127.0.0.1"), true)
			if err != nil {
				return err
			}
			opts.primaryPort, err = promptPort("Primary backend port", firstNonEmpty(existingPrimaryPort, firstNonEmpty(listenerPort, "80")))
			if err != nil {
				return err
			}
			opts.secondaryHost, err = promptValue("Secondary backend host (optional)", existingSecondaryHost, false)
			if err != nil {
				return err
			}
			secondaryHost, secondaryPort = existingSecondaryHost, existingSecondaryPort
			if opts.secondaryHost != "" {
				opts.secondaryPort, err = promptPort("Secondary backend port", firstNonEmpty(existingSecondaryPort, opts.primaryPort))
				if err != nil {
					return err
				}
				opts.secondarySet = true
				secondaryHost, secondaryPort = opts.secondaryHost, opts.secondaryPort
			}
			if err := validateBackendPortConflict(listenerPort, opts.primaryHost, opts.primaryPort, "Primary backend"); err != nil {
				retry, err := promptConfigRetry("[proxyble] Config -> Backend", "Define the backend server that receives allowed traffic.", err)
				if err != nil {
					return err
				}
				if !retry {
					return errActionCancelled
				}
				continue
			}
			if err := validateBackendPortConflict(listenerPort, secondaryHost, secondaryPort, "Secondary backend"); err != nil {
				retry, err := promptConfigRetry("[proxyble] Config -> Backend", "Define the backend server that receives allowed traffic.", err)
				if err != nil {
					return err
				}
				if !retry {
					return errActionCancelled
				}
				continue
			}
			break
		}
	}
	_ = c.Set("haproxy", "backend_primary_host", opts.primaryHost)
	_ = c.Set("haproxy", "backend_primary_port", opts.primaryPort)
	_ = c.Set("haproxy", "backend_secondary_host", secondaryHost)
	_ = c.Set("haproxy", "backend_secondary_port", secondaryPort)
	if err := updateHAProxyEnabled(c); err != nil {
		return err
	}
	if configIsTrue(c.Get("haproxy", "enabled", "false")) {
		a.Printf("[PASS] Backend saved. Listener and backend are complete.\n")
		if err := applyHAProxyIfEnabled(ctx, a, p); err != nil {
			return err
		}
		if shouldStartServices(a, opts.cli, opts.startServices) {
			if err := startRuntimeServices(ctx, a); err != nil {
				return err
			}
		} else {
			a.Printf("[NOTICE] Proxyble service start skipped.\n")
		}
	} else {
		a.Printf("[NOTICE] Backend saved. HAProxy remains disabled until listener configuration is complete.\n")
	}
	a.Printf("[PASS] Backend configuration complete.\n")
	return nil
}

// parseBackendOptions converts --config-backend flags into backendOptions.
func parseBackendOptions(args []string) (backendOptions, error) {
	var o backendOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := func() (string, error) {
			if strings.Contains(arg, "=") {
				return strings.SplitN(arg, "=", 2)[1], nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}
		setBool := func(v bool) *bool { b := v; return &b }
		switch {
		case arg == "--primary-host":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.primaryHost = v
		case strings.HasPrefix(arg, "--primary-host="):
			o.cli = true
			o.primaryHost, _ = value()
		case arg == "--primary-port":
			o.cli = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.primaryPort = v
		case strings.HasPrefix(arg, "--primary-port="):
			o.cli = true
			o.primaryPort, _ = value()
		case arg == "--secondary-host":
			o.cli = true
			o.secondarySet = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.secondaryHost = v
		case strings.HasPrefix(arg, "--secondary-host="):
			o.cli = true
			o.secondarySet = true
			o.secondaryHost, _ = value()
		case arg == "--secondary-port":
			o.cli = true
			o.secondarySet = true
			v, err := value()
			if err != nil {
				return o, err
			}
			o.secondaryPort = v
		case strings.HasPrefix(arg, "--secondary-port="):
			o.cli = true
			o.secondarySet = true
			o.secondaryPort, _ = value()
		case arg == "--no-secondary":
			o.cli = true
			o.noSecondary = true
		case arg == "--start-services" || arg == "--start-listener":
			o.cli = true
			o.startServices = setBool(true)
		case arg == "--no-start":
			o.cli = true
			o.startServices = setBool(false)
		default:
			return o, fmt.Errorf("unknown option for --config-backend: %s", arg)
		}
	}
	return o, nil
}

// validateBackendCLIOptions requires all command-line backend inputs before
// any confirmation prompt or HAProxy render is attempted.
func validateBackendCLIOptions(o backendOptions, listenerPort, existingSecondaryHost, existingSecondaryPort string) (string, string, error) {
	if strings.TrimSpace(o.primaryHost) == "" || strings.TrimSpace(o.primaryPort) == "" {
		return "", "", fmt.Errorf("--config-backend requires --primary-host and --primary-port")
	}
	if err := validatePort(o.primaryPort, "--primary-port"); err != nil {
		return "", "", err
	}
	if o.noSecondary && o.secondarySet {
		return "", "", fmt.Errorf("use either --no-secondary or --secondary-host/--secondary-port, not both")
	}
	secondaryHost, secondaryPort := existingSecondaryHost, existingSecondaryPort
	if o.secondarySet {
		if strings.TrimSpace(o.secondaryHost) == "" || strings.TrimSpace(o.secondaryPort) == "" {
			return "", "", fmt.Errorf("--secondary-host and --secondary-port must be provided together")
		}
		if err := validatePort(o.secondaryPort, "--secondary-port"); err != nil {
			return "", "", err
		}
		secondaryHost, secondaryPort = o.secondaryHost, o.secondaryPort
	} else if o.noSecondary {
		secondaryHost, secondaryPort = "", ""
	}
	if err := validateBackendPortConflict(listenerPort, o.primaryHost, o.primaryPort, "Primary backend"); err != nil {
		return "", "", err
	}
	if err := validateBackendPortConflict(listenerPort, secondaryHost, secondaryPort, "Secondary backend"); err != nil {
		return "", "", err
	}
	return secondaryHost, secondaryPort, nil
}

// shouldStartServices centralizes the final start confirmation used by both
// listener and backend configuration.
func shouldStartServices(a *App, cli bool, explicit *bool) bool {
	if cli && explicit != nil {
		return *explicit
	}
	ok, _ := appConfirm(a, "Start all Proxyble services now?")
	return ok
}

// promptConfigRetry keeps interactive validation errors inside the wizard: the
// operator can retry the form or cancel back to the menu without ending Proxyble.
func promptConfigRetry(title, summary string, validationErr error) (bool, error) {
	if !isTerminal(os.Stdin) {
		return false, validationErr
	}
	choice, err := choiceMenu(title, fmt.Sprintf("%s\n\n[ERROR] %v\n\nRetry input or cancel and return to menu.", summary, validationErr), [][2]string{
		{"retry", "Retry input"},
		{"cancel", "Cancel and return to menu"},
	}, "retry")
	if err != nil {
		return false, err
	}
	switch choice {
	case "retry":
		return true, nil
	case "cancel", "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown retry selection: %s", choice)
	}
}

// promptMode presents the traffic-mode selector used by the interactive
// listener flow.
func promptMode(def string) (string, error) {
	items := [][2]string{
		{"tcp", "Receiving any Layer 4 TCP traffic, including unterminated HTTPS traffic. Fewer rule options"},
		{"http", "Receiving Layer 7 HTTP unencrypted traffic"},
		{"https", "Receiving and terminating HTTPS TLS-encrypted traffic with a PEM certificate"},
		{"cancel", "Cancel listener configuration"},
	}
	choice, err := choiceMenu("[proxyble] Config -> Listener", "Select the traffic mode received by Proxyble.", items, def)
	if err != nil {
		return "", err
	}
	if choice == "cancel" || choice == "exit" {
		return "", errActionCancelled
	}
	return normalizeTrafficMode(choice)
}

// promptPort reads and validates a TCP port with a default value.
func promptPort(label, def string) (string, error) {
	for {
		v, err := promptValue(label, def, true)
		if err != nil {
			return "", err
		}
		if err := validatePort(v, label); err == nil {
			return v, nil
		}
		fmt.Fprintln(os.Stderr, "[ERROR] Enter a port number between 1 and 65535.")
	}
}

// validatePort enforces the valid TCP/UDP port number range.
func validatePort(value, label string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s must be a number between 1 and 65535", label)
	}
	return nil
}

// promptHTTPSCertificate lets the operator choose or generate the PEM bundle
// required by HTTPS listener mode. The boolean return identifies generated
// self-signed certificates so completion notices can name the certificate type.
func promptHTTPSCertificate(existing string) (string, bool, error) {
	currentIP := detectCurrentIP()
	currentHostname := detectCurrentHostname()
	for {
		defaultChoice := "hostname"
		if existing != "" {
			defaultChoice = "provide"
		}
		choice, err := choiceMenu("[proxyble] Config -> Listener TLS", "HTTPS listeners require a HAProxy PEM bundle. Use an existing certificate or generate a self-signed one now.", [][2]string{
			{"provide", "Provide an existing .pem file"},
			{"ip", "Generate for current IP address (" + currentIP + ")"},
			{"hostname", "Generate for current hostname (" + currentHostname + ")"},
			{"fqdn", "Generate for a DNS name that points to this server"},
			{"cancel", "Cancel listener configuration"},
		}, defaultChoice)
		if err != nil {
			return "", false, err
		}
		switch choice {
		case "cancel", "exit":
			return "", false, errActionCancelled
		case "ip":
			path, err := createSelfSignedPEM("ip", currentIP, "")
			return path, true, err
		case "hostname":
			path, err := createSelfSignedPEM("hostname", currentHostname, "")
			return path, true, err
		case "fqdn":
			actionPage("[proxyble] Config -> Listener TLS", "HTTPS listeners require a HAProxy PEM bundle. Use an existing certificate or generate a self-signed one now.")
			fqdn, err := promptValue("Fully qualified DNS name", "", true)
			if err != nil {
				return "", false, err
			}
			path, err := createSelfSignedPEM("fqdn", fqdn, "")
			return path, true, err
		case "provide":
			actionPage("[proxyble] Config -> Listener TLS", "HTTPS listeners require a HAProxy PEM bundle. Use an existing certificate or generate a self-signed one now.")
			v, err := promptValue("TLS certificate path (.pem), or type cancel", existing, true)
			if err != nil {
				return "", false, err
			}
			switch strings.ToLower(v) {
			case "cancel", "q", "quit":
				return "", false, errActionCancelled
			}
			if _, err := os.Stat(v); err == nil {
				return v, false, nil
			}
			fmt.Fprintf(os.Stderr, "[ERROR] Certificate file not found: %s\n", v)
		}
	}
}

// listenerCertificateMessage summarizes the certificate path saved for HTTPS
// listener mode without hiding whether it was generated or supplied by the user.
func listenerCertificateMessage(certPath string, selfSigned bool) string {
	certType := "provided certificate"
	if selfSigned {
		certType = "self-signed certificate"
	}
	return fmt.Sprintf("Listener configured with %s %s", certType, certPath)
}

// listenerConfigurationExists distinguishes first-time listener setup from an
// operator modifying an already populated listener section.
func listenerConfigurationExists(port, certPath, previousMode string) bool {
	return strings.TrimSpace(port) != "" || strings.TrimSpace(certPath) != "" || strings.TrimSpace(previousMode) != "tcp"
}

// trafficModeChangedAfterExistingListener keeps the first HTTPS setup from
// looking like a TCP-to-HTTPS migration just because tcp is the template default.
func trafficModeChangedAfterExistingListener(hasExisting bool, previousMode, mode string) bool {
	return hasExisting && previousMode != mode
}

// shouldPromptRuleResetForModeChange only offers to reset live rules when there
// was a complete runtime config before the listener mode changed.
func shouldPromptRuleResetForModeChange(hasExisting, previouslyRuntimeComplete bool, previousMode, mode string) bool {
	return trafficModeChangedAfterExistingListener(hasExisting, previousMode, mode) && previouslyRuntimeComplete
}

// listenerConfiguredNotice gives first-time installs and edits the same concise
// completion summary while surfacing the HTTPS certificate path when applicable.
func listenerConfiguredNotice(port, timeout, certPath string) string {
	if strings.TrimSpace(certPath) != "" {
		return fmt.Sprintf("Listener configured for port %s with %s timeout, and TLS certificate: %s", port, timeout, certPath)
	}
	return fmt.Sprintf("Listener configured for port %s with %s timeout", port, timeout)
}

// normalizeSelfSignedTarget accepts user-friendly aliases for certificate
// subject type selection.
func normalizeSelfSignedTarget(target string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "ip", "address", "current-ip", "current_ip":
		return "ip", nil
	case "host", "hostname", "current-hostname", "current_hostname":
		return "hostname", nil
	case "fqdn", "dns", "domain":
		return "fqdn", nil
	default:
		return "", fmt.Errorf("invalid self-signed target; allowed values: ip, hostname, fqdn")
	}
}

// selfSignedSubject resolves the requested certificate subject to an IP,
// hostname, or validated FQDN.
func selfSignedSubject(target, fqdn string) (string, error) {
	target, err := normalizeSelfSignedTarget(target)
	if err != nil {
		return "", fmt.Errorf("--generate-self-signed requires --self-signed-for ip|hostname|fqdn")
	}
	switch target {
	case "ip":
		return detectCurrentIP(), nil
	case "hostname":
		return detectCurrentHostname(), nil
	case "fqdn":
		fqdn = strings.TrimSuffix(fqdn, ".")
		if !validDNSName(fqdn, true) {
			return "", fmt.Errorf("--self-signed-fqdn must be a valid fully qualified domain name")
		}
		return fqdn, nil
	default:
		return "", fmt.Errorf("invalid self-signed target")
	}
}

// createSelfSignedPEM writes a root-owned HAProxy PEM bundle containing a
// short-lived self-signed certificate and private key.
func createSelfSignedPEM(target, subject, output string) (string, error) {
	target, err := normalizeSelfSignedTarget(target)
	if err != nil {
		return "", err
	}
	if output == "" {
		output = defaultSelfSignedPEMPath(subject)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject, Organization: []string{"Proxyble"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if target == "ip" {
		ip := net.ParseIP(subject)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("cannot generate certificate for invalid IP address: %s", subject)
		}
		template.IPAddresses = []net.IP{ip}
	} else {
		subject = strings.TrimSuffix(subject, ".")
		if !validDNSName(subject, target == "fqdn") {
			return "", fmt.Errorf("cannot generate certificate for invalid DNS name: %s", subject)
		}
		template.DNSNames = []string{subject}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	var pemBytes strings.Builder
	_ = pem.Encode(&pemStringWriter{&pemBytes}, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&pemStringWriter{&pemBytes}, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := atomicWriteFile(output, []byte(pemBytes.String()), 0o600); err != nil {
		return "", err
	}
	_ = chownPath(output, "root", "root")
	return output, nil
}

// defaultSelfSignedPEMPath names generated certificates after the subject so
// operators can recognize which hostname or IP the PEM bundle belongs to.
func defaultSelfSignedPEMPath(subject string) string {
	name := strings.TrimSpace(strings.TrimSuffix(subject, "."))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	clean := strings.Trim(b.String(), ".-")
	if clean == "" {
		clean = "listener"
	}
	return filepath.Join("/etc/proxyble", clean+"-self-signed.pem")
}

// pemStringWriter adapts strings.Builder to the io.Writer interface expected by
// encoding/pem.
type pemStringWriter struct{ *strings.Builder }

// Write appends PEM bytes into the embedded strings.Builder.
func (w *pemStringWriter) Write(p []byte) (int, error) { return w.Builder.Write(p) }

// validDNSName performs conservative DNS label validation for certificate
// subjects.
func validDNSName(name string, requireDot bool) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	if requireDot && !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
			if !ok || (r == '-' && (i == 0 || i == len(label)-1)) {
				return false
			}
		}
	}
	return true
}

// detectCurrentIP returns the first non-loopback IPv4 address, falling back to
// localhost when the host has no usable interface yet.
func detectCurrentIP() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip4 := ip.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

// detectCurrentHostname returns a DNS-safe local hostname for certificate
// generation prompts.
func detectCurrentHostname() string {
	host, _ := os.Hostname()
	host = strings.TrimSuffix(host, ".")
	if !validDNSName(host, false) {
		return "localhost"
	}
	return host
}

// displayValue formats empty config fields for existing-configuration summaries.
func displayValue(v string) string {
	if v == "" {
		return "<not set>"
	}
	return v
}

// firstNonEmpty returns the first non-empty string from a preference list.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// showStatus prints systemd health, host resource usage, and recent rule-agent
// activity.
func showStatus(ctx context.Context, a *App) error {
	services := proxybleRuntimeHealthUnits(a.Config)
	a.Printf("%sSystem Service Health Check%s\n", colorBold, colorReset)
	a.Printf("%-28s %-12s %-12s %s\n", "SERVICE", "ENABLED", "ACTIVE", "STATUS")
	a.Printf("%s\n", hr(79))
	overall := 0
	for _, svc := range services {
		enabled := systemctlState(ctx, "is-enabled", svc)
		active := systemctlState(ctx, "is-active", svc)
		status := colorBlueDark + "NOT HEALTHY" + colorReset
		if active == "active" && enabled == "enabled" {
			status = colorBlueLight + "OK" + colorReset
		} else if active == "active" {
			status = colorBlueMedium + "RUNNING (NOT ENABLED)" + colorReset
			overall = 1
		} else {
			overall = 1
		}
		a.Printf("%-28s %-12s %-12s %s\n", svc, enabled, active, status)
	}
	a.Printf("%s\n", hr(79))
	if overall == 0 {
		a.Printf("[PASS] All required services are enabled and running.\n")
	} else {
		a.Printf("[FAIL] One or more services require attention.\n")
	}
	a.Printf("\n%sCurrent Host Resource Usage%s\n", colorBold, colorReset)
	a.Printf("%s\n", hr(70))
	if commandExists("mpstat") {
		a.Printf("%-25s %s %%\n", "CPU Usage:", cpuUsageFromMPStat(ctx))
	} else {
		a.Printf("%-25s %s\n", "CPU Usage:", "unavailable (mpstat not installed)")
	}
	if commandExists("free") {
		out, _ := exec.CommandContext(ctx, "free", "-h").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 7 && fields[0] == "Mem:" {
				a.Printf("%-25s %s / %s\n", "Memory Used:", fields[2], fields[1])
				a.Printf("%-25s %s\n", "Memory Available:", fields[6])
			}
		}
	}
	activityHeading := "Rule Activity"
	if riodbEnabled(a.Config) {
		activityHeading = "Proxyble Policy Activity"
	}
	a.Printf("\n%s%s%s\n", colorBold, activityHeading, colorReset)
	today := time.Now().Format("2006-01-02")
	todayCount := countActionAdded(filepath.Join("/var/log/proxyble-rule-agent", today+".log"))
	week := 0
	for i := 0; i < 7; i++ {
		week += countActionAdded(filepath.Join("/var/log/proxyble-rule-agent", time.Now().AddDate(0, 0, -i).Format("2006-01-02")+".log"))
	}
	a.Printf("Rules applied today (%s):   %d\n", today, todayCount)
	a.Printf("Rules applied during the past week: %d\n\n", week)
	a.Printf("Rule activity is logged under /var/log/proxyble-rule-agent\n")
	if overall != 0 {
		return exitError{code: overall}
	}
	return nil
}

// systemctlState returns a single systemctl state value or not-found when the
// unit/state query fails.
func systemctlState(ctx context.Context, stateType, service string) string {
	cmd := exec.CommandContext(ctx, "systemctl", stateType, service)
	out, err := cmd.Output()
	if err != nil {
		return "not-found"
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if line == "" {
		return "not-found"
	}
	return line
}

// cpuUsageFromMPStat extracts CPU usage from the final mpstat sample.
func cpuUsageFromMPStat(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "mpstat", "1", "1").Output()
	if err != nil {
		return "unavailable"
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		fields := strings.Fields(lines[i])
		if len(fields) == 0 {
			continue
		}
		idleText := fields[len(fields)-1]
		idle, err := strconv.ParseFloat(idleText, 64)
		if err == nil {
			return fmt.Sprintf("%.2f", 100-idle)
		}
	}
	return "unavailable"
}

// countActionAdded counts rule-agent ACTION=ADDED audit entries in one log file.
func countActionAdded(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "ACTION=ADDED")
}

// uninstallProxyble performs the destructive teardown workflow for installed
// services, files, packages, state, and optional Java removal.
func uninstallProxyble(ctx context.Context, a *App, args []string) error {
	removeJavaChoice := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--remove-java":
			removeJavaChoice = "1"
		case "--keep-java":
			removeJavaChoice = "0"
		default:
			return fmt.Errorf("unknown option for --installation-remove: %s", args[i])
		}
	}
	if err := a.PrepareLog("uninstall"); err != nil {
		return err
	}
	defer a.CloseLog()
	if !a.Silent {
		fmt.Println("[WARNING] Proxyble teardown")
		printHR(os.Stdout, 79)
		fmt.Println("This will remove Proxyble services, configuration, logs, runtime state, installed")
		fmt.Println("software packages, systemd units, and the RioDB system user/group.")
		fmt.Println()
		fmt.Println("This operation is destructive.")
		printHR(os.Stdout, 79)
	}
	ok, err := appConfirm(a, "Continue with Proxyble teardown?")
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return errActionCancelled
	}
	p, err := detectPlatform()
	if err != nil {
		return err
	}
	removeJava := false
	javaCanBeRemoved := javaRemovalCandidate(ctx, a, p)
	riodbWasInstalled := riodbInstalledForRemoval(a.Config)
	if riodbWasInstalled {
		if removeJavaChoice == "1" {
			removeJava = true
		} else if removeJavaChoice == "" {
			removeJava, err = promptJavaRemoval(a)
			if err != nil {
				return err
			}
		}
	} else if removeJavaChoice == "1" {
		a.Printf("[NOTICE] Java removal skipped; RioDB is not installed on this host.\n")
	}
	if removeJava && !javaCanBeRemoved {
		a.Printf("[NOTICE] Java removal was selected, but no supported Java package was detected on this host.\n")
		removeJava = false
	}
	var finalOK bool
	if a.CommandLine {
		finalOK, err = appConfirm(a, "Permanently uninstall Proxyble?")
	} else {
		finalOK, err = confirmKeyword("Type REMOVE to permanently uninstall Proxyble: ", "REMOVE", a.AssumeYes)
	}
	if err != nil || !finalOK {
		if err != nil {
			return err
		}
		a.Printf("[NOTICE] Confirmation did not match. Teardown cancelled.\n")
		return errActionCancelled
	}
	failures := 0
	step := func(label string, fn func() error) {
		if err := runStep(a, label, fn); err != nil {
			failures = 1
		}
	}
	step("Stopping services", func() error {
		units := []string{"proxyble-rule-agent.path", "proxyble-rule-agent.timer", "proxyble-rule-agent.service", riodbServiceName(a.Config), "haproxy.service", "nftables.service"}
		for _, unit := range units {
			_ = systemctl(ctx, stepOutput(a), "stop", unit)
			_ = systemctl(ctx, stepOutput(a), "disable", unit)
		}
		_ = runCommand(ctx, stepOutput(a), "pkill", "-9", "proxyble-rule-agent")
		_ = runCommand(ctx, stepOutput(a), "pkill", "-9", "riodb")
		_ = runCommand(ctx, stepOutput(a), "pkill", "-9", "haproxy")
		return nil
	})
	step("Removing systemd units", func() error {
		for _, path := range []string{
			"/etc/systemd/system/proxyble-rule-agent.service",
			"/etc/systemd/system/proxyble-rule-agent.path",
			"/etc/systemd/system/proxyble-rule-agent.timer",
			filepath.Join("/etc/systemd/system", riodbServiceName(a.Config)),
			"/etc/systemd/system/haproxy.service.d",
			"/etc/systemd/system/nftables.service.d",
			"/etc/tmpfiles.d/haproxy.conf",
		} {
			_ = safeRemovePath(path, a.Config.Get("proxyble", "log_dir", "/var/log/proxyble"))
		}
		_ = systemctl(ctx, stepOutput(a), "daemon-reload")
		_ = systemctl(ctx, stepOutput(a), "reset-failed")
		return nil
	})
	step("Removing packages", func() error {
		for _, pkg := range haproxyRemovalPackages(p) {
			_ = packageRemove(ctx, p, stepOutput(a), pkg)
		}
		_ = packageRemove(ctx, p, stepOutput(a), defaultNFTablesPackage)
		if removeJava {
			javaPkg, err := a.Settings.JavaPackage(p.Family)
			if err == nil {
				_ = packageRemove(ctx, p, stepOutput(a), javaPkg.Package)
			}
		} else if riodbWasInstalled && !javaCanBeRemoved {
			fmt.Fprintln(stepOutput(a), "[NOTICE] Java package removal skipped; no supported Java package was detected on this host.")
		} else if riodbWasInstalled {
			fmt.Fprintln(stepOutput(a), "[NOTICE] Java package removal skipped by operator choice.")
		}
		if p.Family == platformFamilyDebian {
			_ = runCommand(ctx, stepOutput(a), "apt-get", "autoremove", "-y")
		}
		return nil
	})
	step("Removing files and state", func() error {
		riodbInstallRoot := riodbInstallDir(a.Config)
		paths := []string{
			defaultConfigDir,
			a.Config.Get("proxyble", "launcher_path", "/usr/local/bin/proxyble"),
			a.Config.Get("proxyble", "install_dir", "/opt/proxyble"),
			a.Config.Get("rule_agent", "rule_dir", defaultRuleDir),
			a.Config.Get("rule_agent", "state_dir", "/var/lib/proxyble-rule-agent"),
			a.Config.Get("rule_agent", "log_dir", "/var/log/proxyble-rule-agent"),
			riodbHome(a.Config),
			a.Config.Get("riodb", "log_dir", "/var/log/riodb"),
			a.Config.Get("rule_agent", "binary_path", "/usr/local/bin/proxyble-rule-agent"),
			"/usr/local/bin/nft-pmgr-init.sh",
			"/etc/haproxy",
			a.Config.Get("haproxy", "maps_dir", "/etc/haproxy/maps"),
			a.Config.Get("haproxy", "runtime_dir", "/run/haproxy"),
			a.Config.Get("haproxy", "chroot_dir", "/var/lib/haproxy"),
			"/var/tmp/proxyble-installer.swap",
		}
		if filepath.Clean(riodbInstallRoot) != defaultRioDBInstallDir {
			paths = append(paths, riodbInstallRoot)
		}
		for _, path := range paths {
			_ = safeRemovePath(path, a.Config.Get("proxyble", "log_dir", "/var/log/proxyble"))
		}
		return nil
	})
	step("Removing users and groups", func() error {
		_ = runCommand(ctx, stepOutput(a), "userdel", a.Config.Get("riodb", "user", "riodb"))
		_ = runCommand(ctx, stepOutput(a), "groupdel", a.Config.Get("riodb", "group", "riodb"))
		return nil
	})
	if failures != 0 {
		return exitError{code: failures}
	}
	a.Printf("Full log: %s\n", a.LogPath)
	return nil
}

func riodbInstalledForRemoval(c *Config) bool {
	if riodbEnabled(c) {
		return true
	}
	if st, err := os.Stat(riodbHome(c)); err == nil && st.IsDir() {
		return true
	}
	if _, err := os.Stat(filepath.Join("/etc/systemd/system", riodbServiceName(c))); err == nil {
		return true
	}
	return false
}

// promptJavaRemoval asks whether uninstall should remove Java as a separate
// three-way choice so keeping Java does not look the same as cancelling teardown.
func promptJavaRemoval(a *App) (bool, error) {
	if a.CommandLine {
		if a.AssumeYes {
			return false, fmt.Errorf("Java JDK removal choice required; re-run with --remove-java or --keep-java")
		}
		ok, err := commandLineConfirm("Also remove Java JDK? Only choose yes if Java is not used by other software.", false)
		if err != nil {
			return false, fmt.Errorf("confirmation required; re-run with --yes, --remove-java, or --keep-java for non-interactive execution")
		}
		return ok, nil
	}
	if !isTerminal(os.Stdin) {
		return false, fmt.Errorf("confirmation required; re-run with --yes, --remove-java, or --keep-java for non-interactive execution")
	}
	choice, err := choiceMenu("[proxyble] Installation -> Remove", "RioDB is installed.\n\nWould you like to also remove Java JDK, or keep it for other applications?", [][2]string{
		{"Yes, remove Java.", ""},
		{"No, keep Java.", ""},
		{"Cancel.", ""},
	}, "No, keep Java.")
	if err != nil {
		return false, err
	}
	switch choice {
	case "Yes, remove Java.":
		return true, nil
	case "No, keep Java.":
		return false, nil
	case "Cancel.", "back", "exit":
		return false, errActionCancelled
	default:
		return false, fmt.Errorf("unknown Java removal selection: %s", choice)
	}
}

func javaRemovalCandidate(ctx context.Context, a *App, p Platform) bool {
	if !probeExistingJavaRuntime(ctx).Available {
		return false
	}
	settings := defaultRuntimeSettings()
	if a != nil {
		settings = a.Settings
		settings.fillDefaults()
	}
	javaPkg, err := settings.JavaPackage(p.Family)
	if err != nil {
		return false
	}
	return knownPackageInstalled(ctx, p, javaPkg.Package)
}

func knownPackageInstalled(ctx context.Context, p Platform, pkg string) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return false
	}
	switch p.Family {
	case platformFamilyDebian:
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", pkg).Output()
		return err == nil && strings.Contains(string(out), "install ok installed")
	case platformFamilyAmazon, platformFamilyAzure, platformFamilyRHEL:
		return exec.CommandContext(ctx, "rpm", "-q", pkg).Run() == nil
	default:
		return false
	}
}

// exitError lets actions request a specific process exit code without losing the
// ordinary error-return style used across the program.
type exitError struct{ code int }

// Error satisfies the error interface for exitError.
func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

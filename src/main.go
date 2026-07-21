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

// main.go is the top-level command dispatcher for the Proxyble installer and
// management wizard. It owns argument normalization, root/config bootstrap,
// runtime settings loading, CLI action routing, and the interactive menu tree. Future
// maintainers should keep this file focused on orchestration: concrete system
// changes belong in actions.go, install.go, haproxy.go, rules.go, or
// policies.go, while shared OS helpers belong in system.go.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// actionAliases maps all accepted CLI spellings to the canonical action names
// used by runCLIAction. Keep compatibility aliases here so older scripts and
// documentation can continue invoking the single Go binary.
var actionAliases = map[string]string{
	"--install":                "--install",
	"--installation-install":   "--install",
	"--install-license":        "--installation-license",
	"--installation-license":   "--installation-license",
	"--license":                "--installation-license",
	"--installation-list":      "--installation-list",
	"--install-list":           "--installation-list",
	"--list-components":        "--installation-list",
	"--installation-add-riodb": "--installation-add-riodb",
	"--add-riodb":              "--installation-add-riodb",
	"--enable-riodb":           "--installation-add-riodb",
	"--installation-remove":    "--installation-remove",
	"--install-remove":         "--installation-remove",
	"--remove":                 "--installation-remove",
	"--config-listener":        "--config-listener",
	"--config-backend":         "--config-backend",
	"--config-status":          "--config-status",
	"--config-start":           "--config-start",
	"--config-restart":         "--config-start",
	"--config-stop":            "--config-stop",
	"--config-view":            "--config-view",
	"--policies-deploy":        "--policies-deploy",
	"--policies-list":          "--policies-list",
	"--policies-remove":        "--policies-remove",
	"--policies-view":          "--policies-view",
	"--policies-edit":          "--policies-edit",
	"--rules-list":             "--rules-list",
	"--rules-add":              "--rules-add",
	"--rules-check":            "--rules-check",
	"--rules-reset":            "--rules-reset",
	"--basic-allow-list":       "--basic-allow-list",
	"--endpoint-allow-list":    "--endpoint-allow-list",
	"--internal-nft-init":      "--internal-nft-init",
}

// main performs process bootstrap, then delegates either to one CLI action or
// to the interactive wizard. It intentionally exits with numeric process codes
// here so lower-level functions can return ordinary errors.
func main() {
	ctx := context.Background()
	app, help, err := parseGlobalArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if help {
		if app.Action != "" {
			printActionHelp(app.Action)
		} else {
			printGlobalHelp()
		}
		return
	}
	stopInterruptHandler := installInterruptHandler(app.Silent)
	defer stopInterruptHandler()
	if app.Action == "--internal-nft-init" {
		if err := internalNFTInit(ctx, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "[ERROR]", err)
			os.Exit(1)
		}
		return
	}
	if cliActionRequiresInstalledSoftware(app.Action) && !isInstalled() {
		fmt.Fprintln(os.Stderr, "[ERROR] Proxyble is not installed. Run proxyble --install first.")
		os.Exit(1)
	}
	app.SourceRoot = findResourceRoot()
	settings, settingsPath, err := loadRuntimeSettings(app.SourceRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[ERROR]", err)
		os.Exit(1)
	}
	app.Settings = settings
	app.SettingsPath = settingsPath
	if err := requireRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	app.ConfigFileExistedAtStart = fileExists(defaultConfigFile)
	if app.Action != "" || app.ConfigFileExistedAtStart {
		if err := ensureAppConfig(app); err != nil {
			fmt.Fprintln(os.Stderr, "[ERROR]", err)
			os.Exit(1)
		}
	}
	if app.Action != "" {
		err = runCLIAction(ctx, app)
	} else {
		err = runInteractive(ctx, app)
	}
	if err != nil {
		if errors.Is(err, errActionCancelled) {
			return
		}
		if ee, ok := err.(exitError); ok {
			os.Exit(ee.code)
		}
		if !app.Silent {
			fmt.Fprintln(os.Stderr, "[ERROR]", err)
		}
		os.Exit(1)
	}
}

func ensureAppConfig(a *App) error {
	if a.Config != nil {
		return nil
	}
	cfg, created, err := initConfig(a.Action != "" && (a.Silent || !a.Verbose))
	if err != nil {
		return err
	}
	a.Config = cfg
	return applySettingsConfigDefaults(a.Config, a.Settings, created)
}

// parseGlobalArgs separates global flags, one action, and action-specific
// arguments. The parser is deliberately small and strict so unexpected input is
// rejected before any privileged filesystem or service work begins.
func parseGlobalArgs(args []string) (*App, bool, error) {
	app := &App{}
	help := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-v", "--verbose":
			app.Verbose = true
		case "-y", "--yes":
			app.CommandLine = true
			app.AssumeYes = true
		case "-s", "--silent":
			app.CommandLine = true
			app.Silent = true
		case "-h", "--help":
			app.CommandLine = true
			help = true
		case "--":
			app.CommandLine = true
			app.Args = append(app.Args, args[i+1:]...)
			i = len(args)
		default:
			if isAllowListCLIAction(app.Action) {
				app.CommandLine = true
				app.Args = append(app.Args, arg)
			} else if normalized, ok := actionAliases[arg]; ok {
				app.CommandLine = true
				if app.Action != "" {
					return nil, false, fmt.Errorf("[ERROR] Only one action can be selected at a time: %s and %s", app.Action, arg)
				}
				app.Action = normalized
			} else if app.Action != "" {
				app.CommandLine = true
				app.Args = append(app.Args, arg)
			} else {
				return nil, false, fmt.Errorf("[ERROR] Unknown option or action: %s", arg)
			}
		}
	}
	if app.CommandLine && app.Action == "" && !help {
		return nil, false, fmt.Errorf("[ERROR] Command-line flags require an action. Run proxyble --help to list actions")
	}
	if app.Action == "--installation-add-riodb" && app.AssumeYes && !contains(app.Args, "--accept-license") {
		return nil, false, fmt.Errorf("[ERROR] Non-interactive option --yes also requires --accept-license when enabling RioDB")
	}
	return app, help, nil
}

// runCLIAction executes the canonical action selected by parseGlobalArgs.
// Runtime-affecting actions are gated on listener/backend completeness to avoid
// starting or mutating services before Proxyble has a usable HAProxy config.
func runCLIAction(ctx context.Context, a *App) error {
	if cliActionRequiresInstalledSoftware(a.Action) && !isInstalled() {
		return fmt.Errorf("Proxyble is not installed. Run proxyble --install first")
	}
	if cliActionRequiresRioDB(a.Action) && !riodbEnabled(a.Config) {
		return fmt.Errorf("RioDB analytics is not enabled. Run proxyble --installation-add-riodb --accept-license to enable policy workflows")
	}
	if cliActionRequiresRuntimeConfig(a.Action) && !runtimeConfigComplete(a.Config) {
		if err := a.PrepareLog("[proxyble] Runtime Config Preflight"); err != nil {
			return err
		}
		defer a.CloseLog()
		msg := fmt.Sprintf("Listener and backend need to be configured first. Complete --config-listener and --config-backend, or provide a complete %s.", defaultConfigFile)
		fmt.Fprintf(a.LogFile, "%s ACTION=CONFIG_GATE_FAILED CLI_ACTION=%s CONFIG_FILE=%s\n", logTimestamp(), a.Action, defaultConfigFile)
		fmt.Fprintf(a.LogFile, "%s MESSAGE=%s\n", logTimestamp(), msg)
		return fmt.Errorf("%s blocked. Full log: %s", msg, a.LogPath)
	}
	switch a.Action {
	case "--install":
		return installCLI(ctx, a)
	case "--installation-license":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Installation -> License"); err != nil {
			return err
		}
		defer a.CloseLog()
		return viewLicense(a)
	case "--installation-list":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Installation -> List"); err != nil {
			return err
		}
		defer a.CloseLog()
		return showComponentVersions(ctx, a)
	case "--installation-add-riodb":
		return addRioDBCLI(ctx, a)
	case "--installation-remove":
		return uninstallProxyble(ctx, a, a.Args)
	case "--config-listener":
		if err := a.PrepareLog("[proxyble] Config -> Listener"); err != nil {
			return err
		}
		defer a.CloseLog()
		return configureListenerAction(ctx, a, a.Args)
	case "--config-backend":
		if err := a.PrepareLog("[proxyble] Config -> Backend"); err != nil {
			return err
		}
		defer a.CloseLog()
		return configureBackendAction(ctx, a, a.Args)
	case "--config-status":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Config -> Status"); err != nil {
			return err
		}
		defer a.CloseLog()
		return showStatus(ctx, a)
	case "--config-start":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Config -> Start"); err != nil {
			return err
		}
		defer a.CloseLog()
		return startServices(ctx, a)
	case "--config-stop":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Config -> Stop"); err != nil {
			return err
		}
		defer a.CloseLog()
		return stopServices(ctx, a)
	case "--config-view":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Config -> View"); err != nil {
			return err
		}
		defer a.CloseLog()
		return viewConfig(a)
	case "--policies-view":
		if err := a.PrepareLog("[proxyble] Policies -> View"); err != nil {
			return err
		}
		defer a.CloseLog()
		return policiesList(a, a.Args)
	case "--policies-list":
		if err := a.PrepareLog("[proxyble] Policies -> List"); err != nil {
			return err
		}
		defer a.CloseLog()
		return policiesList(a, a.Args)
	case "--policies-deploy":
		if err := a.PrepareLog("[proxyble] Policies -> Deploy"); err != nil {
			return err
		}
		defer a.CloseLog()
		return policiesDeployCLI(ctx, a, a.Args)
	case "--policies-remove":
		if err := a.PrepareLog("[proxyble] Policies -> Remove"); err != nil {
			return err
		}
		defer a.CloseLog()
		return policiesRemoveCLI(ctx, a, a.Args)
	case "--policies-edit":
		return policiesEdit(ctx, a, a.Args)
	case "--rules-list":
		if err := noArgs(a); err != nil {
			return err
		}
		if err := a.PrepareLog("[proxyble] Rules -> List"); err != nil {
			return err
		}
		defer a.CloseLog()
		return listRules(a)
	case "--rules-add":
		if err := a.PrepareLog("[proxyble] Rules -> Add"); err != nil {
			return err
		}
		defer a.CloseLog()
		return addRule(ctx, a, a.Args)
	case "--rules-check":
		if err := a.PrepareLog("[proxyble] Rules -> Check IP"); err != nil {
			return err
		}
		defer a.CloseLog()
		return checkIP(ctx, a, a.Args)
	case "--rules-reset":
		if err := a.PrepareLog("[proxyble] Rules -> Reset"); err != nil {
			return err
		}
		defer a.CloseLog()
		return resetRules(ctx, a, a.Args)
	case "--basic-allow-list":
		if err := a.PrepareLog("[proxyble] Allow-list -> Basic"); err != nil {
			return err
		}
		defer a.CloseLog()
		return basicAllowListCLI(ctx, a, a.Args)
	case "--endpoint-allow-list":
		if err := a.PrepareLog("[proxyble] Allow-list -> Endpoint"); err != nil {
			return err
		}
		defer a.CloseLog()
		return endpointAllowListCLI(ctx, a, a.Args)
	default:
		return fmt.Errorf("no CLI action selected")
	}
}

// installCLI is the non-menu installation path and the shared implementation
// used by the interactive install selection after it has drawn its page.
func installCLI(ctx context.Context, a *App) error {
	opts, err := parseInstallOptions(a.Args)
	if err != nil {
		return err
	}
	if !opts.profileSet {
		opts.profile = selectedInstallProfile(a)
	}
	a.InstallProfile = opts.profile
	withRioDB := profileIncludesRioDB(opts.profile)
	if a.AssumeYes && withRioDB && !opts.acceptLicense {
		return fmt.Errorf("non-interactive option --yes also requires --accept-license when installing RioDB")
	}
	repair := isInstalled()
	ok, err := appConfirm(a, installConfirmPrompt(opts.profile, repair))
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return errActionCancelled
	}
	if withRioDB && !rioDBEULAAccepted(a, opts.acceptLicense) {
		notice := javaDependencyNoticeOptions(ctx, a)
		if a.CommandLine {
			lines, err := licenseDisplayLinesWithJavaNoticeContext(ctx, a, notice)
			if err != nil {
				return err
			}
			a.Printf("%s\n\n", strings.Join(lines, "\n"))
			ok, err = appConfirm(a, "Acknowledge the component notices, accept the RioDB EULA, and continue?")
		} else {
			ok, err = confirmInstallLicense(a, notice)
		}
		if err != nil || !ok {
			if err == nil {
				err = errActionCancelled
			}
			if !a.Silent {
				fmt.Println("[NOTICE] Required license acknowledgement was not accepted. Installation was not started.")
			}
			return err
		}
		a.AcceptedLicense = true
		a.AcceptedRioDBEULA = true
	} else if !withRioDB && !openSourceNoticesAcknowledged(a, opts.acceptLicense) {
		if a.CommandLine {
			if err := printNoticeLines(a, openSourceNoticeDisplayLines); err != nil {
				return err
			}
			ok, err = appConfirm(a, "Acknowledge the component notices and continue?")
		} else {
			ok, err = reviewAndAcknowledgeOpenSourceNoticesInteractive(a)
			if ok {
				actionPage("[proxyble] Installation -> Install", installProfileDescription(opts.profile))
			}
		}
		if err != nil || !ok {
			if err == nil {
				err = errActionCancelled
			}
			if !a.Silent {
				fmt.Println("[NOTICE] Required component notice acknowledgement was not accepted. Installation was not started.")
			}
			return err
		}
		a.AcceptedLicense = true
	}
	return runInstall(ctx, a)
}

type installOptions struct {
	profile       installProfile
	profileSet    bool
	acceptLicense bool
}

func parseInstallOptions(args []string) (installOptions, error) {
	opts := installOptions{profile: installProfileFull}
	profileSet := false
	for _, arg := range args {
		switch arg {
		case "--accept-license":
			opts.acceptLicense = true
		case "--with-riodb", "--full", "--full-install":
			if profileSet && opts.profile != installProfileFull {
				return opts, fmt.Errorf("--install cannot combine --with-riodb and --core-only")
			}
			opts.profile = installProfileFull
			opts.profileSet = true
			profileSet = true
		case "--core-only", "--proxyble-core", "--manual-rules-only":
			if profileSet && opts.profile != installProfileCore {
				return opts, fmt.Errorf("--install cannot combine --core-only and --with-riodb")
			}
			opts.profile = installProfileCore
			opts.profileSet = true
			profileSet = true
		default:
			return opts, fmt.Errorf("unexpected flag for --install: %s", arg)
		}
	}
	return opts, nil
}

func installConfirmPrompt(profile installProfile, repair bool) string {
	if repair {
		if profile == installProfileCore {
			return "Repair/re-install Proxyble Core components now?"
		}
		return "Repair/re-install Proxyble plus RioDB analytics now?"
	}
	if profile == installProfileCore {
		return "Install Proxyble Core for manual rule enforcement now?"
	}
	return "Install Proxyble plus RioDB analytics now?"
}

func rioDBEULAAccepted(a *App, explicit bool) bool {
	if explicit {
		return true
	}
	if a == nil {
		return false
	}
	return a.AcceptedRioDBEULA || riodbEnabled(a.Config)
}

func openSourceNoticesAcknowledged(a *App, explicit bool) bool {
	if explicit {
		return true
	}
	return a != nil && (a.AcceptedLicense || isInstalled())
}

func addRioDBCLI(ctx context.Context, a *App) error {
	accept := false
	for _, arg := range a.Args {
		if arg == "--accept-license" {
			accept = true
			continue
		}
		return fmt.Errorf("unexpected flag for --installation-add-riodb: %s", arg)
	}
	if a.AssumeYes && !accept {
		return fmt.Errorf("non-interactive option --yes also requires --accept-license when enabling RioDB")
	}
	if riodbEnabled(a.Config) {
		if err := a.PrepareLog("[proxyble] Installation -> Add RioDB"); err != nil {
			return err
		}
		defer a.CloseLog()
		a.Printf("[NOTICE] RioDB analytics is already enabled in %s.\n", defaultConfigFile)
		return nil
	}
	ok, err := appConfirm(a, "Enable RioDB analytics now?")
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return errActionCancelled
	}
	accepted := accept || (!a.CommandLine && a.AcceptedRioDBEULA)
	if !accepted {
		notice := javaDependencyNoticeOptions(ctx, a)
		if a.CommandLine {
			lines, err := rioDBLicenseDisplayLinesWithJavaNoticeContext(ctx, a, notice)
			if err != nil {
				return err
			}
			a.Printf("%s\n\n", strings.Join(lines, "\n"))
			ok, err = appConfirm(a, rioDBCLIConfirmPrompt(notice.IncludeJava))
		} else {
			ok, err = reviewAndAcceptRioDBLicenseInteractive(a)
			if ok {
				actionPage("[proxyble] Installation -> Add RioDB", "Enable RioDB analytics for real-time traffic detection.")
			}
		}
		if err != nil || !ok {
			if err == nil {
				err = errActionCancelled
			}
			if !a.Silent {
				fmt.Println("[NOTICE] RioDB EULA was not accepted. RioDB analytics was not enabled.")
			}
			return err
		}
		a.AcceptedLicense = true
		a.AcceptedRioDBEULA = true
	}
	return addRioDBAnalytics(ctx, a)
}

func printNoticeLines(a *App, build func(*App) ([]string, error)) error {
	lines, err := build(a)
	if err != nil {
		return err
	}
	a.Printf("%s\n\n", strings.Join(lines, "\n"))
	return nil
}

// confirmInstallLicense lets wizard users review the license before accepting
// it. CLI automation remains on typed y/N confirmation through appConfirm.
func confirmInstallLicense(a *App, notice javaNoticeOptions) (bool, error) {
	ok, err := reviewAndAcceptLicenseInteractiveWithJavaNotice(a, notice)
	if ok {
		actionPage("[proxyble] Installation -> Install", installProfileDescription(selectedInstallProfile(a)))
	}
	return ok, err
}

// cliActionRequiresInstalledSoftware matches command-line areas hidden by the
// wizard until Proxyble has been installed.
func cliActionRequiresInstalledSoftware(action string) bool {
	return action == "--installation-add-riodb" || isAllowListCLIAction(action) || strings.HasPrefix(action, "--config-") || strings.HasPrefix(action, "--policies-") || strings.HasPrefix(action, "--rules-")
}

func isAllowListCLIAction(action string) bool {
	return action == "--basic-allow-list" || action == "--endpoint-allow-list"
}

func cliActionRequiresRioDB(action string) bool {
	return strings.HasPrefix(action, "--policies-")
}

// cliActionRequiresRuntimeConfig identifies actions that should not run before
// listener and backend configuration exists.
func cliActionRequiresRuntimeConfig(action string) bool {
	return action == "--config-start" || action == "--config-stop" || strings.HasPrefix(action, "--policies-") || strings.HasPrefix(action, "--rules-")
}

// noArgs rejects action-specific arguments for commands that are intentionally
// argument-free.
func noArgs(a *App) error {
	if len(a.Args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected flag for %s: %s", a.Action, a.Args[0])
}

// runInteractive owns the top-level wizard loop and decides which major areas
// are visible based on installation and runtime configuration state.
func runInteractive(ctx context.Context, a *App) error {
	for {
		if !isInstalled() {
			choice, err := menu("[proxyble]", "Proxyble is not currently installed.\n\nChoose the components to install:", installProfileMenuItems())
			if err != nil {
				return err
			}
			switch choice {
			case "core":
				installed, err := installSelectedProfileInteractive(ctx, a, installProfileCore)
				if err != nil {
					return err
				}
				if installed {
					pause()
				}
			case "full":
				installed, err := installSelectedProfileInteractive(ctx, a, installProfileFull)
				if err != nil {
					return err
				}
				if installed {
					pause()
				}
			case "exit":
				return nil
			}
			continue
		}
		servicesNeedStart := runtimeConfigComplete(a.Config) && proxybleServicesNeedStart(ctx, a)
		items := mainMenuItems(a.Config, servicesNeedStart)
		choice, err := menu("[proxyble]", "Use this wizard to set up Proxyble and manage API protection\n\nChoose a management area:", items)
		if err != nil {
			return err
		}
		switch choice {
		case "installation":
			if err := runInstallationMenu(ctx, a); err != nil {
				return err
			}
		case "config":
			if err := runConfigMenu(ctx, a); err != nil {
				return err
			}
		case "policies":
			if err := runPoliciesMenu(ctx, a); err != nil {
				return err
			}
		case "rules":
			if err := runRulesMenu(ctx, a); err != nil {
				return err
			}
		case "allow-list":
			if err := runAllowListMenu(ctx, a); err != nil {
				return err
			}
		case "exit":
			return nil
		}
	}
}

func installSelectedProfileInteractive(ctx context.Context, a *App, profile installProfile) (bool, error) {
	a.InstallProfile = profile
	accepted, err := reviewAndConfirmInstallInteractive(ctx, a, profile)
	if err != nil {
		return false, err
	}
	if !accepted {
		return false, nil
	}
	a.AcceptedLicense = true
	a.AcceptedRioDBEULA = profileIncludesRioDB(profile)
	actionPage("[proxyble] Installation -> Install", installProfileDescription(profile))
	if err := ensureAppConfig(a); err != nil {
		return false, err
	}
	return true, runInstall(ctx, a)
}

func installProfileMenuItems() [][2]string {
	return [][2]string{
		{"full|Automated protection", "(Recommended) Detect anomalies and automate rule workflows;\nProxyble Core + RioDB analytics, with an always-free RioDB tier.\n"},
		{"core|Core only", "Control rules manually with open-source (GPLv2) Proxyble Core;\nRioDB automation can be added later.\n"},
		{"exit|Exit", ""},
	}
}

func mainMenuItems(c *Config, servicesNeedStart bool) [][2]string {
	configTag := "config"
	if !runtimeConfigComplete(c) || servicesNeedStart {
		configTag = "config!"
	}
	items := [][2]string{
		{"installation", "Install and remove software"},
		{configTag, "Configure and control Proxyble services"},
	}
	if haproxyListenerComplete(c) {
		items = append(items, [2]string{"allow-list", "Deny by default, allowing only specific sources"})
	}
	if runtimeConfigComplete(c) {
		items = append(items, [2]string{"rules", "Manually add or remove enforcement rules"})
		if riodbEnabled(c) {
			items = append(items, [2]string{"policies", "Detect threats with real-time analytics"})
		}
	}
	items = append(items, [2]string{"exit", "Exit this wizard"})
	return items
}

// runInstallationMenu handles install, remove, inventory, and license screens
// from the interactive wizard.
func runInstallationMenu(ctx context.Context, a *App) error {
	for {
		installed := isInstalled()
		items := installationMenuItems(a.Config, installed)
		choice, err := menu("[proxyble] Installation", "Installation actions manage Proxyble files and component inventory.", items)
		if err != nil {
			return err
		}
		switch choice {
		case "license":
			_ = a.PrepareLog("[proxyble] Installation -> License")
			_ = viewLicenseInteractive(a)
			a.CloseLog()
		case "list":
			_ = a.PrepareLog("[proxyble] Installation -> List")
			actionPage("[proxyble] Installation -> List", "View component versions.")
			_ = showComponentVersions(ctx, a)
			a.CloseLog()
			pause()
		case "install":
			if installed {
				actionPage("[proxyble] Installation -> Repair", "Re-run dependency checks and restore missing Proxyble components.")
			} else {
				actionPage("[proxyble] Installation -> Install", installProfileDescription(selectedInstallProfile(a)))
			}
			if err := installCLI(ctx, a); errors.Is(err, errActionCancelled) {
				continue
			} else if err != nil {
				return err
			}
			pause()
		case "add-riodb":
			actionPage("[proxyble] Installation -> Add RioDB", "Enable RioDB analytics for real-time traffic detection.")
			if err := addRioDBCLI(ctx, a); errors.Is(err, errActionCancelled) {
				continue
			} else if err != nil {
				return err
			}
			pause()
		case "remove":
			actionPage("[proxyble] Installation -> Remove", "Uninstall proxyble and all dependencies.")
			if err := uninstallProxyble(ctx, a, nil); errors.Is(err, errActionCancelled) {
				continue
			} else if err != nil {
				return err
			}
			pauseAnyKeyExit()
			return exitError{code: 0}
		case "back", "exit":
			return nil
		}
	}
}

func installationMenuItems(c *Config, installed bool) [][2]string {
	items := [][2]string{
		{"license", "Display component notices and RioDB EULA"},
		{"list", "View components in this release"},
	}
	if installed {
		items = append(items, [2]string{"install|Repair / re-install", "Re-run dependency checks and restore missing Proxyble components"})
	} else {
		items = append(items, [2]string{"install|Install Proxyble", "Install Proxyble and dependencies"})
	}
	if installed && !riodbEnabled(c) {
		items = append(items, [2]string{"add-riodb", "Add RioDB analytics and policy workflows"})
	}
	if installed {
		items = append(items, [2]string{"remove", "Uninstall proxyble and all dependencies"})
	}
	items = append(items, [2]string{"back", "Return to main menu"})
	return items
}

// runConfigMenu handles listener/backend setup plus service control and config
// viewing from the interactive wizard.
func runConfigMenu(ctx context.Context, a *App) error {
	for {
		servicesNeedStart := runtimeConfigComplete(a.Config) && proxybleServicesNeedStart(ctx, a)
		choice, err := menu("[proxyble] Config", "Define Proxyble settings and control its services.", configMenuItemsForState(a.Config, servicesNeedStart))
		if err != nil {
			return err
		}
		switch choice {
		case "listener":
			_ = a.PrepareLog("[proxyble] Config -> Listener")
			actionPage("[proxyble] Config -> Listener", "Configure the public listener that receives client traffic.")
			err = configureListenerAction(ctx, a, nil)
			a.CloseLog()
			if err != nil {
				if errors.Is(err, errActionCancelled) || strings.Contains(err.Error(), "listener configuration cancelled") {
					continue
				}
				return err
			}
			pause()
		case "backend":
			_ = a.PrepareLog("[proxyble] Config -> Backend")
			actionPage("[proxyble] Config -> Backend", "Define the backend server that receives allowed traffic.")
			err = configureBackendAction(ctx, a, nil)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			pause()
		case "status":
			_ = a.PrepareLog("[proxyble] Config -> Status")
			actionPage("[proxyble] Config -> Status", "Show Proxyble service status.")
			_ = showStatus(ctx, a)
			a.CloseLog()
			pause()
		case "start":
			_ = a.PrepareLog("[proxyble] Config -> Start")
			actionPage("[proxyble] Config -> Start", "Start all Proxyble services.")
			err = startServices(ctx, a)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			pause()
		case "stop":
			_ = a.PrepareLog("[proxyble] Config -> Stop")
			actionPage("[proxyble] Config -> Stop", "Stop Proxyble runtime services.")
			err = stopServices(ctx, a)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			pause()
		case "view":
			_ = a.PrepareLog("[proxyble] Config -> View")
			_ = viewConfigInteractive(a)
			a.CloseLog()
		case "back", "exit":
			return nil
		}
	}
}

func configMenuItems(c *Config) [][2]string {
	return configMenuItemsForState(c, false)
}

// configMenuItemsForState returns the Config menu entries and hides service
// controls until the runtime configuration is complete.
func configMenuItemsForState(c *Config, servicesNeedStart bool) [][2]string {
	listenerTag := "listener"
	if !haproxyListenerComplete(c) {
		listenerTag = "listener!"
	}
	backendTag := "backend"
	if !haproxyBackendComplete(c) {
		backendTag = "backend!"
	}
	items := [][2]string{
		{listenerTag, "Configure how incoming client requests are received"},
		{backendTag, "Define the server Proxyble protects"},
	}
	if runtimeConfigComplete(c) {
		startTag := "start"
		if servicesNeedStart {
			startTag = "start!"
		}
		items = append(items,
			[2]string{startTag, "Start all Proxyble services"},
			[2]string{"status", "Show service status"},
			[2]string{"stop", "Stop proxyble services"},
		)
	} else {
		items = append(items, [2]string{"status", "Show service status"})
	}
	items = append(items,
		[2]string{"view", "Show configuration"},
		[2]string{"back", "Return to main menu"},
	)
	return items
}

func proxybleServicesNeedStart(ctx context.Context, a *App) bool {
	if a == nil || a.Config == nil || !runtimeConfigComplete(a.Config) {
		return false
	}
	for _, unit := range proxybleRuntimeHealthUnits(a.Config) {
		if !systemctlQuiet(ctx, "is-enabled", "--quiet", unit) {
			return true
		}
		if !systemctlQuiet(ctx, "is-active", "--quiet", unit) {
			return true
		}
	}
	return false
}

func proxybleRuntimeHealthUnits(c *Config) []string {
	units := []string{
		"nftables.service",
		"haproxy.service",
		"proxyble-rule-agent.path",
		"proxyble-rule-agent.timer",
	}
	if riodbEnabled(c) {
		units = append([]string{"nftables.service", riodbServiceName(c)}, units[1:]...)
	}
	return units
}

// runPoliciesMenu handles Proxyble policy deployment and deactivation from the
// interactive wizard.
func runPoliciesMenu(ctx context.Context, a *App) error {
	if !riodbEnabled(a.Config) {
		return fmt.Errorf("RioDB analytics is not enabled. Use Installation -> Add RioDB analytics to enable policy workflows")
	}
	for {
		choice, err := menu("[proxyble] Policies", "Policies monitor traffic and automatically trigger rules.", [][2]string{
			{"deploy", "Choose policies to manage protection automatically"},
			{"view", "View and deactivate deployed policies"},
			{"back", "Return to main menu"},
		})
		if err != nil {
			return err
		}
		switch choice {
		case "deploy":
			_ = a.PrepareLog("[proxyble] Policies -> Deploy")
			err = deployPolicyInteractive(ctx, a)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			pause()
		case "view":
			_ = a.PrepareLog("[proxyble] Policies -> Deployed")
			err = viewDeployedPoliciesInteractive(ctx, a)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
		case "back", "exit":
			return nil
		}
	}
}

// runRulesMenu handles manual rule listing, addition, lookup, and reset from
// the interactive wizard.
func runRulesMenu(ctx context.Context, a *App) error {
	for {
		choice, err := menu("[proxyble] Rules", "Rules control client access to the backend server\n\nChoose a rule action.", [][2]string{
			{"list", "List rules currently in effect"},
			{"add", "Manually add a rule"},
			{"check IP", "Check if an IP address is affected by a rule"},
			{"reset", "Remove all rules currently in effect"},
			{"back", "Return to main menu"},
		})
		if err != nil {
			return err
		}
		switch choice {
		case "list":
			_ = a.PrepareLog("[proxyble] Rules -> List")
			actionPage("[proxyble] Rules -> List", "Rules currently controlling client access to the backend server.")
			_ = listRules(a)
			a.CloseLog()
			pause()
		case "add":
			_ = a.PrepareLog("[proxyble] Rules -> Add")
			err = addRule(ctx, a, nil)
			a.CloseLog()
			if err != nil {
				return err
			}
		case "check IP":
			_ = a.PrepareLog("[proxyble] Rules -> Check IP")
			err = checkIP(ctx, a, nil)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			pause()
		case "reset":
			_ = a.PrepareLog("[proxyble] Rules -> Reset")
			actionPage("[proxyble] Rules -> Reset", "Remove all rules currently in effect.")
			err = resetRules(ctx, a, nil)
			a.CloseLog()
			if errors.Is(err, errActionCancelled) {
				continue
			}
			if err != nil {
				return err
			}
			pause()
		case "back", "exit":
			return nil
		}
	}
}

// printGlobalHelp emits the compact action inventory for CLI users.
func printGlobalHelp() {
	fmt.Print(`Usage: proxyble [action] [action flags] [global flags]

Without an action, proxyble starts the interactive wizard.

Global flags:
  -y, --yes       Accept confirmations for the selected action.
  -s, --silent    Print nothing to the terminal.
  -v, --verbose   Print detailed action logs to the terminal.
  -h, --help      Print this help, or action help when used with an action.

Actions:
  --install                 Install Proxyble. Use --core-only or --with-riodb.
  --installation-license    Display component notices and the RioDB EULA.
  --installation-list       View component versions.
  --installation-add-riodb  Add RioDB analytics after a core install.
  --installation-remove     Uninstall Proxyble.

  --config-listener         Configure the public listener.
  --config-backend          Configure the protected backend.
  --config-status           Show service status.
  --config-start            Start all Proxyble services.
  --config-restart          Alias for --config-start.
  --config-stop             Stop Proxyble services.
  --config-view             Show the Proxyble configuration file.

  --policies-deploy         Deploy a compatible Proxyble policy.
  --policies-list           List deployed Proxyble policies.
  --policies-remove         Remove a deployed Proxyble policy.
  --policies-view           Alias for --policies-list.
  --policies-edit           Open an installed SQL file in an editor.

  --rules-list              List rules currently in effect.
  --rules-add               Add a manual rule.
  --rules-check             Check an IP and optionally remove a matching rule.
  --rules-reset             Reset active rules by type or all rules.

  --basic-allow-list        Add or remove Basic allow-list sources.
  --endpoint-allow-list     Add or remove endpoint allow-list source/path entries.
`)
}

// printActionHelp emits usage for actions whose accepted flags need extra
// explanation beyond the global help list.
func printActionHelp(action string) {
	switch action {
	case "--install":
		fmt.Println("Usage: proxyble --install [--core-only|--with-riodb] [--accept-license] [global flags]")
	case "--installation-add-riodb":
		fmt.Println("Usage: proxyble --installation-add-riodb [--accept-license] [global flags]")
	case "--installation-remove":
		fmt.Println("Usage: proxyble --installation-remove [--remove-java|--keep-java] [global flags]")
	case "--config-listener":
		fmt.Println("Usage: proxyble --config-listener --mode tcp|http|https --port PORT --timeout VALUE [flags] [global flags]")
	case "--config-backend":
		fmt.Println("Usage: proxyble --config-backend --primary-host HOST --primary-port PORT [flags] [global flags]")
	case "--config-start":
		fmt.Println("Usage: proxyble --config-start [global flags]")
	case "--policies-deploy":
		fmt.Println("Usage: proxyble --policies-deploy --policy POLICY [--restart-riodb] [global flags]")
	case "--policies-list", "--policies-view":
		fmt.Println("Usage: proxyble --policies-list [global flags]")
	case "--policies-remove":
		fmt.Println("Usage: proxyble --policies-remove --policy POLICY [--restart-riodb] [global flags]")
	case "--rules-add":
		fmt.Println("Usage: proxyble --rules-add --rule TYPE --target IP_OR_CIDR --expiration VALUE [rule flags] [global flags]")
	case "--rules-check":
		fmt.Println("Usage: proxyble --rules-check --ip IP [--remove] [selector flags] [global flags]")
	case "--rules-reset":
		fmt.Println("Usage: proxyble --rules-reset --type ALL|RULE_TYPE [global flags]")
	case "--basic-allow-list":
		fmt.Println("Usage: proxyble --basic-allow-list --add SOURCE | --remove SOURCE | --remove-all [--yes] [global flags]")
	case "--endpoint-allow-list":
		fmt.Println("Usage: proxyble --endpoint-allow-list --add SOURCE --endpoints PATH [PATH...] | --remove SOURCE --endpoints PATH [PATH...] | --remove-all [--yes] [global flags]")
	default:
		printGlobalHelp()
	}
}

package main

// system.go contains the operating-system boundary for Proxyble. It centralizes
// root checks, logging, command execution, platform detection, package manager
// calls, filesystem helpers, systemd wrappers, locking, and output routing.
// Future AI maintainers should prefer adding privileged or distribution-specific
// helpers here instead of scattering shell-style behavior through menu and
// action code.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// App carries process-wide state assembled during startup and passed through
// CLI actions and interactive menu handlers.
type App struct {
	Verbose                  bool
	AssumeYes                bool
	Silent                   bool
	CommandLine              bool
	AcceptedLicense          bool
	AcceptedRioDBEULA        bool
	InstallProfile           installProfile
	ConfigFileExistedAtStart bool
	Action                   string
	Args                     []string
	Config                   *Config
	Settings                 RuntimeSettings
	SettingsPath             string
	LogFile                  *os.File
	LogPath                  string
	SourceRoot               string
	InstalledNow             bool
}

// installProfile records the user's installation choice. A full install keeps
// the historical default behavior. A core install installs Proxyble, HAProxy,
// nftables, and the rule agent without enabling the proprietary RioDB analytics
// component.
type installProfile string

const (
	installProfileFull installProfile = "full"
	installProfileCore installProfile = "core"
)

// Platform describes the detected Linux distribution and the package manager
// commands this installer should use for it.
type Platform struct {
	ID             string
	VersionID      string
	Codename       string
	PrettyName     string
	Family         string
	PackageManager string
}

const (
	platformFamilyAmazon = "amazon"
	platformFamilyAzure  = "azure"
	platformFamilyDebian = "debian"
	platformFamilyRHEL   = "rhel"
)

// errActionCancelled is returned when a user intentionally cancels a menu
// action. Interactive menus treat it as "go back immediately" instead of
// showing an error or an extra pause.
var errActionCancelled = errors.New("action cancelled")

// CloseLog closes the current action log, allowing the next menu action to open
// its own audit file.
func (a *App) CloseLog() {
	if a.LogFile != nil {
		_ = a.LogFile.Close()
		a.LogFile = nil
	}
}

// Logf writes detailed messages to the action log and mirrors them to the
// terminal only when verbose output is enabled.
func (a *App) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if a.LogFile != nil {
		fmt.Fprint(a.LogFile, msg)
		if !strings.HasSuffix(msg, "\n") {
			fmt.Fprintln(a.LogFile)
		}
	}
	if !a.Silent && a.Verbose {
		fmt.Print(msg)
		if !strings.HasSuffix(msg, "\n") {
			fmt.Println()
		}
	}
}

// Printf writes user-visible action output and duplicates it into the current
// action log when one is open.
func (a *App) Printf(format string, args ...any) {
	if !a.Silent {
		fmt.Printf(format, args...)
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, format, args...)
	}
}

// PrepareLog opens a fresh timestamped log file for a single action or menu
// page.
func (a *App) PrepareLog(label string) error {
	a.CloseLog()
	dir := "/var/log/proxyble"
	if a.Config != nil {
		dir = a.Config.Get("proxyble", "log_dir", dir)
	}
	if err := mkdirAllNoSymlink(dir, 0o700); err != nil {
		return err
	}
	_ = chmodPath(dir, 0o700)
	safe := safeLogLabel(label)
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.log", safe, time.Now().Format("20060102-150405")))
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	a.LogFile = f
	a.LogPath = path
	return nil
}

// safeLogLabel turns a human action label into a conservative filename stem.
func safeLogLabel(label string) string {
	label = strings.ToLower(label)
	label = strings.NewReplacer(" ", "-", "[", "", "]", "", ">", "", "→", "").Replace(label)
	var b strings.Builder
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "proxyble"
	}
	return b.String()
}

// requireRoot blocks privileged installer work unless the process is running as
// root.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("[ERROR] Insufficient privileges. Please run as root (use sudo).")
	}
	return nil
}

// isTerminal reports whether f is an interactive character device.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && (info.Mode()&os.ModeCharDevice) != 0
}

// commandExists checks PATH for an executable command.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runCommand executes an external command with inherited environment and stdin,
// sending both stdout and stderr to out.
func runCommand(ctx context.Context, out io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	return cmd.Run()
}

// runCommandEnv executes an external command with additional environment values
// appended to the inherited environment.
func runCommandEnv(ctx context.Context, out io.Writer, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(), env...)
	return cmd.Run()
}

// downloadFile fetches one installer dependency without relying on curl/wget
// being present when Proxyble is launched directly instead of through install.sh.
func downloadFile(ctx context.Context, out io.Writer, url, dst string, mode fs.FileMode) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("download failed for %s: HTTP %s", url, resp.Status)
	}
	dir := filepath.Dir(dst)
	if err := mkdirAllNoSymlink(dir, 0o755); err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(dst); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proxyble-download-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	if out != nil {
		fmt.Fprintf(out, "[PASS] Downloaded %s\n", dst)
	}
	return nil
}

// firstLineCommand returns the first line of a version/status command for
// component inventory screens.
func firstLineCommand(ctx context.Context, name string, args ...string) string {
	if strings.Contains(name, "/") {
		if st, err := os.Stat(name); err != nil || st.Mode()&0o111 == 0 {
			return fmt.Sprintf("not installed (%s is not executable)", name)
		}
	} else if !commandExists(name) {
		return fmt.Sprintf("not installed (%s not found)", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	line := strings.SplitN(strings.TrimRight(buf.String(), "\n"), "\n", 2)[0]
	if line == "" {
		if err == nil {
			return "installed (no version output)"
		}
		return fmt.Sprintf("version command failed: %v", err)
	}
	if err != nil {
		return fmt.Sprintf("%s (%v)", line, err)
	}
	return line
}

// detectPlatform reads os-release and chooses the supported package-management
// strategy for compatible systemd/glibc Linux families.
func detectPlatform() (Platform, error) {
	values, err := readHostOSRelease()
	if err != nil {
		return Platform{}, fmt.Errorf("cannot detect Linux distribution: %w", err)
	}
	if !systemdAvailable() {
		return Platform{}, fmt.Errorf("unsupported host: Proxyble requires a running systemd host")
	}
	return platformFromOSRelease(values, commandExists)
}

func platformFromOSRelease(values map[string]string, hasCommand func(string) bool) (Platform, error) {
	if hasCommand == nil {
		hasCommand = commandExists
	}
	p := Platform{
		ID:         values["ID"],
		VersionID:  values["VERSION_ID"],
		Codename:   firstNonEmpty(values["VERSION_CODENAME"], values["UBUNTU_CODENAME"]),
		PrettyName: values["PRETTY_NAME"],
	}
	if p.PrettyName == "" {
		p.PrettyName = strings.TrimSpace(firstNonEmpty(values["NAME"], p.ID) + " " + p.VersionID)
	}
	id := strings.ToLower(strings.TrimSpace(p.ID))
	likes := osReleaseLikes(values)
	switch id {
	case "amzn":
		p.Family = platformFamilyAmazon
		p.PackageManager = firstAvailableCommand(hasCommand, "dnf", "yum")
	case "azurelinux", "mariner", "cbl-mariner":
		p.Family = platformFamilyAzure
		p.PackageManager = firstAvailableCommand(hasCommand, "tdnf", "dnf", "yum")
	case "ubuntu", "debian":
		p.Family = platformFamilyDebian
		p.PackageManager = firstAvailableCommand(hasCommand, "apt-get")
	case "rhel", "redhat", "ol", "oracle", "rocky", "almalinux", "centos", "fedora":
		p.Family = platformFamilyRHEL
		p.PackageManager = firstAvailableCommand(hasCommand, "dnf", "yum")
	case "clear-linux-os", "clear":
		return Platform{}, fmt.Errorf("unsupported Linux distribution: %s; Clear Linux uses swupd bundles and needs a dedicated Proxyble package/service adapter", p.PrettyName)
	default:
		switch {
		case containsAnyToken(likes, "debian", "ubuntu"):
			p.Family = platformFamilyDebian
			p.PackageManager = firstAvailableCommand(hasCommand, "apt-get")
		case containsAnyToken(likes, "rhel", "centos", "fedora"):
			p.Family = platformFamilyRHEL
			p.PackageManager = firstAvailableCommand(hasCommand, "dnf", "yum")
		default:
			return Platform{}, fmt.Errorf("unsupported Linux distribution: %s; supported families: Debian/Ubuntu, RHEL-compatible, Amazon Linux, and Azure Linux", p.PrettyName)
		}
	}
	if p.PackageManager == "" {
		return Platform{}, fmt.Errorf("unsupported Linux distribution: %s; no supported package manager found for %s family", p.PrettyName, p.Family)
	}
	return p, nil
}

func readHostOSRelease() (map[string]string, error) {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		values, err := readOSRelease(path)
		if err == nil {
			return values, nil
		}
	}
	return nil, os.ErrNotExist
}

func osReleaseLikes(values map[string]string) []string {
	var tokens []string
	for _, token := range strings.Fields(values["ID_LIKE"]) {
		token = strings.ToLower(strings.Trim(token, `"'`))
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func containsAnyToken(tokens []string, wants ...string) bool {
	for _, token := range tokens {
		for _, want := range wants {
			if token == want {
				return true
			}
		}
	}
	return false
}

func firstAvailableCommand(hasCommand func(string) bool, names ...string) string {
	for _, name := range names {
		if hasCommand(name) {
			return name
		}
	}
	return ""
}

func systemdAvailable() bool {
	if !commandExists("systemctl") {
		return false
	}
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

// readOSRelease parses /etc/os-release style key/value files.
func readOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		values[strings.TrimSpace(k)] = v
	}
	return values, scanner.Err()
}

// packageUpdate refreshes package metadata using the detected distribution's
// package manager.
func packageUpdate(ctx context.Context, p Platform, out io.Writer) error {
	switch p.PackageManager {
	case "dnf":
		err := withPackageMemoryGuard(ctx, p, out, p.PackageManager, "--setopt=max_parallel_downloads=1", "-q", "makecache", "--timer")
		if err == nil {
			return nil
		}
		fmt.Fprintln(out, "[NOTICE] Package metadata refresh did not complete; continuing because installs refresh metadata on demand.")
		return nil
	case "yum":
		if err := withPackageMemoryGuard(ctx, p, out, p.PackageManager, "-q", "makecache", "-y"); err == nil {
			return nil
		}
		fmt.Fprintln(out, "[NOTICE] Package metadata refresh did not complete; continuing because installs refresh metadata on demand.")
		return nil
	case "tdnf":
		if err := runCommand(ctx, out, p.PackageManager, "makecache"); err == nil {
			return nil
		}
		fmt.Fprintln(out, "[NOTICE] Package metadata refresh did not complete; continuing because installs refresh metadata on demand.")
		return nil
	case "apt-get":
		return runCommandEnv(ctx, out, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update")
	default:
		return fmt.Errorf("unsupported package manager: %s", p.PackageManager)
	}
}

// packageInstall installs one or more OS packages using the detected package
// manager.
func packageInstall(ctx context.Context, p Platform, out io.Writer, packages ...string) error {
	if len(packages) == 0 {
		return errors.New("packageInstall called without package names")
	}
	switch p.PackageManager {
	case "dnf":
		args := append([]string{"--setopt=max_parallel_downloads=1", "--setopt=install_weak_deps=False", "install", "-y"}, packages...)
		return withPackageMemoryGuard(ctx, p, out, p.PackageManager, args...)
	case "yum":
		args := append([]string{"install", "-y"}, packages...)
		return withPackageMemoryGuard(ctx, p, out, p.PackageManager, args...)
	case "tdnf":
		args := append([]string{"install", "-y"}, packages...)
		return runCommand(ctx, out, p.PackageManager, args...)
	case "apt-get":
		args := append([]string{"install", "-y"}, packages...)
		return runCommandEnv(ctx, out, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", args...)
	default:
		return fmt.Errorf("unsupported package manager: %s", p.PackageManager)
	}
}

// packageRemove removes one OS package using the detected package manager.
func packageRemove(ctx context.Context, p Platform, out io.Writer, pkg string) error {
	switch p.PackageManager {
	case "dnf":
		return withPackageMemoryGuard(ctx, p, out, p.PackageManager, "--setopt=max_parallel_downloads=1", "remove", "-y", pkg)
	case "yum":
		return withPackageMemoryGuard(ctx, p, out, p.PackageManager, "remove", "-y", pkg)
	case "tdnf":
		return runCommand(ctx, out, p.PackageManager, "remove", "-y", pkg)
	case "apt-get":
		return runCommandEnv(ctx, out, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "purge", "-y", pkg)
	default:
		return fmt.Errorf("unsupported package manager: %s", p.PackageManager)
	}
}

// memoryTotalMB returns host RAM in megabytes from /proc/meminfo.
func memoryTotalMB() int {
	return meminfoMB("MemTotal")
}

// swapTotalMB returns configured swap in megabytes from /proc/meminfo.
func swapTotalMB() int {
	return meminfoMB("SwapTotal")
}

const packageSwapFileSizeBytes int64 = 1024 * 1024 * 1024

// meminfoMB reads one numeric kilobyte field from /proc/meminfo and converts it
// to megabytes.
func meminfoMB(key string) int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && strings.TrimSuffix(fields[0], ":") == key {
			kb, _ := strconv.Atoi(fields[1])
			return kb / 1024
		}
	}
	return 0
}

// withPackageMemoryGuard adds temporary swap for low-memory Amazon Linux hosts
// before running memory-hungry package manager operations.
func withPackageMemoryGuard(ctx context.Context, p Platform, out io.Writer, name string, args ...string) error {
	if p.Family != platformFamilyAmazon || memoryTotalMB() >= 1536 || swapTotalMB() >= 512 {
		return runCommand(ctx, out, name, args...)
	}
	swapFile := "/var/tmp/proxyble-installer.swap"
	enabled := false
	prepared := false
	if commandExists("swapon") && commandExists("mkswap") {
		fmt.Fprintf(out, "[NOTICE] Low-memory host detected; enabling temporary package-install swap at %s\n", swapFile)
		if err := preparePackageSwapFile(ctx, out, swapFile, packageSwapFileSizeBytes); err != nil {
			return err
		}
		prepared = true
		if err := runCommand(ctx, out, "mkswap", swapFile); err == nil {
			if err := runCommand(ctx, out, "swapon", swapFile); err == nil {
				enabled = true
			}
		}
	}
	if prepared && !enabled {
		_ = os.Remove(swapFile)
	}
	err := runCommand(ctx, out, name, args...)
	if enabled {
		_ = runCommand(ctx, out, "swapoff", swapFile)
		_ = os.Remove(swapFile)
		fmt.Fprintln(out, "[NOTICE] Temporary package-install swap removed.")
	}
	return err
}

func preparePackageSwapFile(ctx context.Context, out io.Writer, path string, size int64) error {
	if err := mkdirAllNoSymlink(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(path); err != nil {
		return err
	}
	if swapFileActive(path) {
		if err := runCommand(ctx, out, "swapoff", path); err != nil {
			return fmt.Errorf("disable existing temporary swap: %w", err)
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return createAllocatedFile(path, size, 0o600)
}

func createAllocatedFile(path string, size int64, mode fs.FileMode) error {
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if err := syscall.Fallocate(int(f.Fd()), 0, 0, size); err != nil {
		if err := f.Truncate(0); err != nil {
			return err
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := writeZeroFile(f, size); err != nil {
			return err
		}
	} else if err := f.Truncate(size); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func writeZeroFile(f *os.File, size int64) error {
	buf := make([]byte, 1024*1024)
	for remaining := size; remaining > 0; {
		n := len(buf)
		if remaining < int64(n) {
			n = int(remaining)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		remaining -= int64(n)
	}
	return nil
}

func swapFileActive(path string) bool {
	f, err := os.Open("/proc/swaps")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[0] == path {
			return true
		}
	}
	return false
}

// mkdirOwned creates a directory tree, applies owner/group, and enforces the
// final permission mode.
func mkdirOwned(path string, mode fs.FileMode, owner, group string) error {
	if err := mkdirAllNoSymlink(path, mode); err != nil {
		return err
	}
	if err := chownPath(path, owner, group); err != nil {
		return err
	}
	return chmodPath(path, mode)
}

// chownPath resolves owner/group names and applies them to one path.
func chownPath(path, ownerName, groupName string) error {
	uid, gid, err := lookupOwnerGroup(ownerName, groupName)
	if err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(path); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(path, uid, gid)
}

// chownRecursive resolves owner/group names once and applies them throughout a
// directory tree.
func chownRecursive(path, ownerName, groupName string) error {
	uid, gid, err := lookupOwnerGroup(ownerName, groupName)
	if err != nil {
		return err
	}
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to chown symlinked path: %s", p)
		}
		return os.Lchown(p, uid, gid)
	})
}

func lookupOwnerGroup(ownerName, groupName string) (int, int, error) {
	uid, gid := -1, -1
	if ownerName != "" {
		u, err := user.Lookup(ownerName)
		if err != nil {
			return -1, -1, err
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return -1, -1, err
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return uid, gid, nil
}

func mkdirAllNoSymlink(path string, mode fs.FileMode) error {
	if err := rejectSymlinkInPath(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return rejectSymlinkInPath(path)
}

func chmodPath(path string, mode fs.FileMode) error {
	if err := rejectSymlinkIfExists(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func openFileNoFollow(path string, flags int, mode fs.FileMode) (*os.File, error) {
	if err := rejectSymlinkInPath(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func rejectSymlinkIfExists(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to manage symlinked path: %s", path)
	}
	return nil
}

func rejectSymlinkInPath(path string) error {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return rejectSymlinkIfExists(clean)
	}
	current := "."
	rest := clean
	if filepath.IsAbs(clean) {
		current = string(filepath.Separator)
		rest = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to manage path through symlink: %s", current)
		}
	}
	return nil
}

// chmodRecursive applies one permission mode throughout a directory tree.
func chmodRecursive(path string, mode fs.FileMode) error {
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to chmod symlinked path: %s", p)
		}
		return os.Chmod(p, mode)
	})
}

// touchFile ensures a file exists and has the requested permission mode.
func touchFile(path string, mode fs.FileMode) error {
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_APPEND, mode)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return chmodPath(path, mode)
}

// atomicWriteFile writes data to a temporary file in the destination directory
// and renames it into place to avoid partially-written config files.
func atomicWriteFile(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := mkdirAllNoSymlink(dir, 0o755); err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proxyble-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// copyFile copies one regular file through a temporary file and handles the
// src==dst case without truncating the running binary.
func copyFile(src, dst string, mode fs.FileMode) error {
	if err := rejectSymlinkIfExists(src); err != nil {
		return err
	}
	if err := rejectSymlinkIfExists(dst); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if same, err := sameFile(src, dst); err == nil && same {
		return chmodPath(dst, mode)
	}
	if err := mkdirAllNoSymlink(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".proxyble-copy-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	_, copyErr := io.Copy(tmp, in)
	if copyErr != nil {
		_ = tmp.Close()
		return copyErr
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, dst)
}

// sameFile reports whether two paths resolve to the same filesystem object.
func sameFile(a, b string) (bool, error) {
	aInfo, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bInfo, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(aInfo, bInfo), nil
}

// copyDir recursively copies regular files from src to dst, allowing callers to
// skip paths such as development utilities.
func copyDir(src, dst string, skip func(string, fs.DirEntry) bool) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skip != nil && skip(path, d) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlinked path: %s", path)
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return mkdirAllNoSymlink(target, info.Mode().Perm())
		}
		if info.Mode().Type() != 0 {
			return nil
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

// safeRemovePath refuses broad system paths before removing installer-owned
// files during uninstall.
func safeRemovePath(path, preserveLogDir string) error {
	path = filepath.Clean(path)
	if path == filepath.Clean(preserveLogDir) {
		return nil
	}
	unsafe := map[string]bool{
		"": true, "/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true,
		"/home": true, "/lib": true, "/lib64": true, "/opt": true, "/proc": true,
		"/root": true, "/run": true, "/sbin": true, "/sys": true, "/tmp": true,
		"/usr": true, "/usr/local": true, "/usr/local/bin": true, "/var": true,
		"/var/lib": true, "/var/log": true, "/var/tmp": true,
	}
	if unsafe[path] {
		return fmt.Errorf("refusing to remove unsafe path: %s", path)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("refusing to remove non-absolute path: %s", path)
	}
	if err := rejectSymlinkInPath(path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// systemctl runs systemctl with combined output routed to the provided writer.
func systemctl(ctx context.Context, out io.Writer, args ...string) error {
	return runCommand(ctx, out, "systemctl", args...)
}

// systemctlQuiet runs systemctl for boolean probes where terminal output would
// be noisy.
func systemctlQuiet(ctx context.Context, args ...string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// timeoutCommand runs a command with a caller-specified timeout in seconds.
func timeoutCommand(ctx context.Context, out io.Writer, seconds int, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	err := runCommand(cctx, out, name, args...)
	if cctx.Err() == context.DeadlineExceeded {
		return cctx.Err()
	}
	return err
}

// lockFile obtains an exclusive advisory flock for rule-state maintenance.
func lockFile(path string) (*os.File, error) {
	if err := mkdirAllNoSymlink(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = chmodPath(filepath.Dir(path), 0o700)
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("could not acquire lock: %s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// unlockFile releases and closes a file previously returned by lockFile.
func unlockFile(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// findResourceRoot locates the directory that contains bundled settings,
// assets, and installable files for either development or installed execution.
func findResourceRoot() string {
	exe, err := os.Executable()
	if err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if root, ok := parentResourceRoot(dir); ok {
				return root
			}
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, "bin")); err == nil {
			return dir
		}
	}
	if _, err := os.Stat("/opt/proxyble"); err == nil {
		return "/opt/proxyble"
	}
	if wd, err := os.Getwd(); err == nil {
		if root, ok := parentResourceRoot(wd); ok {
			return root
		}
		return wd
	}
	return "."
}

func parentResourceRoot(dir string) (string, bool) {
	if filepath.Base(dir) != "src" {
		return "", false
	}
	parent := filepath.Dir(dir)
	for _, name := range []string{"bin", "templates"} {
		if _, err := os.Stat(filepath.Join(parent, name)); err == nil {
			return parent, true
		}
	}
	return "", false
}

// multiOutput returns a writer that records to the action log and optionally
// mirrors output to the terminal.
func multiOutput(log io.Writer, terminal bool) io.Writer {
	if log == nil {
		if terminal {
			return os.Stdout
		}
		return io.Discard
	}
	if terminal {
		return io.MultiWriter(os.Stdout, log)
	}
	return log
}

// stepOutput returns the normal writer for detailed install/service steps.
func stepOutput(a *App) io.Writer {
	return multiOutput(a.LogFile, a.Verbose && !a.Silent)
}

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

// config.go owns Proxyble's persistent INI configuration file. It creates the
// first-run template, loads the file into a small section/key map, and writes
// individual values back without forcing operators to hand-edit generated
// service configuration. Future AI maintainers should treat this file as the
// contract between user choices, runtime settings, HAProxy rendering, RioDB
// setup, and rule-agent behavior.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// defaultConfigDir and defaultConfigFile are the canonical installed
// configuration locations.
const (
	defaultConfigDir  = "/etc/proxyble"
	defaultConfigFile = "/etc/proxyble/config.ini"

	defaultRuleDir         = "/var/spool/proxyble/rules"
	defaultRuleInbox       = defaultRuleDir + "/inbox.tmp"
	legacyDefaultRuleDir   = "/var/tmp/rules"
	legacyDefaultRuleInbox = legacyDefaultRuleDir + "/inbox.tmp"

	defaultRuleAgentRuntimeDir = "/run/proxyble-rule-agent"
	defaultRuleAgentLockFile   = defaultRuleAgentRuntimeDir + "/rule_agent.lock"

	defaultRioDBInstallDir       = "/opt"
	defaultRioDBAppSubdir        = "riodb"
	legacyDefaultRioDBInstallDir = "/opt/riodb-01"

	defaultRioDBUDPTCPRequestArrivalLogPort     = "5241"
	defaultRioDBUDPTCPRequestCompletionLogPort  = "5242"
	defaultRioDBUDPHTTPRequestArrivalLogPort    = "5243"
	defaultRioDBUDPHTTPRequestCompletionLogPort = "5244"
	defaultRioDBMetricLogLayers                 = "request-completion"
)

// configTemplate is the minimal root-owned configuration written on first run.
// Keep defaults conservative: RioDB starts disabled. The UDP log ports remain
// visible so advanced operators can change the HAProxy/RioDB contract before
// enabling analytics; the rest of the RioDB service details are added later.
var configTemplate = strings.TrimLeft(`
# Proxyble configuration.
# This file is created and maintained by the Proxyble wizard.
# Keep this file owned by root and writable only by root.

[proxyble]
install_dir=/opt/proxyble
launcher_path=/usr/local/bin/proxyble
log_dir=/var/log/proxyble

[java]
version=17
installed_by_proxyble=false

[traffic]
mode=tcp

[riodb]
enabled=false
udp_tcp_request_arrival_log_port=5241
udp_tcp_request_completion_log_port=5242
udp_http_request_arrival_log_port=5243
udp_http_request_completion_log_port=5244
metrics_log_layers=request-completion

[haproxy]
enabled=false
listener_port=
timeout=60s
certificate_path=
backend_primary_host=
backend_primary_port=
backend_secondary_host=
backend_secondary_port=
maps_dir=/etc/haproxy/maps
runtime_dir=/run/haproxy
chroot_dir=/var/lib/haproxy

[nftables]
enabled=true
table_family=inet
table_name=pmgr
managed_chain=managed_rules
input_chain=input
blacklist_set=blacklist

[rule_agent]
enabled=true
binary_path=/usr/local/bin/proxyble-rule-agent
rule_dir=/var/spool/proxyble/rules
watch_file=/var/spool/proxyble/rules/inbox.tmp
state_dir=/var/lib/proxyble-rule-agent
log_dir=/var/log/proxyble-rule-agent
`, "\n")

var defaultRioDBConfig = []struct {
	key   string
	value string
}{
	{"udp_tcp_request_arrival_log_port", defaultRioDBUDPTCPRequestArrivalLogPort},
	{"udp_tcp_request_completion_log_port", defaultRioDBUDPTCPRequestCompletionLogPort},
	{"udp_http_request_arrival_log_port", defaultRioDBUDPHTTPRequestArrivalLogPort},
	{"udp_http_request_completion_log_port", defaultRioDBUDPHTTPRequestCompletionLogPort},
	{"metrics_log_layers", defaultRioDBMetricLogLayers},
	{"user", "riodb"},
	{"group", "riodb"},
	{"install_dir", defaultRioDBInstallDir},
	{"app_subdir", defaultRioDBAppSubdir},
	{"log_dir", "/var/log/riodb"},
	{"service_name", "riodb.service"},
	{"logger_config", "conf/logback_service.xml"},
	{"keystore_relative_path", ".ssl/keystore.jks"},
	{"keystore_password", "pass_for_self_signed_cert"},
	{"keystore_distinguished_name", "CN=localhost, OU=Developers, O=Bull Bytes, L=Linz, C=AT"},
}

// Config is the in-memory representation of config.ini. Data is intentionally
// simple because this program only needs flat keys grouped by named sections.
type Config struct {
	Path string
	Data map[string]map[string]string
}

// initConfig ensures config.ini exists with secure ownership and permissions,
// then returns the parsed config plus whether this invocation created it.
func initConfig(quiet bool) (*Config, bool, error) {
	if err := mkdirOwned(defaultConfigDir, 0o700, "root", "root"); err != nil {
		return nil, false, err
	}
	created := false
	if _, err := os.Stat(defaultConfigFile); os.IsNotExist(err) {
		if err := atomicWriteFile(defaultConfigFile, []byte(configTemplate), 0o600); err != nil {
			return nil, false, err
		}
		if err := chownPath(defaultConfigFile, "root", "root"); err != nil {
			return nil, false, err
		}
		created = true
		if !quiet {
			fmt.Printf("[PASS] Proxyble config initialized (%s)\n", defaultConfigFile)
		}
	} else if err != nil {
		return nil, false, err
	} else {
		if err := chownPath(defaultConfigFile, "root", "root"); err != nil {
			return nil, false, err
		}
		if err := chmodPath(defaultConfigFile, 0o600); err != nil {
			return nil, false, err
		}
		if !quiet {
			fmt.Printf("[PASS] Proxyble config permissions verified (%s)\n", defaultConfigFile)
		}
	}
	cfg, err := loadConfig(defaultConfigFile)
	return cfg, created, err
}

// loadConfig parses the subset of INI syntax used by Proxyble: comments, blank
// lines, section headers, and key=value pairs.
func loadConfig(path string) (*Config, error) {
	cfg := &Config{Path: path, Data: map[string]map[string]string{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	defer f.Close()
	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if cfg.Data[section] == nil {
				cfg.Data[section] = map[string]string{}
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if ok && section != "" {
			if cfg.Data[section] == nil {
				cfg.Data[section] = map[string]string{}
			}
			cfg.Data[section][strings.TrimSpace(key)] = strings.TrimSpace(val)
		}
	}
	return cfg, scanner.Err()
}

// Get returns a non-empty configured value or def when the section/key is unset.
func (c *Config) Get(section, key, def string) string {
	if c == nil {
		return def
	}
	if sec, ok := c.Data[section]; ok {
		if val, ok := sec[key]; ok && val != "" {
			return val
		}
	}
	return def
}

// Raw returns the configured value exactly as stored, including an empty string
// when the key exists but has not been filled in yet.
func (c *Config) Raw(section, key string) string {
	if c == nil {
		return ""
	}
	if sec, ok := c.Data[section]; ok {
		return sec[key]
	}
	return ""
}

// Set updates the in-memory value and persists the same value to config.ini.
func (c *Config) Set(section, key, value string) error {
	if c.Data[section] == nil {
		c.Data[section] = map[string]string{}
	}
	c.Data[section][key] = value
	return setIniValue(c.Path, section, key, value)
}

// setIniValue edits a single INI key while preserving unrelated lines and
// comments as much as possible for operator readability.
func setIniValue(path, section, key, value string) error {
	input, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(input))
	inSection := false
	seenSection := false
	updated := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inSection && !updated {
				fmt.Fprintf(&out, "%s=%s\n", key, value)
				updated = true
			}
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			inSection = name == section
			if inSection {
				seenSection = true
			}
			fmt.Fprintln(&out, line)
			continue
		}
		if inSection {
			k, _, ok := strings.Cut(trimmed, "=")
			if ok && strings.TrimSpace(k) == key {
				fmt.Fprintf(&out, "%s=%s\n", key, value)
				updated = true
				continue
			}
		}
		fmt.Fprintln(&out, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !seenSection {
		if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
			out.WriteByte('\n')
		}
		fmt.Fprintf(&out, "\n[%s]\n%s=%s\n", section, key, value)
	} else if inSection && !updated {
		fmt.Fprintf(&out, "%s=%s\n", key, value)
	}
	if err := atomicWriteFile(path, out.Bytes(), 0o600); err != nil {
		return err
	}
	return chownPath(path, "root", "root")
}

// configIsTrue normalizes common truthy strings used by config.ini and service
// toggles.
func configIsTrue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

// riodbEnabled reports whether this host has opted into RioDB analytics.
func riodbEnabled(c *Config) bool {
	return configIsTrue(c.Get("riodb", "enabled", "false"))
}

// javaInstalledByProxyble reports whether this installation installed Java
// itself. Hosts that already had Java keep this false, but teardown still offers
// Java removal when a supported Java package is present.
func javaInstalledByProxyble(c *Config) bool {
	return configIsTrue(c.Get("java", "installed_by_proxyble", "false"))
}

// configuredRioDBUDPPort returns a RioDB UDP listener port from config.ini.
func configuredRioDBUDPPort(c *Config, key, def, label string) (string, error) {
	port := strings.TrimSpace(c.Get("riodb", key, def))
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("riodb %s must be a number between 1 and 65535", label)
	}
	return port, nil
}

// configuredRioDBUDPTCPRequestArrivalLogPort returns the UDP port RioDB listens
// on for HAProxy TCP request-arrival logs.
func configuredRioDBUDPTCPRequestArrivalLogPort(c *Config) (string, error) {
	return configuredRioDBUDPPort(c, "udp_tcp_request_arrival_log_port", defaultRioDBUDPTCPRequestArrivalLogPort, "udp_tcp_request_arrival_log_port")
}

// configuredRioDBUDPTCPRequestCompletionLogPort returns the UDP port RioDB
// listens on for HAProxy TCP request-completion logs.
func configuredRioDBUDPTCPRequestCompletionLogPort(c *Config) (string, error) {
	return configuredRioDBUDPPort(c, "udp_tcp_request_completion_log_port", defaultRioDBUDPTCPRequestCompletionLogPort, "udp_tcp_request_completion_log_port")
}

// configuredRioDBUDPHTTPRequestArrivalLogPort returns the UDP port RioDB
// listens on for HAProxy HTTP/HTTPS request-arrival logs.
func configuredRioDBUDPHTTPRequestArrivalLogPort(c *Config) (string, error) {
	return configuredRioDBUDPPort(c, "udp_http_request_arrival_log_port", defaultRioDBUDPHTTPRequestArrivalLogPort, "udp_http_request_arrival_log_port")
}

// configuredRioDBUDPHTTPRequestCompletionLogPort returns the UDP port RioDB
// listens on for HAProxy HTTP/HTTPS request-completion logs.
func configuredRioDBUDPHTTPRequestCompletionLogPort(c *Config) (string, error) {
	return configuredRioDBUDPPort(c, "udp_http_request_completion_log_port", defaultRioDBUDPHTTPRequestCompletionLogPort, "udp_http_request_completion_log_port")
}

func configuredRioDBUDPLogPortsForMode(c *Config, mode string) (arrivalPort, completionPort string, err error) {
	mode, err = ruleAgentModeForTraffic(mode)
	if err != nil {
		return "", "", err
	}
	if mode == "http" {
		arrivalPort, err = configuredRioDBUDPHTTPRequestArrivalLogPort(c)
		if err != nil {
			return "", "", err
		}
		completionPort, err = configuredRioDBUDPHTTPRequestCompletionLogPort(c)
		return arrivalPort, completionPort, err
	}
	arrivalPort, err = configuredRioDBUDPTCPRequestArrivalLogPort(c)
	if err != nil {
		return "", "", err
	}
	completionPort, err = configuredRioDBUDPTCPRequestCompletionLogPort(c)
	return arrivalPort, completionPort, err
}

func configuredRioDBUDPCompletionLogPortForMode(c *Config, mode string) (string, error) {
	_, completionPort, err := configuredRioDBUDPLogPortsForMode(c, mode)
	return completionPort, err
}

func validateConfiguredRioDBUDPLogPorts(c *Config) error {
	for _, check := range []func(*Config) (string, error){
		configuredRioDBUDPTCPRequestArrivalLogPort,
		configuredRioDBUDPTCPRequestCompletionLogPort,
		configuredRioDBUDPHTTPRequestArrivalLogPort,
		configuredRioDBUDPHTTPRequestCompletionLogPort,
	} {
		if _, err := check(c); err != nil {
			return err
		}
	}
	return nil
}

// enableRioDBConfig turns on RioDB analytics and fills any missing service
// defaults without overwriting operator-customized values.
func enableRioDBConfig(c *Config) error {
	if err := c.Set("riodb", "enabled", "true"); err != nil {
		return err
	}
	if filepath.Clean(c.Raw("riodb", "install_dir")) == legacyDefaultRioDBInstallDir {
		if err := c.Set("riodb", "install_dir", defaultRioDBInstallDir); err != nil {
			return err
		}
	}
	for _, item := range defaultRioDBConfig {
		if strings.TrimSpace(c.Raw("riodb", item.key)) != "" {
			continue
		}
		if err := c.Set("riodb", item.key, item.value); err != nil {
			return err
		}
	}
	return nil
}

// disableRioDBConfig keeps the core install lightweight. Existing RioDB path
// details are preserved in case an operator disables and later re-enables it.
func disableRioDBConfig(c *Config) error {
	return c.Set("riodb", "enabled", "false")
}

// normalizeTrafficMode validates the supported Proxyble listener modes.
func normalizeTrafficMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "tcp", "http", "https":
		return strings.ToLower(strings.TrimSpace(mode)), nil
	default:
		return "", fmt.Errorf("invalid traffic mode: %s", mode)
	}
}

// TrafficMode returns the configured traffic mode with the same validation used
// by prompts and CLI flags.
func (c *Config) TrafficMode() (string, error) {
	return normalizeTrafficMode(c.Get("traffic", "mode", "tcp"))
}

// ruleAgentModeForTraffic maps listener mode to the mode understood by the rule
// agent; HTTPS is enforced through HAProxy HTTP-level rules after TLS handling.
func ruleAgentModeForTraffic(mode string) (string, error) {
	mode, err := normalizeTrafficMode(mode)
	if err != nil {
		return "", err
	}
	if mode == "https" {
		return "http", nil
	}
	return mode, nil
}

// riodbInstallDir returns the configured RioDB installation root.
func riodbInstallDir(c *Config) string {
	return c.Get("riodb", "install_dir", defaultRioDBInstallDir)
}

// riodbAppSubdir returns the subdirectory created by the RioDB archive.
func riodbAppSubdir(c *Config) string {
	return c.Get("riodb", "app_subdir", defaultRioDBAppSubdir)
}

// riodbHome returns the installed RioDB application directory.
func riodbHome(c *Config) string {
	return filepath.Join(riodbInstallDir(c), riodbAppSubdir(c))
}

// riodbUser returns the Unix user that owns and runs RioDB.
func riodbUser(c *Config) string {
	return c.Get("riodb", "user", "riodb")
}

// riodbGroup returns the Unix group that owns and runs RioDB.
func riodbGroup(c *Config) string {
	return c.Get("riodb", "group", "riodb")
}

// riodbLogDir returns the RioDB log directory.
func riodbLogDir(c *Config) string {
	return c.Get("riodb", "log_dir", "/var/log/riodb")
}

// riodbServiceName returns the systemd unit name used for RioDB.
func riodbServiceName(c *Config) string {
	return c.Get("riodb", "service_name", "riodb.service")
}

// riodbLoggerConfig returns the RioDB logger config path relative to RioDB home.
func riodbLoggerConfig(c *Config) string {
	return c.Get("riodb", "logger_config", "conf/logback_service.xml")
}

// riodbKeystoreRelativePath returns the generated keystore path relative to
// RioDB home.
func riodbKeystoreRelativePath(c *Config) string {
	return c.Get("riodb", "keystore_relative_path", ".ssl/keystore.jks")
}

// riodbKeystorePath returns the full generated RioDB keystore path.
func riodbKeystorePath(c *Config) string {
	return filepath.Join(riodbHome(c), riodbKeystoreRelativePath(c))
}

// riodbKeystorePassword returns the password used for the generated keystore.
func riodbKeystorePassword(c *Config) string {
	return c.Get("riodb", "keystore_password", "pass_for_self_signed_cert")
}

// riodbKeystoreDistinguishedName returns the subject used for the generated
// RioDB self-signed keystore.
func riodbKeystoreDistinguishedName(c *Config) string {
	return c.Get("riodb", "keystore_distinguished_name", "CN=localhost, OU=Developers, O=Bull Bytes, L=Linz, C=AT")
}

// riodbJVMOptionsScript returns RioDB's bundled JVM options generator path.
func riodbJVMOptionsScript(c *Config) string {
	return filepath.Join(riodbHome(c), "bin", "generate-jvm-options.sh")
}

// riodbConfDir returns the installed RioDB configuration directory.
func riodbConfDir(c *Config) string {
	return filepath.Join(riodbHome(c), "conf")
}

// runtimeConfigComplete reports whether the listener and backend are both ready
// enough for service control, policy, and rule operations.
func runtimeConfigComplete(c *Config) bool {
	return haproxyListenerComplete(c) && haproxyBackendComplete(c)
}

// isInstalled checks for the installed config marker used by the interactive
// wizard to decide whether to show only installation options.
func isInstalled() bool {
	if _, err := os.Stat(defaultConfigFile); err != nil {
		return false
	}
	candidates := []string{
		"/usr/local/bin/proxyble-rule-agent",
		filepath.Join(defaultRioDBInstallDir, defaultRioDBAppSubdir),
		"/etc/systemd/system/proxyble-rule-agent.service",
		"/etc/systemd/system/riodb.service",
		"/etc/haproxy/haproxy.cfg",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	return false
}

// configPath returns the canonical path for help text and diagnostics.
func configPath() string {
	return filepath.Clean(defaultConfigFile)
}

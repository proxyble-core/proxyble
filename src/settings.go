package main

// settings.go defines the small runtime settings file read from
// bin/riodb-settings.json. Keep this file focused on release inputs that should
// change without recompiling Proxyble: Java package selection, the RioDB archive
// name, and RioDB download servers. OS package names, rule-agent binary names,
// and ordinary RioDB service defaults belong in Go constants or config.ini
// instead.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Runtime package constants are intentionally hardcoded because Proxyble always
// installs these component packages/binaries by their canonical names.
const (
	defaultSettingsName        = "riodb-settings.json"
	defaultHAProxyPackage      = "haproxy"
	defaultNFTablesPackage     = "nftables"
	defaultRuleAgentBinaryName = "proxyble-rule-agent"
)

// RuntimeSettings is the top-level JSON schema consumed by the installer.
type RuntimeSettings struct {
	Java  SettingsJava  `json:"java"`
	RioDB SettingsRioDB `json:"riodb"`
}

// SettingsJava stores the Java major version, default package, and optional
// per-OS overrides.
type SettingsJava struct {
	Version string                         `json:"version"`
	Default SettingsJavaPackage            `json:"default"`
	ByOS    map[string]SettingsJavaPackage `json:"by_os"`
}

// SettingsJavaPackage identifies the installable Java package and display label
// for one OS family or default fallback.
type SettingsJavaPackage struct {
	Package string `json:"package"`
	Label   string `json:"label"`
}

// SettingsRioDB stores RioDB payload metadata so release payload changes do not
// require recompiling the Go installer.
type SettingsRioDB struct {
	ArchivePath     string   `json:"archive_path"`
	DownloadServers []string `json:"download_servers"`
}

// defaultRuntimeSettings returns built-in values used when no settings file is
// present or when a settings file omits optional fields.
func defaultRuntimeSettings() RuntimeSettings {
	return RuntimeSettings{
		Java: SettingsJava{
			Version: "17",
			Default: SettingsJavaPackage{
				Package: "openjdk-17-jre-headless",
				Label:   "OpenJDK Java 17 (headless)",
			},
			ByOS: map[string]SettingsJavaPackage{
				platformFamilyAmazon: {
					Package: "java-17-amazon-corretto-headless",
					Label:   "Amazon Corretto Java 17 (headless)",
				},
				platformFamilyAzure: {
					Package: "msopenjdk-17",
					Label:   "Microsoft Build of OpenJDK 17",
				},
				platformFamilyRHEL: {
					Package: "java-17-openjdk-headless",
					Label:   "OpenJDK Java 17 (headless)",
				},
			},
		},
		RioDB: SettingsRioDB{
			ArchivePath: "riodb-lin-x86.2026-3.tar.gz",
			DownloadServers: []string{
				"https://www.riodb.co/downloads/2026-6/",
				"https://www.proxyble.com/downloads/2026-6/",
			},
		},
	}
}

// loadRuntimeSettings reads the first available settings file and fills omitted
// fields with built-in defaults.
func loadRuntimeSettings(sourceRoot string) (RuntimeSettings, string, error) {
	settings := defaultRuntimeSettings()
	for _, path := range settingsCandidates(sourceRoot) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(data, &settings); err != nil {
			return settings, path, fmt.Errorf("invalid settings file %s: %w", path, err)
		}
		settings.fillDefaults()
		return settings, path, nil
	}
	settings.fillDefaults()
	return settings, "", nil
}

// settingsCandidates returns riodb-settings.json search paths in override order.
func settingsCandidates(sourceRoot string) []string {
	var candidates []string
	if envPath := os.Getenv("PROXYBLE_RIODB_SETTINGS"); envPath != "" {
		candidates = append(candidates, envPath)
	}
	if sourceRoot != "" {
		candidates = append(candidates, filepath.Join(sourceRoot, "bin", defaultSettingsName))
	}
	candidates = append(candidates, filepath.Join("/opt/proxyble/bin", defaultSettingsName))
	return candidates
}

// fillDefaults overlays built-in values onto an already-decoded settings file.
func (s *RuntimeSettings) fillDefaults() {
	d := defaultRuntimeSettings()
	if s.Java.Version == "" {
		s.Java.Version = d.Java.Version
	}
	if s.Java.Default.Package == "" {
		s.Java.Default.Package = d.Java.Default.Package
	}
	if s.Java.Default.Label == "" {
		s.Java.Default.Label = d.Java.Default.Label
	}
	if s.Java.ByOS == nil {
		s.Java.ByOS = d.Java.ByOS
	} else {
		for family, def := range d.Java.ByOS {
			current := s.Java.ByOS[family]
			if current.Package == "" {
				current.Package = def.Package
			}
			if current.Label == "" {
				current.Label = def.Label
			}
			s.Java.ByOS[family] = current
		}
	}
	if strings.TrimSpace(s.RioDB.ArchivePath) == "" {
		s.RioDB.ArchivePath = d.RioDB.ArchivePath
	}
	if len(s.RioDB.DownloadServers) == 0 {
		s.RioDB.DownloadServers = d.RioDB.DownloadServers
	}
}

// JavaPackage returns an OS-specific Java package when configured, otherwise the
// default Java package.
func (s RuntimeSettings) JavaPackage(family string) (SettingsJavaPackage, error) {
	if pkg, ok := s.Java.ByOS[family]; ok && pkg.Package != "" {
		return pkg, nil
	}
	if s.Java.Default.Package == "" {
		return s.Java.Default, fmt.Errorf("runtime settings have no default Java package")
	}
	return s.Java.Default, nil
}

// applySettingsConfigDefaults copies runtime settings defaults into config.ini
// so later actions read one consistent source of truth. Some defaults are also
// backfilled into older configs when the key is safe and operator-editable.
func applySettingsConfigDefaults(c *Config, s RuntimeSettings, created bool) error {
	if created {
		if err := c.Set("java", "version", s.Java.Version); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		key   string
		value string
	}{
		{"udp_tcp_request_arrival_log_port", defaultRioDBUDPTCPRequestArrivalLogPort},
		{"udp_tcp_request_completion_log_port", defaultRioDBUDPTCPRequestCompletionLogPort},
		{"udp_http_request_arrival_log_port", defaultRioDBUDPHTTPRequestArrivalLogPort},
		{"udp_http_request_completion_log_port", defaultRioDBUDPHTTPRequestCompletionLogPort},
	} {
		if strings.TrimSpace(c.Raw("riodb", item.key)) != "" {
			continue
		}
		if err := c.Set("riodb", item.key, item.value); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.Raw("riodb", "metrics_log_layers")) == "" {
		return c.Set("riodb", "metrics_log_layers", defaultRioDBMetricLogLayers)
	}
	return nil
}

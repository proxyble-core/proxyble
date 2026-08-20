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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const defaultDependenciesName = "dependencies.json"

// DependencySettings contains release compatibility requirements for external
// software used by Proxyble.
type DependencySettings struct {
	Dependencies Dependencies `json:"dependencies"`
}

// Dependencies groups the external software requirements in the manifest.
type Dependencies struct {
	Java    JavaDependency    `json:"java"`
	RioDB   RioDBDependency   `json:"riodb"`
	HAProxy HAProxyDependency `json:"haproxy"`
}

// JavaDependency stores the Java runtime version and package selection.
type JavaDependency struct {
	Version string                 `json:"version"`
	Default JavaPackage            `json:"default"`
	ByOS    map[string]JavaPackage `json:"by_os"`
}

// JavaPackage identifies the installable Java package and display label for
// one OS family.
type JavaPackage struct {
	Package string `json:"package"`
	Label   string `json:"label"`
}

// RioDBDependency stores release payload metadata for RioDB analytics.
type RioDBDependency struct {
	ArchivePath     string   `json:"archive_path"`
	DownloadServers []string `json:"download_servers"`
}

// HAProxyDependency defines the package name and supported version interval.
type HAProxyDependency struct {
	Package             string `json:"package"`
	MinVersionSupported string `json:"min_version_supported"`
	MaxVersionExclusive string `json:"max_version_exclusive"`
}

type dependencyVersion struct {
	major int
	minor int
	patch int
}

var dependencyVersionPattern = regexp.MustCompile(`(?:^|[^0-9])(\d+)\.(\d+)(?:\.(\d+))?`)

func loadDependencySettings(sourceRoot string) (DependencySettings, string, error) {
	for _, path := range dependencySettingsCandidates(sourceRoot) {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return DependencySettings{}, path, fmt.Errorf("read dependency settings %s: %w", path, err)
		}
		settings := defaultDependencySettings()
		if err := json.Unmarshal(data, &settings); err != nil {
			return settings, path, fmt.Errorf("invalid dependency settings %s: %w", path, err)
		}
		settings.fillDefaults()
		if err := settings.validate(); err != nil {
			return settings, path, fmt.Errorf("invalid dependency settings %s: %w", path, err)
		}
		return settings, path, nil
	}
	return DependencySettings{}, "", fmt.Errorf("required %s was not found", defaultDependenciesName)
}

// defaultDependencySettings supplies release defaults when optional manifest
// fields are omitted.
func defaultDependencySettings() DependencySettings {
	return DependencySettings{Dependencies: Dependencies{
		Java: JavaDependency{
			Version: "17",
			Default: JavaPackage{
				Package: "openjdk-17-jre-headless",
				Label:   "OpenJDK Java 17 (headless)",
			},
			ByOS: map[string]JavaPackage{
				platformFamilyAmazon: {Package: "java-17-amazon-corretto-headless", Label: "Amazon Corretto Java 17 (headless)"},
				platformFamilyAzure:  {Package: "msopenjdk-17", Label: "Microsoft Build of OpenJDK 17"},
				platformFamilyRHEL:   {Package: "java-17-openjdk-headless", Label: "OpenJDK Java 17 (headless)"},
			},
		},
		RioDB: RioDBDependency{
			ArchivePath: "riodb-lin-x86.2026-3.tar.gz",
			DownloadServers: []string{
				"https://www.riodb.co/downloads/2026-6/",
				"https://www.proxyble.com/downloads/2026-6/",
			},
		},
		HAProxy: HAProxyDependency{
			Package:             "haproxy",
			MinVersionSupported: "2.8.0",
			MaxVersionExclusive: "3.1.0",
		},
	}}
}

func dependencySettingsCandidates(sourceRoot string) []string {
	var candidates []string
	if sourceRoot != "" {
		candidates = append(candidates, filepath.Join(sourceRoot, "bin", defaultDependenciesName))
	}
	installed := filepath.Join("/opt/proxyble/bin", defaultDependenciesName)
	if len(candidates) == 0 || candidates[0] != installed {
		candidates = append(candidates, installed)
	}
	return candidates
}

func (s DependencySettings) validate() error {
	h := s.Dependencies.HAProxy
	if strings.TrimSpace(h.Package) == "" {
		return fmt.Errorf("dependencies.haproxy.package is required")
	}
	min, err := parseDependencyVersion(h.MinVersionSupported)
	if err != nil {
		return fmt.Errorf("dependencies.haproxy.min_version_supported: %w", err)
	}
	max, err := parseDependencyVersion(h.MaxVersionExclusive)
	if err != nil {
		return fmt.Errorf("dependencies.haproxy.max_version_exclusive: %w", err)
	}
	if compareDependencyVersions(min, max) >= 0 {
		return fmt.Errorf("HAProxy minimum version must be lower than the exclusive maximum")
	}
	return nil
}

func (s *DependencySettings) fillDefaults() {
	d := defaultDependencySettings()
	if s.Dependencies.Java.Version == "" {
		s.Dependencies.Java.Version = d.Dependencies.Java.Version
	}
	if s.Dependencies.Java.Default.Package == "" {
		s.Dependencies.Java.Default.Package = d.Dependencies.Java.Default.Package
	}
	if s.Dependencies.Java.Default.Label == "" {
		s.Dependencies.Java.Default.Label = d.Dependencies.Java.Default.Label
	}
	if s.Dependencies.Java.ByOS == nil {
		s.Dependencies.Java.ByOS = d.Dependencies.Java.ByOS
	}
	for family, def := range d.Dependencies.Java.ByOS {
		current := s.Dependencies.Java.ByOS[family]
		if current.Package == "" {
			current.Package = def.Package
		}
		if current.Label == "" {
			current.Label = def.Label
		}
		s.Dependencies.Java.ByOS[family] = current
	}
	if strings.TrimSpace(s.Dependencies.RioDB.ArchivePath) == "" {
		s.Dependencies.RioDB.ArchivePath = d.Dependencies.RioDB.ArchivePath
	}
	if len(s.Dependencies.RioDB.DownloadServers) == 0 {
		s.Dependencies.RioDB.DownloadServers = d.Dependencies.RioDB.DownloadServers
	}
}

// JavaPackage returns an OS-specific Java package when configured, otherwise
// the default Java package.
func (s DependencySettings) JavaPackage(family string) (JavaPackage, error) {
	if pkg, ok := s.Dependencies.Java.ByOS[family]; ok && pkg.Package != "" {
		return pkg, nil
	}
	if s.Dependencies.Java.Default.Package == "" {
		return s.Dependencies.Java.Default, fmt.Errorf("dependency settings have no default Java package")
	}
	return s.Dependencies.Java.Default, nil
}

// applyDependencyConfigDefaults copies dependency defaults into config.ini.
func applyDependencyConfigDefaults(c *Config, s DependencySettings, created bool) error {
	if created {
		if err := c.Set("java", "version", s.Dependencies.Java.Version); err != nil {
			return err
		}
	}
	for _, item := range []struct{ key, value string }{
		{"udp_tcp_request_arrival_log_port", defaultRioDBUDPTCPRequestArrivalLogPort},
		{"udp_tcp_request_completion_log_port", defaultRioDBUDPTCPRequestCompletionLogPort},
		{"udp_http_request_arrival_log_port", defaultRioDBUDPHTTPRequestArrivalLogPort},
		{"udp_http_request_completion_log_port", defaultRioDBUDPHTTPRequestCompletionLogPort},
	} {
		if strings.TrimSpace(c.Raw("riodb", item.key)) == "" {
			if err := c.Set("riodb", item.key, item.value); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(c.Raw("riodb", "metrics_log_layers")) == "" {
		return c.Set("riodb", "metrics_log_layers", defaultRioDBMetricLogLayers)
	}
	return nil
}

func (h HAProxyDependency) supports(versionText string) (bool, error) {
	version, err := parseDependencyVersion(versionText)
	if err != nil {
		return false, err
	}
	min, err := parseDependencyVersion(h.MinVersionSupported)
	if err != nil {
		return false, err
	}
	max, err := parseDependencyVersion(h.MaxVersionExclusive)
	if err != nil {
		return false, err
	}
	return compareDependencyVersions(version, min) >= 0 && compareDependencyVersions(version, max) < 0, nil
}

func (h HAProxyDependency) rangeDescription() string {
	return fmt.Sprintf(">=%s and <%s", h.MinVersionSupported, h.MaxVersionExclusive)
}

func parseDependencyVersion(text string) (dependencyVersion, error) {
	match := dependencyVersionPattern.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return dependencyVersion{}, fmt.Errorf("cannot parse version from %q", text)
	}
	parts := [3]int{}
	for i := range parts {
		if match[i+1] == "" {
			continue
		}
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return dependencyVersion{}, fmt.Errorf("cannot parse version from %q", text)
		}
		parts[i] = n
	}
	return dependencyVersion{major: parts[0], minor: parts[1], patch: parts[2]}, nil
}

func compareDependencyVersions(a, b dependencyVersion) int {
	if a.major != b.major {
		return a.major - b.major
	}
	if a.minor != b.minor {
		return a.minor - b.minor
	}
	return a.patch - b.patch
}

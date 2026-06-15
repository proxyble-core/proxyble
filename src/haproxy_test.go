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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildHAProxyConfigOmitsRioDBUDPSinkWhenDisabled(t *testing.T) {
	cfg := testHAProxyConfig("tcp", false, "2444")
	body, err := buildHAProxyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"127.0.0.1:",
		"log-format",
		"log global",
		"option  tcplog",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("core-only HAProxy config should not contain %q\n%s", forbidden, body)
		}
	}
	if !strings.Contains(body, "tcp-request connection reject") {
		t.Fatalf("core-only HAProxy config should still include enforcement rules\n%s", body)
	}
}

func TestBuildHAProxyConfigUsesConfiguredRioDBUDPPortForTCP(t *testing.T) {
	cfg := testHAProxyConfig("tcp", true, "2444")
	body, err := buildHAProxyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"log 127.0.0.1:2444 format raw local0",
		"option  tcplog",
		`log-format '{"schema":"proxyble_tcp_request_completion_v1"`,
		`"bytes_sent":%B`,
		`"session_duration_ms":%Tt`,
		`"source_conn_cur":%[sc_conn_cur(0)]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HAProxy TCP config missing %q\n%s", want, body)
		}
	}
}

func TestBuildHAProxyConfigUsesHTTPLogFormatWhenRioDBEnabled(t *testing.T) {
	cfg := testHAProxyConfig("http", true, "2445")
	body, err := buildHAProxyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"log 127.0.0.1:2445 format raw local0",
		"option  httplog",
		`log-format '{"schema":"proxyble_http_request_completion_v1"`,
		`"method":"%[var(txn.method),json(utf8s)]"`,
		`"path":"%[var(txn.path),json(utf8s)]"`,
		`"status_code":%ST`,
		`"response_header_time_ms":%Tr`,
		`"cache_status":"%[var(txn.cache_status),json(utf8s)]"`,
		"http-response set-var(txn.cache_status) res.fhdr(cache-status)",
		"http-response set-var(txn.x_cache) res.fhdr(x-cache)",
		"http-response set-var(txn.response_content_length) res.fhdr(content-length)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HAProxy HTTP config missing %q\n%s", want, body)
		}
	}
	if strings.Contains(haproxyCompletionLogFormat("http"), "res.fhdr(") {
		t.Fatalf("HTTP completion log-format should use captured txn vars, not direct response-header fetches")
	}
	if strings.Contains(body, `"schema":"proxyble_tcp`) {
		t.Fatalf("HTTP mode should not render TCP schemas\n%s", body)
	}
}

func TestBuildHAProxyHTTPConfigPassesHAProxySyntaxWhenAvailable(t *testing.T) {
	haproxy, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy binary is not installed")
	}
	versionOut, err := exec.Command(haproxy, "-v").CombinedOutput()
	if err != nil {
		t.Skipf("haproxy -v failed: %v", err)
	}
	versionLine := strings.SplitN(strings.TrimSpace(string(versionOut)), "\n", 2)[0]
	if branch := haproxyVersionBranch(versionLine); branch != haproxyRequiredBranch {
		t.Skipf("haproxy branch %q installed; syntax test targets %s", branch, haproxyRequiredBranch)
	}

	cfg := testHAProxyConfig("http", true, "2445")
	body, err := buildHAProxyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mapDir := t.TempDir()
	for _, name := range []string{"rules.map", "params.map", "endpoint-rates.map"} {
		if err := os.WriteFile(filepath.Join(mapDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body = strings.ReplaceAll(body, "/etc/haproxy/maps", mapDir)
	body = strings.ReplaceAll(body, "    chroot /var/lib/haproxy\n", "")
	body = strings.ReplaceAll(body, "    user haproxy\n", "")
	body = strings.ReplaceAll(body, "    group haproxy\n", "")
	body = strings.ReplaceAll(body, "/run/haproxy/admin.sock", filepath.Join(t.TempDir(), "admin.sock"))
	body = strings.ReplaceAll(body, " group "+haproxyRuntimeAdminGroup, " group root")

	configPath := filepath.Join(t.TempDir(), "haproxy.cfg")
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(haproxy, "-c", "-f", configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("haproxy rejected rendered HTTP config: %v\n%s\n\n%s", err, out, body)
	}
}

func TestBuildHAProxyConfigSupportsTCPRequestArrivalAndCompletionDrains(t *testing.T) {
	cfg := testHAProxyConfig("tcp", true, "5242")
	cfg.Data["riodb"]["udp_tcp_request_arrival_log_port"] = "5241"
	cfg.Data["riodb"]["metrics_log_layers"] = "both"
	body, err := buildHAProxyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"log-profile proxyble_riodb_request_arrival",
		`on tcp-req-conn format '{"schema":"proxyble_tcp_request_arrival_v1"`,
		`"policy_action":"%[var(sess.ip_action),json(utf8s)]"`,
		"log 127.0.0.1:5241 format raw profile proxyble_riodb_request_arrival local0",
		"tcp-request connection do-log",
		"log-profile proxyble_riodb_request_completion",
		`on close format '{"schema":"proxyble_tcp_request_completion_v1"`,
		`"bytes_uploaded":%U`,
		"log 127.0.0.1:5242 format raw profile proxyble_riodb_request_completion local0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HAProxy TCP dual-layer config missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "log 127.0.0.1:5242 format raw local0") {
		t.Fatalf("dual-layer logging should use profile-specific drains, not the legacy global drain\n%s", body)
	}
}

func TestBuildHAProxyConfigSupportsHTTPRequestArrivalOnlyDrain(t *testing.T) {
	cfg := testHAProxyConfig("http", true, "5244")
	cfg.Data["riodb"]["udp_http_request_arrival_log_port"] = "5243"
	cfg.Data["riodb"]["metrics_log_layers"] = "request-arrival"
	body, err := buildHAProxyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"log-profile proxyble_riodb_request_arrival",
		`on http-req format '{"schema":"proxyble_http_request_arrival_v1"`,
		`"client_key":"%[var(txn.client_key),json(utf8s)]"`,
		`"endpoint_rate_current":%[var(txn.endpoint_rate)]`,
		"log 127.0.0.1:5243 format raw profile proxyble_riodb_request_arrival local0",
		"http-request set-var(txn.user) req.hdr(user)",
		"http-request set-var(txn.ip_action) src,map_ip(/etc/haproxy/maps/rules.map)",
		"http-request set-var(txn.client_key) req.fhdr(x-proxyble-client-key)",
		"http-request do-log",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HAProxy HTTP request-arrival config missing %q\n%s", want, body)
		}
	}
	for _, forbidden := range []string{
		"127.0.0.1:5244",
		"proxyble_riodb_request_completion",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("request-arrival-only config should not contain %q\n%s", forbidden, body)
		}
	}
}

func TestBuildHAProxyConfigRejectsInvalidRioDBUDPPort(t *testing.T) {
	cfg := testHAProxyConfig("tcp", true, "70000")
	if _, err := buildHAProxyConfig(cfg); err == nil {
		t.Fatalf("invalid RioDB UDP port should block HAProxy rendering")
	}
}

func TestBuildHAProxyConfigRejectsInvalidRioDBRequestArrivalUDPPort(t *testing.T) {
	cfg := testHAProxyConfig("tcp", true, "5244")
	cfg.Data["riodb"]["udp_tcp_request_arrival_log_port"] = "70000"
	cfg.Data["riodb"]["metrics_log_layers"] = "request-arrival"
	if _, err := buildHAProxyConfig(cfg); err == nil {
		t.Fatalf("invalid RioDB request-arrival UDP port should block HAProxy rendering")
	}
}

func TestHAProxyVersionBranch(t *testing.T) {
	line := "HAProxy version 3.3.10-36 2026/05/11 - https://haproxy.org/"
	if got := haproxyVersionBranch(line); got != haproxyRequiredBranch {
		t.Fatalf("haproxyVersionBranch = %q, want %q", got, haproxyRequiredBranch)
	}
}

func TestHAProxyAPTCodename(t *testing.T) {
	tests := []struct {
		name string
		p    Platform
		want string
	}{
		{
			name: "ubuntu 26.04 resolute",
			p:    Platform{ID: "ubuntu", VersionID: "26.04", Codename: "resolute"},
			want: "resolute",
		},
		{
			name: "future ubuntu codename",
			p:    Platform{ID: "ubuntu", VersionID: "28.04", Codename: "future"},
			want: "future",
		},
		{
			name: "future debian codename",
			p:    Platform{ID: "debian", VersionID: "14", Codename: "forky"},
			want: "forky",
		},
		{
			name: "missing codename",
			p:    Platform{ID: "ubuntu", VersionID: "22.04"},
			want: "",
		},
		{
			name: "unsafe codename",
			p:    Platform{ID: "ubuntu", VersionID: "26.04", Codename: "resolute main"},
			want: "",
		},
		{
			name: "unsupported apt distro",
			p:    Platform{ID: "mint", VersionID: "22", Codename: "wilma"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := haproxyAPTCodename(tt.p); got != tt.want {
				t.Fatalf("haproxyAPTCodename = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHAProxyAPTReleaseURLUsesDetectedCodename(t *testing.T) {
	got := haproxyAPTReleaseURL("ubuntu", "resolute")
	want := "https://www.haproxy.com/download/haproxy/performance/ubuntu/ha33/dists/resolute/Release"
	if got != want {
		t.Fatalf("haproxyAPTReleaseURL = %q, want %q", got, want)
	}
}

func TestHAProxyAPTSourceLineAllowsAMD64AndARM64(t *testing.T) {
	got := haproxyAPTSourceLine("/usr/share/keyrings/HAPROXY-key-community.asc", "ubuntu", "noble")
	for _, want := range []string{
		"deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/HAPROXY-key-community.asc]",
		"https://www.haproxy.com/download/haproxy/performance/ubuntu/ha33 noble main",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("haproxyAPTSourceLine missing %q in %q", want, got)
		}
	}
}

func TestHAProxyRPMRepoBodyUsesDNFBaseArch(t *testing.T) {
	got := haproxyRPMRepoBody("9")
	for _, want := range []string{
		"[haproxy-33]",
		"baseurl=https://www.haproxy.com/download/haproxy/performance/rhel/ha33/el9/$basearch",
		"gpgkey=" + haproxyRPMKeyURL,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("haproxyRPMRepoBody missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "x86_64") {
		t.Fatalf("haproxyRPMRepoBody must not pin the repo to x86_64:\n%s", got)
	}
}

func TestHAProxyRPMELMajor(t *testing.T) {
	tests := []struct {
		name string
		p    Platform
		want string
	}{
		{
			name: "amazon",
			p:    Platform{Family: platformFamilyAmazon, VersionID: "2023"},
			want: "9",
		},
		{
			name: "rhel9",
			p:    Platform{Family: platformFamilyRHEL, VersionID: "9.4"},
			want: "9",
		},
		{
			name: "unsupported rhel8",
			p:    Platform{Family: platformFamilyRHEL, VersionID: "8.10"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := haproxyRPMELMajor(tt.p); got != tt.want {
				t.Fatalf("haproxyRPMELMajor = %q, want %q", got, tt.want)
			}
		})
	}
}

func testHAProxyConfig(mode string, riodbEnabledValue bool, udpPort string) *Config {
	riodbEnabledText := "false"
	if riodbEnabledValue {
		riodbEnabledText = "true"
	}
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": mode},
		"riodb": {
			"enabled":                              riodbEnabledText,
			"udp_tcp_request_arrival_log_port":     defaultRioDBUDPTCPRequestArrivalLogPort,
			"udp_tcp_request_completion_log_port":  defaultRioDBUDPTCPRequestCompletionLogPort,
			"udp_http_request_arrival_log_port":    defaultRioDBUDPHTTPRequestArrivalLogPort,
			"udp_http_request_completion_log_port": defaultRioDBUDPHTTPRequestCompletionLogPort,
		},
		"haproxy": {
			"listener_port":        "80",
			"timeout":              "60s",
			"backend_primary_host": "10.0.0.5",
			"backend_primary_port": "8080",
		},
	}}
	if mode == "tcp" {
		cfg.Data["riodb"]["udp_tcp_request_completion_log_port"] = udpPort
	} else {
		cfg.Data["riodb"]["udp_http_request_completion_log_port"] = udpPort
	}
	return cfg
}

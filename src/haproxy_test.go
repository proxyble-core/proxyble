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
	"bytes"
	"context"
	"fmt"
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
		`"accept_ts_ms":%Ts%ms`,
		`"request_ts_ms":%[var(txn.request_ts_ms)]`,
		"http-request set-var(txn.request_ts_ms) date(0,ms)",
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
	for _, unsupported := range []string{"accept_date(ms)", "request_date(ms)"} {
		if strings.Contains(body, unsupported) {
			t.Fatalf("HTTP HAProxy config should not require HAProxy 3.0 timestamp fetch %q\n%s", unsupported, body)
		}
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

	oldPath := endpointAllowListFile
	endpointPath := filepath.Join(t.TempDir(), "endpoint.sources")
	endpointAllowListFile = endpointPath
	t.Cleanup(func() { endpointAllowListFile = oldPath })
	if err := os.WriteFile(endpointPath, []byte("203.0.113.0/24 /api\n198.51.100.7 /login\n"), 0o600); err != nil {
		t.Fatal(err)
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
		`"accept_ts_ms":%Ts%ms`,
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

func TestBuildHAProxyConfigIncludesEndpointAllowListForHTTPOnly(t *testing.T) {
	oldPath := endpointAllowListFile
	path := filepath.Join(t.TempDir(), "endpoint.sources")
	endpointAllowListFile = path
	t.Cleanup(func() { endpointAllowListFile = oldPath })
	if err := os.WriteFile(path, []byte("203.0.113.0/24 /api\n198.51.100.7 /login\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	httpBody, err := buildHAProxyConfig(testHAProxyConfig("http", false, "2445"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"acl proxyble_endpoint_allow_001 path_beg -i /api",
		"acl proxyble_endpoint_allow_001_src src 203.0.113.0/24",
		"acl proxyble_endpoint_allow_002 path_beg -i /login",
		"http-request deny deny_status 403 if { var(txn.proxyble_endpoint_allow_active) -m str 1 } !{ var(txn.proxyble_endpoint_allow_source) -m str 1 }",
	} {
		if !strings.Contains(httpBody, want) {
			t.Fatalf("HTTP HAProxy config missing endpoint allow-list line %q\n%s", want, httpBody)
		}
	}

	tcpBody, err := buildHAProxyConfig(testHAProxyConfig("tcp", false, "2444"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tcpBody, "proxyble_endpoint_allow") {
		t.Fatalf("TCP HAProxy config should not include endpoint allow-list rules\n%s", tcpBody)
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

func TestEnsureHAProxyBinaryReusesWorkingManualInstallation(t *testing.T) {
	binDir := t.TempDir()
	haproxyPath := filepath.Join(binDir, "haproxy")
	if err := os.WriteFile(haproxyPath, []byte("#!/bin/sh\nprintf '%s\\n' 'HAProxy version 2.8.26'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	var out bytes.Buffer
	installed, err := ensureHAProxyBinary(context.Background(), &out, Platform{PackageManager: "apt-get"}, &packageMetadataSession{})
	if err != nil {
		t.Fatalf("ensureHAProxyBinary returned error: %v", err)
	}
	if installed {
		t.Fatalf("existing manual HAProxy installation must not be reported as newly installed")
	}
	for _, want := range []string{"Existing HAProxy binary detected", "HAProxy version 2.8.26", "package installation skipped"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("ensureHAProxyBinary output missing %q:\n%s", want, out.String())
		}
	}
}

func TestEnsureHAProxyBinaryInstallsNativePackageWhenMissing(t *testing.T) {
	binDir := t.TempDir()
	commandLog := filepath.Join(t.TempDir(), "apt-get.log")
	haproxyPath := filepath.Join(binDir, "haproxy")
	aptScript := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %s
case "$*" in
  *"install -y haproxy"*)
    printf '#!/bin/sh\necho "HAProxy version 3.0.25"\n' > %s
    /bin/chmod 755 %s
    ;;
esac
`, commandLog, haproxyPath, haproxyPath)
	if err := os.WriteFile(filepath.Join(binDir, "apt-get"), []byte(aptScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "dpkg-query"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	configPath := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(configPath, []byte("[haproxy]\ninstalled_by_proxyble=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := &App{Config: &Config{Path: configPath, Data: map[string]map[string]string{
		"haproxy": {"installed_by_proxyble": "false"},
	}}}

	var out bytes.Buffer
	installed, err := ensureHAProxyPackage(context.Background(), app, &out, Platform{Family: platformFamilyDebian, PackageManager: "apt-get"}, &packageMetadataSession{})
	if err != nil {
		t.Fatalf("ensureHAProxyPackage returned error: %v\n%s", err, out.String())
	}
	if !installed {
		t.Fatalf("package-manager installation must be reported as newly installed")
	}
	if !packageInstalledByProxyble(app.Config, "haproxy") {
		t.Fatalf("new HAProxy package installation must record Proxyble ownership")
	}
	commands, err := os.ReadFile(commandLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"update", "install -y haproxy"} {
		if !strings.Contains(string(commands), want) {
			t.Fatalf("apt-get command log missing %q:\n%s", want, commands)
		}
	}
	if strings.Contains(string(commands), "haproxy-awslc") {
		t.Fatalf("native installation must not request the legacy performance package:\n%s", commands)
	}
	if !strings.Contains(out.String(), "HAProxy package installation completed (HAProxy version 3.0.25)") {
		t.Fatalf("installation verification output missing:\n%s", out.String())
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

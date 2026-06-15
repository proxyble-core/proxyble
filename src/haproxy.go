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

// haproxy.go owns all HAProxy-specific validation, installation hardening, and
// configuration rendering. It translates Proxyble's INI settings into a tested
// /etc/haproxy/haproxy.cfg while keeping listener/backend completeness checks in
// one place for menus, CLI gates, and service restarts.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// haproxyRuntimeAdminGroup owns the HAProxy Runtime API socket. Keep it
// separate from the runtime haproxy group so a compromised HAProxy worker does
// not inherit admin-socket permissions through its primary group.
const haproxyRuntimeAdminGroup = "proxyble-haproxy-admin"

const (
	haproxyRequiredBranch      = "3.3"
	haproxyRepoVersionNumerals = "33"
	haproxyPerformancePackage  = "haproxy-awslc"
	haproxyAPTKeyURL           = "https://pks.haproxy.com/linux/community/RPM-GPG-KEY-HAProxy"
	haproxyRPMKeyURL           = "https://www.haproxy.com/download/haproxy/HAPROXY-key-community.asc"

	haproxyMetricLayerRequestArrival    = "request-arrival"
	haproxyMetricLayerRequestCompletion = "request-completion"
)

type haproxyMetricDrains struct {
	requestArrival        bool
	requestCompletion     bool
	requestArrivalPort    string
	requestCompletionPort string
}

func (d haproxyMetricDrains) enabled() bool {
	return d.requestArrival || d.requestCompletion
}

func haproxyJSONField(name, value string) string {
	return fmt.Sprintf("%q:%s", name, value)
}

func haproxyJSONStringField(name, value string) string {
	return haproxyJSONField(name, fmt.Sprintf("%q", value))
}

func haproxyLogFormatArg(format string) string {
	return "'" + format + "'"
}

// haproxyTimeoutValue normalizes numeric timeout input into HAProxy's seconds
// syntax while preserving explicit HAProxy duration strings.
func haproxyTimeoutValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "60s"
	}
	if _, err := strconv.Atoi(value); err == nil {
		return value + "s"
	}
	return value
}

func normalizeHAProxyMetricLayerToken(token string) (string, error) {
	token = strings.ToLower(strings.TrimSpace(token))
	token = strings.TrimPrefix(token, "on ")
	token = strings.ReplaceAll(token, "_", "-")
	switch token {
	case "", "and", "on":
		return "", nil
	case "all", "both":
		return "both", nil
	case "arrival", "request", "request-arrival", "request-start", "request-started":
		return haproxyMetricLayerRequestArrival, nil
	case "completion", "complete", "close", "request-completion", "response-complete", "response-completion":
		return haproxyMetricLayerRequestCompletion, nil
	default:
		return "", fmt.Errorf("invalid riodb metrics_log_layers value %q; use request-arrival, request-completion, or both", token)
	}
}

func configuredHAProxyMetricDrains(c *Config, mode string) (haproxyMetricDrains, error) {
	var drains haproxyMetricDrains
	if !riodbEnabled(c) {
		return drains, nil
	}
	layerText := c.Get("riodb", "metrics_log_layers", defaultRioDBMetricLogLayers)
	parts := strings.FieldsFunc(layerText, func(r rune) bool {
		return r == ',' || r == ';' || r == '+' || r == '|' || r == ' '
	})
	if len(parts) == 0 {
		parts = []string{defaultRioDBMetricLogLayers}
	}
	for _, part := range parts {
		layer, err := normalizeHAProxyMetricLayerToken(part)
		if err != nil {
			return drains, err
		}
		switch layer {
		case "":
			continue
		case "both":
			drains.requestArrival = true
			drains.requestCompletion = true
		case haproxyMetricLayerRequestArrival:
			drains.requestArrival = true
		case haproxyMetricLayerRequestCompletion:
			drains.requestCompletion = true
		}
	}
	if !drains.enabled() {
		return drains, fmt.Errorf("riodb metrics_log_layers must enable request-arrival, request-completion, or both")
	}
	arrivalPort, completionPort, err := configuredRioDBUDPLogPortsForMode(c, mode)
	if err != nil {
		return drains, err
	}
	if drains.requestArrival {
		drains.requestArrivalPort = arrivalPort
	}
	if drains.requestCompletion {
		drains.requestCompletionPort = completionPort
	}
	return drains, nil
}

func haproxyTCPRequestArrivalLogFields() []string {
	return []string{
		haproxyJSONStringField("schema", "proxyble_tcp_request_arrival_v1"),
		haproxyJSONStringField("event_stage", "request_arrival"),
		haproxyJSONStringField("traffic_mode", "tcp"),
		haproxyJSONStringField("request_id", "%ID"),
		haproxyJSONField("accept_ts_ms", "%[accept_date(ms)]"),
		haproxyJSONStringField("source_ip", "%ci"),
		haproxyJSONField("source_port", "%cp"),
		haproxyJSONStringField("frontend_ip", "%fi"),
		haproxyJSONField("frontend_port", "%fp"),
		haproxyJSONStringField("frontend_name", "%f"),
		haproxyJSONField("active_conn", "%ac"),
		haproxyJSONField("frontend_conn", "%fc"),
		haproxyJSONField("source_conn_cur", "%[sc_conn_cur(0)]"),
		haproxyJSONStringField("policy_action", "%[var(sess.ip_action),json(utf8s)]"),
		haproxyJSONStringField("policy_param", "%[var(sess.ip_param),json(utf8s)]"),
	}
}

func haproxyTCPRequestCompletionLogFields() []string {
	fields := haproxyTCPRequestArrivalLogFields()
	fields[0] = haproxyJSONStringField("schema", "proxyble_tcp_request_completion_v1")
	fields[1] = haproxyJSONStringField("event_stage", "request_completion")
	fields = append(fields,
		haproxyJSONStringField("backend_name", "%b"),
		haproxyJSONStringField("server_name", "%s"),
		haproxyJSONStringField("server_ip", "%si"),
		haproxyJSONStringField("server_port", "%sp"),
		haproxyJSONField("bytes_uploaded", "%U"),
		haproxyJSONField("bytes_sent", "%B"),
		haproxyJSONField("queue_time_ms", "%Tw"),
		haproxyJSONField("connect_time_ms", "%Tc"),
		haproxyJSONField("total_time_ms", "%Tt"),
		haproxyJSONField("session_duration_ms", "%Tt"),
		haproxyJSONStringField("termination_state", "%ts"),
		haproxyJSONField("backend_conn", "%bc"),
		haproxyJSONField("server_conn", "%sc"),
		haproxyJSONField("backend_queue", "%bq"),
		haproxyJSONField("server_queue", "%sq"),
	)
	return fields
}

func haproxyHTTPRequestArrivalLogFields() []string {
	return []string{
		haproxyJSONStringField("schema", "proxyble_http_request_arrival_v1"),
		haproxyJSONStringField("event_stage", "request_arrival"),
		haproxyJSONStringField("traffic_mode", "http"),
		haproxyJSONStringField("request_id", "%ID"),
		haproxyJSONField("accept_ts_ms", "%[accept_date(ms)]"),
		haproxyJSONField("request_ts_ms", "%[request_date(ms)]"),
		haproxyJSONStringField("source_ip", "%ci"),
		haproxyJSONField("source_port", "%cp"),
		haproxyJSONStringField("real_client_ip", "%[var(txn.real_client_ip),json(utf8s)]"),
		haproxyJSONStringField("frontend_ip", "%fi"),
		haproxyJSONField("frontend_port", "%fp"),
		haproxyJSONStringField("frontend_name", "%f"),
		haproxyJSONStringField("tls", "%[ssl_fc]"),
		haproxyJSONStringField("sni", "%[ssl_fc_sni,json(utf8s)]"),
		haproxyJSONStringField("tls_protocol", "%[ssl_fc_protocol,json(utf8s)]"),
		haproxyJSONStringField("tls_cipher", "%[ssl_fc_cipher,json(utf8s)]"),
		haproxyJSONStringField("alpn", "%[ssl_fc_alpn,json(utf8s)]"),
		haproxyJSONStringField("host", "%[var(txn.host),json(utf8s)]"),
		haproxyJSONStringField("method", "%[var(txn.method),json(utf8s)]"),
		haproxyJSONStringField("path", "%[var(txn.path),json(utf8s)]"),
		haproxyJSONStringField("query_string", "%[var(txn.query_string),json(utf8s)]"),
		haproxyJSONStringField("full_url", "%[var(txn.full_url),json(utf8s)]"),
		haproxyJSONStringField("http_version", "%[var(txn.http_version),json(utf8s)]"),
		haproxyJSONStringField("user_agent", "%[var(txn.user_agent),json(utf8s)]"),
		haproxyJSONStringField("referer", "%[var(txn.referer),json(utf8s)]"),
		haproxyJSONStringField("user_header", "%[var(txn.user),json(utf8s)]"),
		haproxyJSONStringField("client_key", "%[var(txn.client_key),json(utf8s)]"),
		haproxyJSONStringField("tenant_id", "%[var(txn.tenant_id),json(utf8s)]"),
		haproxyJSONStringField("session_id", "%[var(txn.session_id),json(utf8s)]"),
		haproxyJSONStringField("login_identifier", "%[var(txn.login_identifier),json(utf8s)]"),
		haproxyJSONStringField("mcp_client_id", "%[var(txn.mcp_client_id),json(utf8s)]"),
		haproxyJSONStringField("mcp_session_id", "%[var(txn.mcp_session_id),json(utf8s)]"),
		haproxyJSONStringField("mcp_tool_name", "%[var(txn.mcp_tool_name),json(utf8s)]"),
		haproxyJSONField("active_conn", "%ac"),
		haproxyJSONField("frontend_conn", "%fc"),
		haproxyJSONStringField("policy_action", "%[var(txn.ip_action),json(utf8s)]"),
		haproxyJSONStringField("policy_param", "%[var(txn.ip_param),json(utf8s)]"),
		haproxyJSONField("endpoint_rate_limit", "%[var(txn.endpoint_limit)]"),
		haproxyJSONField("endpoint_rate_current", "%[var(txn.endpoint_rate)]"),
	}
}

func haproxyHTTPRequestCompletionLogFields() []string {
	fields := haproxyHTTPRequestArrivalLogFields()
	fields[0] = haproxyJSONStringField("schema", "proxyble_http_request_completion_v1")
	fields[1] = haproxyJSONStringField("event_stage", "request_completion")
	fields = append(fields,
		haproxyJSONField("status_code", "%ST"),
		haproxyJSONStringField("backend_name", "%b"),
		haproxyJSONStringField("server_name", "%s"),
		haproxyJSONStringField("server_ip", "%si"),
		haproxyJSONStringField("server_port", "%sp"),
		haproxyJSONField("bytes_uploaded", "%U"),
		haproxyJSONField("bytes_sent", "%B"),
		haproxyJSONField("request_header_time_ms", "%TR"),
		haproxyJSONField("queue_time_ms", "%Tw"),
		haproxyJSONField("connect_time_ms", "%Tc"),
		haproxyJSONField("response_header_time_ms", "%Tr"),
		haproxyJSONField("response_data_time_ms", "%Td"),
		haproxyJSONField("total_time_ms", "%Tt"),
		haproxyJSONField("active_time_ms", "%Ta"),
		haproxyJSONStringField("termination_state", "%ts"),
		haproxyJSONField("backend_conn", "%bc"),
		haproxyJSONField("server_conn", "%sc"),
		haproxyJSONField("backend_queue", "%bq"),
		haproxyJSONField("server_queue", "%sq"),
		haproxyJSONStringField("cache_status", "%[var(txn.cache_status),json(utf8s)]"),
		haproxyJSONStringField("x_cache", "%[var(txn.x_cache),json(utf8s)]"),
		haproxyJSONStringField("response_content_length", "%[var(txn.response_content_length),json(utf8s)]"),
	)
	return fields
}

func haproxyCompletionLogFormat(mode string) string {
	if mode == "http" {
		return "{" + strings.Join(haproxyHTTPRequestCompletionLogFields(), ",") + "}"
	}
	return "{" + strings.Join(haproxyTCPRequestCompletionLogFields(), ",") + "}"
}

func haproxyRequestArrivalLogFormat(mode string) string {
	if mode == "http" {
		return "{" + strings.Join(haproxyHTTPRequestArrivalLogFields(), ",") + "}"
	}
	return "{" + strings.Join(haproxyTCPRequestArrivalLogFields(), ",") + "}"
}

func writeHAProxyRioDBLogProfiles(b *strings.Builder, mode string, drains haproxyMetricDrains) {
	if drains.requestArrival {
		fmt.Fprintf(b, "log-profile proxyble_riodb_request_arrival\n")
		fmt.Fprintf(b, "    on any drop\n")
		if mode == "http" {
			fmt.Fprintf(b, "    on http-req format %s\n\n", haproxyLogFormatArg(haproxyRequestArrivalLogFormat(mode)))
		} else {
			fmt.Fprintf(b, "    on tcp-req-conn format %s\n\n", haproxyLogFormatArg(haproxyRequestArrivalLogFormat(mode)))
		}
	}
	if drains.requestCompletion {
		format := haproxyCompletionLogFormat(mode)
		fmt.Fprintf(b, "log-profile proxyble_riodb_request_completion\n")
		fmt.Fprintf(b, "    on any drop\n")
		fmt.Fprintf(b, "    on close format %s\n", haproxyLogFormatArg(format))
		fmt.Fprintf(b, "    on error format %s\n\n", haproxyLogFormatArg(format))
	}
}

func writeHAProxyRioDBFrontendLogs(b *strings.Builder, drains haproxyMetricDrains) {
	if drains.requestArrival {
		fmt.Fprintf(b, "    log 127.0.0.1:%s format raw profile proxyble_riodb_request_arrival local0\n", drains.requestArrivalPort)
	}
	if drains.requestCompletion {
		fmt.Fprintf(b, "    log 127.0.0.1:%s format raw profile proxyble_riodb_request_completion local0\n", drains.requestCompletionPort)
	}
	if drains.enabled() {
		b.WriteString("\n")
	}
}

// isLoopbackHost identifies backend hosts that share the listener namespace and
// can therefore conflict with the public listener port.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1":
		return true
	default:
		return false
	}
}

// validateBackendPortConflict prevents configuring a loopback backend on the
// same port as the HAProxy listener.
func validateBackendPortConflict(listenerPort, backendHost, backendPort, label string) error {
	if listenerPort == "" || backendHost == "" || backendPort == "" {
		return nil
	}
	if isLoopbackHost(backendHost) && listenerPort == backendPort {
		return fmt.Errorf("%s uses %s:%s, which conflicts with the HAProxy listener on port %s; use a different backend port or a non-loopback backend host", label, backendHost, backendPort, listenerPort)
	}
	return nil
}

// validateConfigPortConflicts checks the stored primary and secondary backend
// settings against the stored listener port.
func validateConfigPortConflicts(c *Config) error {
	listenerPort := c.Get("haproxy", "listener_port", "")
	if err := validateBackendPortConflict(listenerPort, c.Get("haproxy", "backend_primary_host", ""), c.Get("haproxy", "backend_primary_port", ""), "Primary backend"); err != nil {
		return err
	}
	return validateBackendPortConflict(listenerPort, c.Get("haproxy", "backend_secondary_host", ""), c.Get("haproxy", "backend_secondary_port", ""), "Secondary backend")
}

// haproxyListenerComplete reports whether the listener portion of config.ini is
// valid enough to render HAProxy.
func haproxyListenerComplete(c *Config) bool {
	mode, err := c.TrafficMode()
	if err != nil {
		return false
	}
	port := c.Get("haproxy", "listener_port", "")
	timeout := c.Get("haproxy", "timeout", "")
	if port == "" || timeout == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if mode == "https" {
		cert := c.Get("haproxy", "certificate_path", "")
		if cert == "" {
			return false
		}
		if _, err := os.Stat(cert); err != nil {
			return false
		}
	}
	return true
}

// haproxyBackendComplete reports whether the backend portion of config.ini is
// valid enough to render HAProxy.
func haproxyBackendComplete(c *Config) bool {
	host := c.Get("haproxy", "backend_primary_host", "")
	port := c.Get("haproxy", "backend_primary_port", "")
	if host == "" || port == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	secondaryHost := c.Get("haproxy", "backend_secondary_host", "")
	secondaryPort := c.Get("haproxy", "backend_secondary_port", "")
	if secondaryHost != "" {
		n, err := strconv.Atoi(secondaryPort)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return validateConfigPortConflicts(c) == nil
}

// updateHAProxyEnabled persists whether HAProxy should be active based on
// listener and backend completeness.
func updateHAProxyEnabled(c *Config) error {
	if haproxyListenerComplete(c) && haproxyBackendComplete(c) {
		return c.Set("haproxy", "enabled", "true")
	}
	return c.Set("haproxy", "enabled", "false")
}

func haproxyVersionLine(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "haproxy", "-v")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(buf.String()), err
	}
	return strings.SplitN(strings.TrimSpace(buf.String()), "\n", 2)[0], nil
}

func haproxyVersionBranch(line string) string {
	fields := strings.Fields(line)
	for i, field := range fields {
		if strings.EqualFold(field, "version") && i+1 < len(fields) {
			version := strings.TrimLeft(fields[i+1], "v")
			parts := strings.Split(version, ".")
			if len(parts) >= 2 {
				return parts[0] + "." + parts[1]
			}
			return version
		}
	}
	return ""
}

func haproxyPackageName(p Platform) string {
	switch p.PackageManager {
	case "apt-get", "dnf", "yum":
		return haproxyPerformancePackage
	default:
		return defaultHAProxyPackage
	}
}

func haproxyRemovalPackages(Platform) []string {
	return []string{haproxyPerformancePackage, defaultHAProxyPackage}
}

func ensureHAProxy33PackageSource(ctx context.Context, out interface{ Write([]byte) (int, error) }, p Platform) error {
	switch p.PackageManager {
	case "apt-get":
		return ensureHAProxy33APTSource(ctx, out, p)
	case "dnf", "yum":
		return ensureHAProxy33RPMSource(ctx, out, p)
	default:
		return fmt.Errorf("HAProxy %s packages are not configured for package manager %s", haproxyRequiredBranch, p.PackageManager)
	}
}

func ensureHAProxy33APTSource(ctx context.Context, out interface{ Write([]byte) (int, error) }, p Platform) error {
	distro := strings.ToLower(strings.TrimSpace(p.ID))
	if distro != "ubuntu" && distro != "debian" {
		return fmt.Errorf("official HAProxy %s apt packages are configured for Ubuntu/Debian; detected %s", haproxyRequiredBranch, p.PrettyName)
	}
	codename := haproxyAPTCodename(p)
	if codename == "" {
		return fmt.Errorf("official HAProxy %s apt packages require a detected apt codename; detected %s without VERSION_CODENAME/UBUNTU_CODENAME", haproxyRequiredBranch, p.PrettyName)
	}
	if err := requireHAProxyAPTRelease(ctx, distro, codename); err != nil {
		return err
	}
	keyPath := "/usr/share/keyrings/HAPROXY-key-community.asc"
	if err := downloadFile(ctx, out, haproxyAPTKeyURL, keyPath, 0o644); err != nil {
		return err
	}
	source := haproxyAPTSourceLine(keyPath, distro, codename)
	path := "/etc/apt/sources.list.d/haproxy.list"
	current, _ := os.ReadFile(path)
	if string(current) == source {
		fmt.Fprintln(out, "[PASS] HAProxy 3.3 apt source already current")
		return nil
	}
	if err := atomicWriteFile(path, []byte(source), 0o644); err != nil {
		return err
	}
	_ = chownPath(path, "root", "root")
	fmt.Fprintln(out, "[PASS] HAProxy 3.3 apt source configured")
	return nil
}

func haproxyAPTSourceLine(keyPath, distro, codename string) string {
	return fmt.Sprintf("deb [arch=amd64,arm64 signed-by=%s] %s %s main\n", keyPath, haproxyAPTRepoBaseURL(distro), codename)
}

func haproxyAPTRepoBaseURL(distro string) string {
	return fmt.Sprintf("https://www.haproxy.com/download/haproxy/performance/%s/ha%s", distro, haproxyRepoVersionNumerals)
}

func haproxyAPTReleaseURL(distro, codename string) string {
	return fmt.Sprintf("%s/dists/%s/Release", haproxyAPTRepoBaseURL(distro), codename)
}

func haproxyAPTCodename(p Platform) string {
	codename := strings.ToLower(strings.TrimSpace(p.Codename))
	if codename == "" || !safeAPTCodename(codename) {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(p.ID)) {
	case "ubuntu", "debian":
		return codename
	}
	return ""
}

func safeAPTCodename(codename string) bool {
	for _, r := range codename {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func requireHAProxyAPTRelease(ctx context.Context, distro, codename string) error {
	releaseURL := haproxyAPTReleaseURL(distro, codename)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodHead, releaseURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("check HAProxy %s apt repository for %s %s: %w", haproxyRequiredBranch, distro, codename, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	return fmt.Errorf("official HAProxy %s apt packages are not published for %s codename %q yet (checked %s: HTTP %s)", haproxyRequiredBranch, distro, codename, releaseURL, resp.Status)
}

func ensureHAProxy33RPMSource(ctx context.Context, out interface{ Write([]byte) (int, error) }, p Platform) error {
	elMajor := haproxyRPMELMajor(p)
	if elMajor == "" {
		return fmt.Errorf("official HAProxy %s RPM packages require a RHEL-compatible 9/10 host; detected %s", haproxyRequiredBranch, p.PrettyName)
	}
	_ = runCommand(ctx, out, "rpm", "--import", haproxyRPMKeyURL)
	body := haproxyRPMRepoBody(elMajor)
	path := "/etc/yum.repos.d/haproxy-33.repo"
	current, _ := os.ReadFile(path)
	if string(current) == body {
		fmt.Fprintln(out, "[PASS] HAProxy 3.3 RPM source already current")
		return nil
	}
	if err := atomicWriteFile(path, []byte(body), 0o644); err != nil {
		return err
	}
	_ = chownPath(path, "root", "root")
	cleanHAProxyRPMMetadata(ctx, out, p.PackageManager)
	fmt.Fprintln(out, "[PASS] HAProxy 3.3 RPM source configured")
	return nil
}

func cleanHAProxyRPMMetadata(ctx context.Context, out interface{ Write([]byte) (int, error) }, packageManager string) {
	switch packageManager {
	case "dnf", "yum":
		_ = runCommand(ctx, out, packageManager, "--disablerepo=*", "--enablerepo=haproxy-33", "clean", "metadata")
	}
}

func haproxyRPMRepoBody(elMajor string) string {
	return fmt.Sprintf(`[haproxy-33]
name=HAProxy 3.3 Community Performance Packages
baseurl=https://www.haproxy.com/download/haproxy/performance/rhel/ha%s/el%s/$basearch
enabled=1
gpgcheck=1
gpgkey=%s
`, haproxyRepoVersionNumerals, elMajor, haproxyRPMKeyURL)
}

func haproxyRPMELMajor(p Platform) string {
	if p.Family == platformFamilyAmazon {
		if majorVersion(p.VersionID) != "2023" {
			return ""
		}
		// Amazon Linux 2023 follows the RHEL-family install path in Proxyble; use
		// the el9 HAProxy package repo so Amazon hosts can still get HAProxy 3.3.
		return "9"
	}
	major := majorVersion(p.VersionID)
	if major == "9" || major == "10" {
		return major
	}
	return ""
}

func majorVersion(version string) string {
	version = strings.TrimSpace(strings.Trim(version, `"`))
	if version == "" {
		return ""
	}
	major, _, _ := strings.Cut(version, ".")
	return major
}

// installHAProxySoftware installs the OS package when missing and prepares
// runtime directories, maps, tmpfiles, and systemd hardening.
func installHAProxySoftware(ctx context.Context, a *App, p Platform) error {
	out := stepOutput(a)
	fmt.Fprintln(out, "[NOTICE] HAProxy Community Edition - licensed under GPLv2")
	fmt.Fprintln(out, "[INFO] Performing HAProxy package and runtime bootstrap")
	a.InstalledNow = false
	needsInstall := true
	if commandExists("haproxy") {
		line, err := haproxyVersionLine(ctx)
		if err == nil && haproxyVersionBranch(line) == haproxyRequiredBranch {
			needsInstall = false
			fmt.Fprintf(out, "[PASS] HAProxy %s binary present (%s)\n", haproxyRequiredBranch, line)
		} else {
			if line != "" {
				fmt.Fprintf(out, "[NOTICE] Existing HAProxy is not %s (%s)\n", haproxyRequiredBranch, line)
			} else {
				fmt.Fprintf(out, "[NOTICE] Existing HAProxy version check failed: %v\n", err)
			}
		}
	} else {
		fmt.Fprintln(out, "[NOTICE] HAProxy binary not detected")
	}
	if needsInstall {
		fmt.Fprintf(out, "[INFO] Installing HAProxy %s via official HAProxy package source\n", haproxyRequiredBranch)
		if err := ensureHAProxy33PackageSource(ctx, out, p); err != nil {
			return err
		}
		if err := packageUpdate(ctx, p, out); err != nil {
			return err
		}
		if err := packageInstall(ctx, p, out, haproxyPackageName(p)); err != nil {
			return err
		}
		a.InstalledNow = true
		line, err := haproxyVersionLine(ctx)
		if err != nil {
			return fmt.Errorf("HAProxy installation completed but version verification failed: %w", err)
		}
		if haproxyVersionBranch(line) != haproxyRequiredBranch {
			return fmt.Errorf("HAProxy %s is required but installed binary reports: %s", haproxyRequiredBranch, line)
		}
		fmt.Fprintf(out, "[PASS] HAProxy %s installation completed (%s)\n", haproxyRequiredBranch, line)
	}
	if !groupExists(haproxyRuntimeAdminGroup) {
		if err := runCommand(ctx, out, "groupadd", "-r", haproxyRuntimeAdminGroup); err != nil {
			return err
		}
		fmt.Fprintf(out, "[PASS] Group '%s' created\n", haproxyRuntimeAdminGroup)
	} else {
		fmt.Fprintf(out, "[NOTICE] Group '%s' already exists\n", haproxyRuntimeAdminGroup)
	}
	if err := mkdirOwned("/run/haproxy", 0o750, "root", "haproxy"); err != nil {
		return err
	}
	if err := mkdirOwned("/var/lib/haproxy", 0o755, "root", "root"); err != nil {
		return err
	}
	if err := mkdirOwned("/etc/haproxy/maps", 0o750, "root", "haproxy"); err != nil {
		return err
	}
	for _, file := range []string{"rules.map", "params.map", "endpoint-rates.map"} {
		path := filepath.Join("/etc/haproxy/maps", file)
		if err := touchFile(path, 0o640); err != nil {
			return err
		}
		if err := chownPath(path, "root", "haproxy"); err != nil {
			return err
		}
	}
	if err := ensureHAProxyTmpfiles(ctx, out); err != nil {
		return err
	}
	return ensureHAProxySystemdOverride(ctx, out)
}

// ensureHAProxyTmpfiles writes the tmpfiles rule that recreates /run/haproxy
// after boot.
func ensureHAProxyTmpfiles(ctx context.Context, out interface{ Write([]byte) (int, error) }) error {
	path := "/etc/tmpfiles.d/haproxy.conf"
	wanted := "d /run/haproxy 0750 root haproxy -\n"
	current, _ := os.ReadFile(path)
	if string(current) == wanted {
		fmt.Fprintln(out, "[PASS] tmpfiles rule already current")
		return nil
	}
	if err := atomicWriteFile(path, []byte(wanted), 0o644); err != nil {
		return err
	}
	_ = chownPath(path, "root", "root")
	_ = runCommand(ctx, out, "systemd-tmpfiles", "--create", path)
	fmt.Fprintln(out, "[PASS] tmpfiles rule applied")
	return nil
}

// ensureHAProxySystemdOverride writes Proxyble's HAProxy systemd resource and
// sandboxing override.
func ensureHAProxySystemdOverride(ctx context.Context, out interface{ Write([]byte) (int, error) }) error {
	dir := "/etc/systemd/system/haproxy.service.d"
	path := filepath.Join(dir, "override.conf")
	wanted := `[Unit]
After=systemd-tmpfiles-setup.service
Wants=systemd-tmpfiles-setup.service

[Service]
Nice=-2
CPUWeight=150
MemoryMax=128M
LimitNOFILE=5000
TimeoutStopSec=31s
KillMode=control-group
ProtectSystem=full
ProtectHome=yes
PrivateTmp=true
PrivateDevices=yes
NoNewPrivileges=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
RestrictRealtime=yes
RestrictNamespaces=yes
	MemoryDenyWriteExecute=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_CHOWN
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
	if err := mkdirAllNoSymlink(dir, 0o755); err != nil {
		return err
	}
	current, _ := os.ReadFile(path)
	if string(current) == wanted {
		fmt.Fprintln(out, "[PASS] systemd override already current")
		return nil
	}
	if err := atomicWriteFile(path, []byte(wanted), 0o644); err != nil {
		return err
	}
	_ = chownPath(path, "root", "root")
	if err := systemctl(ctx, out, "daemon-reload"); err != nil {
		return err
	}
	fmt.Fprintln(out, "[PASS] systemd override updated")
	return nil
}

// buildHAProxyConfig translates config.ini into the HAProxy configuration body.
// RioDB access-log shipping is deliberately conditional: core-only installs do
// not configure a UDP sink because nothing is listening until RioDB is enabled.
func buildHAProxyConfig(c *Config) (string, error) {
	trafficMode, err := c.TrafficMode()
	if err != nil {
		return "", err
	}
	listenerPort := c.Get("haproxy", "listener_port", "")
	timeoutValue := haproxyTimeoutValue(c.Get("haproxy", "timeout", "60s"))
	certPath := c.Get("haproxy", "certificate_path", "")
	backendPrimaryHost := c.Get("haproxy", "backend_primary_host", "")
	backendPrimaryPort := c.Get("haproxy", "backend_primary_port", "")
	backendSecondaryHost := c.Get("haproxy", "backend_secondary_host", "")
	backendSecondaryPort := c.Get("haproxy", "backend_secondary_port", "")

	mode, logOpt := "tcp", "tcplog"
	if trafficMode == "http" || trafficMode == "https" {
		mode, logOpt = "http", "httplog"
	}
	if trafficMode != "https" {
		certPath = ""
	} else {
		if certPath == "" {
			return "", fmt.Errorf("HTTPS mode requires an existing certificate bundle path")
		}
		if _, err := os.Stat(certPath); err != nil {
			return "", fmt.Errorf("HTTPS certificate not available: %w", err)
		}
	}
	if !haproxyListenerComplete(c) {
		return "", fmt.Errorf("listener configuration is incomplete")
	}
	if !haproxyBackendComplete(c) {
		return "", fmt.Errorf("backend configuration is incomplete")
	}
	if err := validateBackendPortConflict(listenerPort, backendPrimaryHost, backendPrimaryPort, "Primary backend"); err != nil {
		return "", err
	}
	if err := validateBackendPortConflict(listenerPort, backendSecondaryHost, backendSecondaryPort, "Secondary backend"); err != nil {
		return "", err
	}

	metricDrains, err := configuredHAProxyMetricDrains(c, mode)
	if err != nil {
		return "", err
	}
	legacyCompletionLogging := metricDrains.requestCompletion && !metricDrains.requestArrival

	var b strings.Builder
	b.WriteString("global\n")
	if legacyCompletionLogging {
		fmt.Fprintf(&b, "    log 127.0.0.1:%s format raw local0\n", metricDrains.requestCompletionPort)
	}
	fmt.Fprintf(&b, `    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon
    maxconn 512
    spread-checks 5
    stats socket /run/haproxy/admin.sock mode 660 level admin user root group %s
    stats timeout 30s

defaults
`, haproxyRuntimeAdminGroup)
	if legacyCompletionLogging {
		fmt.Fprintf(&b, `    log     global
    option  %s
    option  dontlognull
`, logOpt)
	} else if metricDrains.enabled() {
		fmt.Fprintf(&b, `    option  %s
    option  dontlognull
`, logOpt)
	}
	fmt.Fprintf(&b, `    mode    %s
    timeout connect 5000
    timeout client  %s
    timeout server  %s
    timeout check   2s
    option  redispatch
`, mode, timeoutValue, timeoutValue)
	if metricDrains.enabled() {
		b.WriteString("    unique-id-format %[uuid(4)]\n")
	}
	if mode == "http" {
		b.WriteString("    option  forwardfor\n")
	}
	if metricDrains.requestArrival {
		b.WriteString("\n")
		writeHAProxyRioDBLogProfiles(&b, mode, metricDrains)
	}
	b.WriteString("\nfrontend my_frontend\n")
	if trafficMode == "https" {
		fmt.Fprintf(&b, "    bind *:%s ssl crt %s\n", listenerPort, certPath)
	} else {
		fmt.Fprintf(&b, "    bind *:%s\n", listenerPort)
	}
	fmt.Fprintf(&b, "    mode %s\n", mode)
	if metricDrains.requestArrival {
		writeHAProxyRioDBFrontendLogs(&b, metricDrains)
	}
	if mode == "tcp" {
		if legacyCompletionLogging {
			b.WriteString(`    log global

`)
		}
		b.WriteString(`    stick-table type ip size 100k store conn_cur
    tcp-request connection track-sc0 src

`)
		if metricDrains.enabled() {
			b.WriteString(`    tcp-request connection set-var(sess.ip_action) src,map_ip(/etc/haproxy/maps/rules.map)
    tcp-request connection set-var(sess.ip_param) src,map_ip(/etc/haproxy/maps/params.map)

`)
		}
		if metricDrains.requestArrival {
			b.WriteString("    tcp-request connection do-log\n\n")
		}
		if legacyCompletionLogging {
			fmt.Fprintf(&b, "    log-format %s\n\n", haproxyLogFormatArg(haproxyCompletionLogFormat(mode)))
		}

		if metricDrains.enabled() {
			b.WriteString(`    tcp-request connection reject if { var(sess.ip_action) -m str RATE_REJ }
    tcp-request connection reject if { var(sess.ip_action) -m str BUSY }

    filter bwlim-in mylimit default-limit 1000m default-period 1s

    tcp-request inspect-delay 5s
    tcp-request content set-bandwidth-limit mylimit limit var(sess.ip_param) if { var(sess.ip_action) -m str BW_LIM }

`)
		} else {
			b.WriteString(`    tcp-request connection reject if { src,map_ip(/etc/haproxy/maps/rules.map) -m str RATE_REJ }
    tcp-request connection reject if { src,map_ip(/etc/haproxy/maps/rules.map) -m str BUSY }

    filter bwlim-in mylimit default-limit 1000m default-period 1s

    tcp-request inspect-delay 5s
    tcp-request content set-bandwidth-limit mylimit limit src,map_ip(/etc/haproxy/maps/params.map) if { src,map_ip(/etc/haproxy/maps/rules.map) -m str BW_LIM }

`)
		}
	} else {
		if legacyCompletionLogging {
			b.WriteString(`
    log global
    http-request set-var(txn.user) req.hdr(user)
`)
			fmt.Fprintf(&b, "    log-format %s\n", haproxyLogFormatArg(haproxyCompletionLogFormat(mode)))
		} else if metricDrains.enabled() {
			b.WriteString(`
    http-request set-var(txn.user) req.hdr(user)
`)
		}
		if metricDrains.enabled() {
			b.WriteString(`    http-request set-var(txn.real_client_ip) req.fhdr(x-forwarded-for)
    http-request set-var(txn.host) req.fhdr(host)
    http-request set-var(txn.method) method
    http-request set-var(txn.path) path
    http-request set-var(txn.query_string) query
    http-request set-var(txn.full_url) url
    http-request set-var(txn.http_version) req.ver
    http-request set-var(txn.user_agent) req.fhdr(user-agent)
    http-request set-var(txn.referer) req.fhdr(referer)
    http-request set-var(txn.client_key) req.fhdr(x-proxyble-client-key)
    http-request set-var(txn.tenant_id) req.fhdr(x-proxyble-tenant-id)
    http-request set-var(txn.session_id) req.fhdr(x-proxyble-session-id)
    http-request set-var(txn.login_identifier) req.fhdr(x-proxyble-login-id)
    http-request set-var(txn.mcp_client_id) req.fhdr(x-proxyble-mcp-client-id)
    http-request set-var(txn.mcp_session_id) req.fhdr(x-proxyble-mcp-session-id)
    http-request set-var(txn.mcp_tool_name) req.fhdr(x-proxyble-mcp-tool-name)
`)
		}
		b.WriteString(`
    stick-table type binary len 20 size 100k expire 10s store http_req_rate(10s)

    filter bwlim-in mylimit default-limit 1000m default-period 1s

    http-request set-var(txn.ip_action) src,map_ip(/etc/haproxy/maps/rules.map)
    http-request set-var(txn.ip_param) src,map_ip(/etc/haproxy/maps/params.map)
    http-request set-var-fmt(txn.endpoint_key) "%[src]|%[path]"
    http-request set-var(txn.endpoint_limit) var(txn.endpoint_key),map_beg(/etc/haproxy/maps/endpoint-rates.map,0)
    http-request track-sc1 base32+src if { var(txn.endpoint_limit) -m int gt 0 }
    http-request set-var(txn.endpoint_rate) base32+src,table_http_req_rate()

`)
		if metricDrains.requestArrival {
			b.WriteString("    http-request do-log\n")
		}
		b.WriteString(`
    http-request deny deny_status 429 if { var(txn.ip_action) -m str RATE_REJ }
    http-request deny deny_status 503 if { var(txn.ip_action) -m str BUSY }
    http-request deny deny_status 429 if { var(txn.endpoint_limit) -m int gt 0 } { var(txn.endpoint_limit),sub(txn.endpoint_rate) lt 0 }

    http-request set-bandwidth-limit mylimit limit var(txn.ip_param) if { var(txn.ip_action) -m str BW_LIM }

`)
		if metricDrains.requestCompletion {
			b.WriteString(`    http-response set-var(txn.cache_status) res.fhdr(cache-status)
    http-response set-var(txn.x_cache) res.fhdr(x-cache)
    http-response set-var(txn.response_content_length) res.fhdr(content-length)

`)
		}
	}
	b.WriteString("\n    default_backend my_servers\n\nbackend my_servers\n")
	fmt.Fprintf(&b, "    mode %s\n", mode)
	if mode == "http" {
		b.WriteString("    http-request set-timeout server src,map_ip(/etc/haproxy/maps/params.map) if { src,map_ip(/etc/haproxy/maps/rules.map) -m str T_OUT }\n")
	}
	if backendSecondaryHost != "" {
		b.WriteString("    balance roundrobin\n")
	}
	fmt.Fprintf(&b, "    server server1 %s:%s\n", backendPrimaryHost, backendPrimaryPort)
	if backendSecondaryHost != "" {
		fmt.Fprintf(&b, "    server server2 %s:%s\n", backendSecondaryHost, backendSecondaryPort)
	}
	return b.String(), nil
}

// renderHAProxyConfig renders, syntax-checks, backs up, and installs the HAProxy
// config for the current traffic mode and backend set.
func renderHAProxyConfig(ctx context.Context, a *App) error {
	c := a.Config
	out := stepOutput(a)
	body, err := buildHAProxyConfig(c)
	if err != nil {
		return err
	}
	if trafficMode, _ := c.TrafficMode(); trafficMode == "https" {
		certPath := c.Get("haproxy", "certificate_path", "")
		_ = chownPath(certPath, "root", "haproxy")
		_ = chmodPath(certPath, 0o640)
	}

	tmp, err := os.CreateTemp("", "proxyble-haproxy-*.cfg")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	fmt.Fprintln(out, "[INFO] Validating HAProxy configuration syntax")
	if err := runCommand(ctx, out, "haproxy", "-c", "-f", tmpPath); err != nil {
		return fmt.Errorf("invalid HAProxy syntax detected: %w", err)
	}
	if _, err := os.Stat("/etc/haproxy/haproxy.cfg"); err == nil {
		backup := fmt.Sprintf("/etc/haproxy/haproxy.cfg.bak.%s", time.Now().Format("2006-01-02_15-04-05"))
		_ = copyFile("/etc/haproxy/haproxy.cfg", backup, 0o644)
		fmt.Fprintln(out, "[NOTICE] Existing HAProxy configuration backed up")
	}
	if err := atomicWriteFile("/etc/haproxy/haproxy.cfg", []byte(body), 0o644); err != nil {
		return err
	}
	_ = chownPath("/etc/haproxy/haproxy.cfg", "root", "root")
	fmt.Fprintln(out, "[PASS] HAProxy configuration installed")
	return nil
}

// applyHAProxyIfEnabled ensures HAProxy dependencies and config are current when
// the stored configuration says HAProxy can run.
func applyHAProxyIfEnabled(ctx context.Context, a *App, p Platform) error {
	if !configIsTrue(a.Config.Get("haproxy", "enabled", "false")) {
		fmt.Fprintf(stepOutput(a), "[NOTICE] HAProxy is disabled in %s; listener/backend configuration is incomplete.\n", a.Config.Path)
		return nil
	}
	if err := installHAProxySoftware(ctx, a, p); err != nil {
		return err
	}
	if err := renderHAProxyConfig(ctx, a); err != nil {
		return err
	}
	_ = systemctl(ctx, stepOutput(a), "enable", "haproxy")
	return nil
}

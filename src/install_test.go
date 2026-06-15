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
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncRioDBSQLCopiesMandatoryTemplateOnly(t *testing.T) {
	app, sqlDir := testRioDBSQLApp(t, true)
	expected := "CREATE STREAM rule_queue;\n"
	writeTestSQLTemplate(t, app.SourceRoot, mandatoryRuleQueueSQLFile, expected)

	if err := syncRioDBSQL(app, "tcp"); err != nil {
		t.Fatal(err)
	}

	body := readTestFile(t, filepath.Join(sqlDir, mandatoryRuleQueueSQLFile))
	if body != expected {
		t.Fatalf("mandatory SQL template = %q, want %q", body, expected)
	}
	for _, name := range []string{"20-tcp-log-input.sql", "20-http-log-input.sql", "200-data-exfiltration.sql"} {
		if _, err := os.Stat(filepath.Join(sqlDir, name)); !os.IsNotExist(err) {
			t.Fatalf("legacy generated SQL file should not exist: %s", name)
		}
	}
}

func TestSyncRioDBSQLSkipsWhenRioDBDisabled(t *testing.T) {
	app, sqlDir := testRioDBSQLApp(t, false)
	if err := syncRioDBSQL(app, "tcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sqlDir); !os.IsNotExist(err) {
		t.Fatalf("core-only SQL sync should not create SQL directory")
	}
}

func TestSyncRioDBSQLLeavesExistingPolicyFilesInPlace(t *testing.T) {
	app, sqlDir := testRioDBSQLApp(t, true)
	writeTestSQLTemplate(t, app.SourceRoot, mandatoryRuleQueueSQLFile, "CREATE STREAM rule_queue;\n")
	if err := os.MkdirAll(sqlDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(sqlDir, "20-existing-policy.sql")
	if err := os.WriteFile(policyPath, []byte("SELECT 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(sqlDir, "20-http-log-input.sql")
	if err := os.WriteFile(legacyPath, []byte("CREATE STREAM haproxy_http_stream;\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := syncRioDBSQL(app, "http"); err != nil {
		t.Fatal(err)
	}

	if got := readTestFile(t, policyPath); got != "SELECT 1;\n" {
		t.Fatalf("existing policy SQL was changed: %q", got)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy generated SQL file should be removed")
	}
}

func TestEnsureRioDBArchiveDownloadsMissingArchive(t *testing.T) {
	installRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(installRoot, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldClient := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://downloads.example.test/riodb/riodb-test.tar.gz" {
			t.Fatalf("download URL = %q", r.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("riodb archive")),
			Header:     make(http.Header),
		}, nil
	})}
	defer func() { http.DefaultClient = oldClient }()
	app := &App{
		Config: &Config{Data: map[string]map[string]string{
			"proxyble": {"install_dir": installRoot},
		}},
		Settings: RuntimeSettings{RioDB: SettingsRioDB{
			ArchivePath:     "riodb-test.tar.gz",
			DownloadServers: []string{"https://downloads.example.test/riodb"},
		}},
	}

	archive, err := ensureRioDBArchive(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(installRoot, "bin", "riodb-test.tar.gz")
	if archive != want {
		t.Fatalf("archive path = %q, want %q", archive, want)
	}
	if got := readTestFile(t, want); got != "riodb archive" {
		t.Fatalf("downloaded archive = %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRioDBArchiveDownloadURLDefaultsToHTTPS(t *testing.T) {
	got, err := rioDBArchiveDownloadURL("www.riodb.co/downloads/2026-6", "riodb-test.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://www.riodb.co/downloads/2026-6/riodb-test.tar.gz"
	if got != want {
		t.Fatalf("download URL = %q, want %q", got, want)
	}
}

func TestRioDBArchiveDownloadURLPreservesExplicitHTTP(t *testing.T) {
	got, err := rioDBArchiveDownloadURL("http://www.proxyble.com/downloads", "riodb-test.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := "http://www.proxyble.com/downloads/riodb-test.tar.gz"
	if got != want {
		t.Fatalf("download URL = %q, want %q", got, want)
	}
}

func testRioDBSQLApp(t *testing.T, enabled bool) (*App, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "riodb")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	enabledText := "false"
	if enabled {
		enabledText = "true"
	}
	cfg := &Config{Data: map[string]map[string]string{
		"traffic": {"mode": "tcp"},
		"riodb": {
			"enabled":                              enabledText,
			"udp_tcp_request_arrival_log_port":     defaultRioDBUDPTCPRequestArrivalLogPort,
			"udp_tcp_request_completion_log_port":  defaultRioDBUDPTCPRequestCompletionLogPort,
			"udp_http_request_arrival_log_port":    defaultRioDBUDPHTTPRequestArrivalLogPort,
			"udp_http_request_completion_log_port": defaultRioDBUDPHTTPRequestCompletionLogPort,
			"install_dir":                          root,
			"app_subdir":                           "riodb",
			"user":                                 "root",
			"group":                                "root",
		},
	}}
	return &App{Config: cfg, SourceRoot: root}, filepath.Join(home, "sql")
}

func writeTestSQLTemplate(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, "templates", "RioSQL", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

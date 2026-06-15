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
	"path/filepath"
	"reflect"
	"testing"
)

// TestParsePolicyVisibilitySupportsExplicitModesAndLegacyText ensures new
// comma-separated Visibility headers and older prose headers normalize to the
// same traffic-mode set.
func TestParsePolicyVisibilitySupportsExplicitModesAndLegacyText(t *testing.T) {
	tests := []struct {
		value string
		want  []string
	}{
		{"http,https", []string{"http", "https"}},
		{"tcp,http,https", []string{"tcp", "http", "https"}},
		{"HTTP-visible only", []string{"http", "https"}},
		{"HTTP-visible with TCP/L4 fallback", []string{"tcp", "http", "https"}},
	}
	for _, tt := range tests {
		if got := parsePolicyVisibility(tt.value); !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("parsePolicyVisibility(%q) = %#v, want %#v", tt.value, got, tt.want)
		}
	}
}

// TestDeployablePoliciesFiltersModeAndAlreadyDeployed verifies the deploy list
// hides incompatible policies and policies whose files already exist in RioDB.
func TestDeployablePoliciesFiltersModeAndAlreadyDeployed(t *testing.T) {
	root := t.TempDir()
	policyDir := filepath.Join(root, "templates", "RioSQL", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePolicy := func(name, id, visibility string) {
		t.Helper()
		body := "# Policy: " + id + "\n" +
			"# Policy ID: " + id + "\n" +
			"# Summary: test policy\n" +
			"# Threat: test threat\n" +
			"# Detection Signals: test signals\n" +
			"# Metrics Layer: on request-completion\n" +
			"# Visibility: " + visibility + "\n\n" +
			"SELECT 1;\n"
		if err := os.WriteFile(filepath.Join(policyDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy("20-http.sql", "http_policy", "http,https")
	writePolicy("20-deployed.sql", "deployed_policy", "http,https")
	writePolicy("20-tcp.sql", "tcp_policy", "tcp")

	installDir := filepath.Join(root, "riodb-install")
	sqlDir := filepath.Join(installDir, "riodb", "sql")
	if err := os.MkdirAll(sqlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sqlDir, "20-deployed.sql"), []byte("SELECT 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	app := &App{
		SourceRoot: root,
		Config: &Config{Data: map[string]map[string]string{
			"traffic": {"mode": "http"},
			"riodb":   {"install_dir": installDir},
		}},
	}
	policies, err := deployablePolicies(app)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].ID != "http_policy" {
		t.Fatalf("deployable policies = %#v, want only http_policy", policies)
	}
	if policies[0].Threat != "test threat" || policies[0].DetectionSignals != "test signals" || policies[0].MetricsLayer != "on request-completion" {
		t.Fatalf("policy detail fields were not parsed: %#v", policies[0])
	}
}

// TestPolicyFileCopyListIncludesRecursiveStreamDependencies documents the
// policy -> window -> stream copy order required by RioDB startup loading.
func TestPolicyFileCopyListIncludesRecursiveStreamDependencies(t *testing.T) {
	root := t.TempDir()
	policyDir := filepath.Join(root, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, mandatoryRuleQueueSQLFile), []byte("CREATE STREAM rule_queue;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "01-stream-http-on-completion.sql"), []byte("CREATE STREAM http_log_on_request_completion;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	window := "# Dependencies: 01-stream-http-on-completion.sql\n\nCREATE WINDOW http_auth_src_loginid_5m;\n"
	if err := os.WriteFile(filepath.Join(root, "10-http-auth-src-loginid-5m.sql"), []byte(window), 0o600); err != nil {
		t.Fatal(err)
	}
	policyBody := "# Policy: Credential Pressure Control\n" +
		"# Policy ID: credential_pressure_control\n" +
		"# Summary: test policy\n" +
		"# Visibility: http,https\n" +
		"# Dependencies:\n" +
		"# - 10-http-auth-src-loginid-5m.sql\n\n" +
		"SELECT 1;\n"
	if err := os.WriteFile(filepath.Join(policyDir, "20-credential-pressure-control.sql"), []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := parsePolicyTemplate(filepath.Join(policyDir, "20-credential-pressure-control.sql"))
	if err != nil {
		t.Fatal(err)
	}
	policy.FileName = "20-credential-pressure-control.sql"
	files, err := policyFileCopyList(root, policy)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		mandatoryRuleQueueSQLFile,
		"01-stream-http-on-completion.sql",
		"10-http-auth-src-loginid-5m.sql",
		"policies/20-credential-pressure-control.sql",
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("policyFileCopyList = %#v, want %#v", files, want)
	}
}

// TestRemovePolicyKeepsDependenciesUsedByRemainingPolicies protects the
// dependency-tree cleanup rule: only orphaned windows/streams may be deleted.
func TestRemovePolicyKeepsDependenciesUsedByRemainingPolicies(t *testing.T) {
	sourceRoot := t.TempDir()
	templateRoot := filepath.Join(sourceRoot, "templates", "RioSQL")
	policyDir := filepath.Join(templateRoot, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(templateRoot, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(mandatoryRuleQueueSQLFile, "CREATE STREAM rule_queue;\n")
	write("01-stream-http-on-completion.sql", "CREATE STREAM http_log_on_request_completion;\n")
	write("10-shared-window.sql", "# Dependencies: 01-stream-http-on-completion.sql\n\nCREATE WINDOW shared;\n")
	write("10-policy-a-only.sql", "# Dependencies: 01-stream-http-on-completion.sql\n\nCREATE WINDOW policy_a_only;\n")
	write("policies/20-policy-a.sql", "# Policy: Policy A\n# Policy ID: policy_a\n# Summary: A\n# Visibility: http,https\n# Dependencies:\n# - 10-shared-window.sql\n# - 10-policy-a-only.sql\n\nSELECT 1;\n")
	write("policies/20-policy-b.sql", "# Policy: Policy B\n# Policy ID: policy_b\n# Summary: B\n# Visibility: http,https\n# Dependencies:\n# - 10-shared-window.sql\n\nSELECT 1;\n")

	installDir := filepath.Join(sourceRoot, "riodb-install")
	sqlDir := filepath.Join(installDir, "riodb", "sql")
	if err := os.MkdirAll(sqlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		mandatoryRuleQueueSQLFile,
		"01-stream-http-on-completion.sql",
		"10-shared-window.sql",
		"10-policy-a-only.sql",
		"20-policy-a.sql",
		"20-policy-b.sql",
	} {
		if err := os.WriteFile(filepath.Join(sqlDir, name), []byte("SELECT 1;\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{
		CommandLine: true,
		SourceRoot:  sourceRoot,
		Config: &Config{Data: map[string]map[string]string{
			"riodb": {"install_dir": installDir},
		}},
	}
	catalog, err := loadPolicyCatalog(app)
	if err != nil {
		t.Fatal(err)
	}
	policyA, ok := selectPolicyByID(catalog, "policy_a")
	if !ok {
		t.Fatal("policy_a not found in catalog")
	}
	if err := removePolicy(nil, app, policyA, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{mandatoryRuleQueueSQLFile, "01-stream-http-on-completion.sql", "10-shared-window.sql", "20-policy-b.sql"} {
		if _, err := os.Stat(filepath.Join(sqlDir, name)); err != nil {
			t.Fatalf("%s should remain for policy_b: %v", name, err)
		}
	}
	for _, name := range []string{"20-policy-a.sql", "10-policy-a-only.sql"} {
		if _, err := os.Stat(filepath.Join(sqlDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should be removed, stat err=%v", name, err)
		}
	}
}

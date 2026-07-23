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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandleCLIArgsHelpAndVersion(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{"short help", []string{"-h"}, "Usage:"},
		{"long help", []string{"--help"}, "proxyble-rule-agent [http|tcp]"},
		{"short version", []string{"-v"}, "proxyble-rule-agent 2026.2"},
		{"long version", []string{"--version"}, "proxyble-rule-agent 2026.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			_, handled, exitCode := handleCLIArgs(tt.args, &stdout, &stderr)
			if !handled {
				t.Fatal("expected argument to be handled")
			}
			if exitCode != 0 {
				t.Fatalf("expected exit code 0, got %d", exitCode)
			}
			if !strings.Contains(stdout.String(), tt.wantOutput) {
				t.Fatalf("expected stdout %q to contain %q", stdout.String(), tt.wantOutput)
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected empty stderr, got %q", stderr.String())
			}
		})
	}
}

func TestHandleCLIArgsModesAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	mode, handled, exitCode := handleCLIArgs([]string{"http"}, &stdout, &stderr)
	if handled || exitCode != 0 || mode != "http" {
		t.Fatalf("expected http mode to continue execution, got mode=%q handled=%v exitCode=%d", mode, handled, exitCode)
	}

	stdout.Reset()
	stderr.Reset()
	_, handled, exitCode = handleCLIArgs([]string{"udp"}, &stdout, &stderr)
	if !handled || exitCode != 1 {
		t.Fatalf("expected invalid mode to be handled with exit code 1, got handled=%v exitCode=%d", handled, exitCode)
	}
	if !strings.Contains(stderr.String(), "mode must be either http or tcp") {
		t.Fatalf("expected invalid mode message, got %q", stderr.String())
	}
}

func TestParseSampleRules(t *testing.T) {
	now := time.Unix(1000, 0)
	tests := []struct {
		line     string
		action   string
		system   string
		target   string
		param    string
		duration string
	}{
		{"limit_bandwidth 192.0.40.85 15mb 10s", ActionLimitBandwidth, SystemHAProxy, "192.0.40.85/32", "15mb", "10s"},
		{"LIMIT_BANDWIDTH 192.0.105.0/24 10mb", ActionLimitBandwidth, SystemHAProxy, "192.0.105.0/24", "10mb", ""},
		{"LIMIT_BANDWIDTH 192.0.106.0/24 1gb", ActionLimitBandwidth, SystemHAProxy, "192.0.106.0/24", "1gb", ""},
		{"drop 192.0.81.141", ActionDrop, SystemNFTables, "192.0.81.141/32", "", ""},
		{"DROP 192.0.166.0/24 10s", ActionDrop, SystemNFTables, "192.0.166.0/24", "", "10s"},
		{"reject 192.0.69.0/24 10s", ActionReject, SystemNFTables, "192.0.69.0/24", "", "10s"},
		{"REJECT 192.0.3.117", ActionReject, SystemNFTables, "192.0.3.117/32", "", ""},
		{"limit_concurrent 192.0.142.1 55 10s", ActionLimitConcurrent, SystemNFTables, "192.0.142.1/32", "55", "10s"},
		{"LIMIT_CONCURRENT 192.0.124.0/24 50", ActionLimitConcurrent, SystemNFTables, "192.0.124.0/24", "50", ""},
		{"limit_conn_rate 192.0.85.43 25/second 10s", ActionLimitConnRate, SystemNFTables, "192.0.85.43/32", "25/second", "10s"},
		{"LIMIT_CONN_RATE 192.0.216.0/24 20/second", ActionLimitConnRate, SystemNFTables, "192.0.216.0/24", "20/second", ""},
		{"timeout 192.0.132.87 5s 10s", ActionTimeout, SystemHAProxy, "192.0.132.87/32", "5s", "10s"},
		{"TIMEOUT 192.0.221.0/24 10s", ActionTimeout, SystemHAProxy, "192.0.221.0/24", "10s", ""},
		{"TIMEOUT 192.0.222.0/24 500ms", ActionTimeout, SystemHAProxy, "192.0.222.0/24", "500ms", ""},
		{"limit_rate_slow 192.0.29.43 10s", ActionLimitRateSlow, SystemHAProxy, "192.0.29.43/32", "", "10s"},
		{"LIMIT_RATE_SLOW 192.0.91.0/24", ActionLimitRateSlow, SystemHAProxy, "192.0.91.0/24", "", ""},
		{"busy_deflection 192.0.28.210 10s", ActionBusyDeflection, SystemHAProxy, "192.0.28.210/32", "", "10s"},
		{"BUSY_DEFLECTION 192.0.49.0/24", ActionBusyDeflection, SystemHAProxy, "192.0.49.0/24", "", ""},
		{"limit_endpoint_rate 192.0.2.50 10/second /login,/api/export 10s", ActionLimitEndpoint, SystemHAProxy, "192.0.2.50", "10/second", "10s"},
		{"LIMIT_ENDPOINT_RATE 192.0.2.51 120/minute /search", ActionLimitEndpoint, SystemHAProxy, "192.0.2.51", "120/minute", ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			p, err := parseRuleLine(tt.line, now)
			if err != nil {
				t.Fatalf("parseRuleLine() error = %v", err)
			}
			if p.Action != tt.action || p.System != tt.system || p.IP != tt.target || p.Parameter != tt.param || p.Duration != tt.duration {
				t.Fatalf("parsed rule mismatch: got action=%q system=%q target=%q param=%q duration=%q", p.Action, p.System, p.IP, p.Parameter, p.Duration)
			}
			if tt.duration == "" {
				if !p.ExpiresAt.IsZero() {
					t.Fatalf("expected permanent rule, got expiration %v", p.ExpiresAt)
				}
				return
			}
			if !p.ExpiresAt.Equal(now.Add(10 * time.Second)) {
				t.Fatalf("expected expiration %v, got %v", now.Add(10*time.Second), p.ExpiresAt)
			}
		})
	}
}

func TestParseRejectsIPv6Targets(t *testing.T) {
	now := time.Unix(1000, 0)
	if _, err := parseRuleLine("drop 2001:db8::1", now); err == nil {
		t.Fatal("expected IPv6 NFTables rule to be rejected")
	}
	if _, err := parseRuleLine("timeout 2001:db8::1 5s", now); err == nil {
		t.Fatal("expected IPv6 HAProxy rule to be rejected")
	}
}

func TestParseNormalizesCIDRHostBitsForLimitRules(t *testing.T) {
	now := time.Unix(1000, 0)
	p, err := parseRuleLine("LIMIT_CONCURRENT 10.10.10.10/24 50", now)
	if err != nil {
		t.Fatalf("parseRuleLine() error = %v", err)
	}
	if p.IP != "10.10.10.0/24" {
		t.Fatalf("expected CIDR host bits to normalize to 10.10.10.0/24, got %q", p.IP)
	}

	p, err = parseRuleLine("LIMIT_CONN_RATE 20.20.20.20/28 25/second", now)
	if err != nil {
		t.Fatalf("parseRuleLine() error = %v", err)
	}
	if p.IP != "20.20.20.16/28" {
		t.Fatalf("expected CIDR host bits to normalize to 20.20.20.16/28, got %q", p.IP)
	}
}

func TestBuildNFTBatchUsesActionSpecificRules(t *testing.T) {
	state := State{Rules: map[string]Rule{
		"192.0.2.10/32": {IP: "192.0.2.10/32", Action: ActionDrop, System: SystemNFTables, Duration: "10s"},
		"192.0.2.0/24":  {IP: "192.0.2.0/24", Action: ActionReject, System: SystemNFTables},
		"192.0.3.0/24":  {IP: "192.0.3.0/24", Action: ActionLimitConcurrent, System: SystemNFTables, Parameter: "55"},
		"192.0.4.0/24":  {IP: "192.0.4.0/24", Action: ActionLimitConnRate, System: SystemNFTables, Parameter: "25/second", Duration: "10s"},
		"192.0.2.14/32": {IP: "192.0.2.14/32", Action: ActionLimitBandwidth, System: SystemHAProxy, Parameter: "15mb"},
	}}

	batch := buildNFTBatch(state)
	dropRule := state.Rules["192.0.2.10/32"]
	dropScopeSet, _ := nftPerSourceSetNames(dropRule)
	rejectRule := state.Rules["192.0.2.0/24"]
	rejectScopeSet, _ := nftPerSourceSetNames(rejectRule)
	concurrentRule := state.Rules["192.0.3.0/24"]
	concurrentScopeSet, concurrentSourceSet := nftPerSourceSetNames(concurrentRule)
	rateRule := state.Rules["192.0.4.0/24"]
	rateScopeSet, rateSourceSet := nftPerSourceSetNames(rateRule)

	if !strings.HasPrefix(batch, "delete table inet pmgr\nadd table inet pmgr\n") {
		t.Fatalf("expected NFT batch to delete existing table before adding it, got:\n%s", batch)
	}
	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 192.0.2.10/32 timeout 10s }", dropScopeSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s drop", dropScopeSet))
	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 192.0.2.0/24 }", rejectScopeSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s reject", rejectScopeSet))
	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 192.0.3.0/24 }", concurrentScopeSet))
	mustContain(t, batch, fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags dynamic; size 65536; }", concurrentSourceSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s add @%s { ip saddr ct count over 55 } drop", concurrentScopeSet, concurrentSourceSet))
	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 192.0.4.0/24 timeout 10s }", rateScopeSet))
	mustContain(t, batch, fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags dynamic, timeout; timeout 10s; size 65536; }", rateSourceSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s ct state new add @%s { ip saddr limit rate over 25/second } drop", rateScopeSet, rateSourceSet))
	mustNotContain(t, batch, "192.0.2.14")
}

func TestBuildNFTBatchUsesSeparateSetsForOverlappingDropTargets(t *testing.T) {
	singleIP := Rule{IP: "20.20.20.20/32", Action: ActionDrop, System: SystemNFTables}
	cidr := Rule{IP: "20.20.20.0/24", Action: ActionDrop, System: SystemNFTables}
	state := State{Rules: map[string]Rule{
		singleIP.IP: singleIP,
		cidr.IP:     cidr,
	}}

	batch := buildNFTBatch(state)
	singleSet, _ := nftPerSourceSetNames(singleIP)
	cidrSet, _ := nftPerSourceSetNames(cidr)
	if singleSet == cidrSet {
		t.Fatalf("expected overlapping DROP targets to use distinct sets, got %q", singleSet)
	}

	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 20.20.20.20/32 }", singleSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s drop", singleSet))
	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 20.20.20.0/24 }", cidrSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s drop", cidrSet))
	mustNotContain(t, batch, "drop_src")
}

func TestBuildNFTBatchForMissingTableSkipsDelete(t *testing.T) {
	state := State{Rules: map[string]Rule{
		"192.0.2.10/32": {IP: "192.0.2.10/32", Action: ActionDrop, System: SystemNFTables},
	}}

	batch := buildNFTBatchForMissingTable(state)
	if !strings.HasPrefix(batch, "add table inet pmgr\n") {
		t.Fatalf("expected missing-table batch to start with add table, got:\n%s", batch)
	}
	mustNotContain(t, batch, "delete table inet pmgr")
}

func TestNFTBatchFailedBecauseTableMissing(t *testing.T) {
	if !nftBatchFailedBecauseTableMissing(fmt.Errorf("nft -f failed: exit status 1: No such file or directory")) {
		t.Fatal("expected missing table error to be retryable")
	}
	if nftBatchFailedBecauseTableMissing(fmt.Errorf("nft -f failed: syntax error")) {
		t.Fatal("did not expect syntax error to be retryable as a missing table")
	}
}

func TestBuildNFTBatchUsesSeparatePerSourceSetsForDifferentCIDRLimits(t *testing.T) {
	first := Rule{IP: "10.10.10.0/24", Action: ActionLimitConcurrent, System: SystemNFTables, Parameter: "50"}
	second := Rule{IP: "20.20.20.16/28", Action: ActionLimitConcurrent, System: SystemNFTables, Parameter: "10"}
	state := State{Rules: map[string]Rule{
		first.IP:  first,
		second.IP: second,
	}}

	batch := buildNFTBatch(state)
	firstScopeSet, firstSourceSet := nftPerSourceSetNames(first)
	secondScopeSet, secondSourceSet := nftPerSourceSetNames(second)
	if firstSourceSet == secondSourceSet {
		t.Fatalf("expected different dynamic source sets for different limit rules, got %q", firstSourceSet)
	}

	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 10.10.10.0/24 }", firstScopeSet))
	mustContain(t, batch, fmt.Sprintf("add element inet pmgr %s { 20.20.20.16/28 }", secondScopeSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s add @%s { ip saddr ct count over 50 } drop", firstScopeSet, firstSourceSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ip saddr @%s add @%s { ip saddr ct count over 10 } drop", secondScopeSet, secondSourceSet))
	if got := strings.Count(batch, "flags dynamic; size 65536"); got != 2 {
		t.Fatalf("expected one dynamic per-source set per limit rule, got %d\n%s", got, batch)
	}
	mustNotContain(t, batch, "10.10.10.1/32")
	mustNotContain(t, batch, "20.20.20.17/32")
}

func TestBuildNFTBatchUsesDirectPerSourceMetersForGlobalLimits(t *testing.T) {
	concurrent := Rule{IP: "0.0.0.0/0", Action: ActionLimitConcurrent, System: SystemNFTables, Parameter: "50"}
	rate := Rule{IP: "0.0.0.0/0", Action: ActionLimitConnRate, System: SystemNFTables, Parameter: "25/second"}
	state := State{Rules: map[string]Rule{
		"global-concurrent": concurrent,
		"global-rate":       rate,
	}}

	batch := buildNFTBatch(state)
	concurrentScopeSet, concurrentSourceSet := nftPerSourceSetNames(concurrent)
	rateScopeSet, rateSourceSet := nftPerSourceSetNames(rate)

	mustContain(t, batch, fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags dynamic; size 65536; }", concurrentSourceSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules add @%s { ip saddr ct count over 50 } drop", concurrentSourceSet))
	mustContain(t, batch, fmt.Sprintf("add set inet pmgr %s { type ipv4_addr; flags dynamic, timeout; timeout 10s; size 65536; }", rateSourceSet))
	mustContain(t, batch, fmt.Sprintf("add rule inet pmgr managed_rules ct state new add @%s { ip saddr limit rate over 25/second } drop", rateSourceSet))
	mustNotContain(t, batch, concurrentScopeSet)
	mustNotContain(t, batch, rateScopeSet)
	mustNotContain(t, batch, "add element inet pmgr")
}

func TestConnRateDynamicElementTimeoutTracksRateWindow(t *testing.T) {
	tests := map[string]string{
		"25/second":  "10s",
		"100/minute": "2m",
		"500/hour":   "2h",
		"1000/day":   "2d",
		"invalid":    "10s",
	}

	for rate, want := range tests {
		t.Run(rate, func(t *testing.T) {
			if got := nftConnRateElementTimeout(rate); got != want {
				t.Fatalf("nftConnRateElementTimeout(%q) = %q, want %q", rate, got, want)
			}
		})
	}
}

func TestBuildHAProxyPayload(t *testing.T) {
	state := State{Rules: map[string]Rule{
		"192.0.2.20/32": {IP: "192.0.2.20/32", Action: ActionLimitBandwidth, System: SystemHAProxy, Parameter: "15mb"},
		"192.0.2.0/24":  {IP: "192.0.2.0/24", Action: ActionTimeout, System: SystemHAProxy, Parameter: "5s"},
		"192.0.3.0/24":  {IP: "192.0.3.0/24", Action: ActionLimitRateSlow, System: SystemHAProxy},
		"192.0.4.0/24":  {IP: "192.0.4.0/24", Action: ActionBusyDeflection, System: SystemHAProxy},
		"192.0.2.24/32": {IP: "192.0.2.24/32", Action: ActionDrop, System: SystemNFTables},
		"192.0.2.25":    {IP: "192.0.2.25", Action: ActionLimitEndpoint, System: SystemHAProxy, Parameter: "10/second", Endpoints: []string{"/api/export", "/login"}, EndpointRateLimit: 100},
	}}

	payload := buildHAProxyPayload(state)
	mustContain(t, payload, "add map /etc/haproxy/maps/rules.map 192.0.2.20/32 BW_LIM")
	mustContain(t, payload, "add map /etc/haproxy/maps/params.map 192.0.2.20/32 15mb")
	mustContain(t, payload, "add map /etc/haproxy/maps/rules.map 192.0.2.0/24 T_OUT")
	mustContain(t, payload, "add map /etc/haproxy/maps/params.map 192.0.2.0/24 5s")
	mustContain(t, payload, "add map /etc/haproxy/maps/rules.map 192.0.3.0/24 RATE_REJ")
	mustContain(t, payload, "add map /etc/haproxy/maps/rules.map 192.0.4.0/24 BUSY")
	mustContain(t, payload, "add map /etc/haproxy/maps/rules.map 192.0.2.25 ENDPOINT_RATE")
	mustContain(t, payload, "add map /etc/haproxy/maps/params.map 192.0.2.25 10/second")
	mustContain(t, payload, "add map /etc/haproxy/maps/endpoint-rates.map 192.0.2.25|/api/export 100")
	mustContain(t, payload, "add map /etc/haproxy/maps/endpoint-rates.map 192.0.2.25|/login 100")
	mustNotContain(t, payload, "192.0.2.24")
	mustNotContain(t, payload, ";")
}

func TestBuildHAProxyMapBodies(t *testing.T) {
	state := State{Rules: map[string]Rule{
		"192.0.2.20/32": {IP: "192.0.2.20/32", Action: ActionLimitBandwidth, System: SystemHAProxy, Parameter: "15mb"},
		"192.0.2.0/24":  {IP: "192.0.2.0/24", Action: ActionTimeout, System: SystemHAProxy, Parameter: "5s"},
		"192.0.2.24/32": {IP: "192.0.2.24/32", Action: ActionDrop, System: SystemNFTables},
		"192.0.2.25":    {IP: "192.0.2.25", Action: ActionLimitEndpoint, System: SystemHAProxy, Parameter: "10/second", Endpoints: []string{"/api/export", "/login"}, EndpointRateLimit: 100},
	}}

	bodies := buildHAProxyMapBodies(state)
	mustContain(t, bodies.rules, "192.0.2.20/32 BW_LIM")
	mustContain(t, bodies.rules, "192.0.2.0/24 T_OUT")
	mustContain(t, bodies.rules, "192.0.2.25 ENDPOINT_RATE")
	mustContain(t, bodies.params, "192.0.2.20/32 15mb")
	mustContain(t, bodies.params, "192.0.2.0/24 5s")
	mustContain(t, bodies.params, "192.0.2.25 10/second")
	mustContain(t, bodies.endpointRates, "192.0.2.25|/api/export 100")
	mustContain(t, bodies.endpointRates, "192.0.2.25|/login 100")
	mustNotContain(t, bodies.rules, "192.0.2.24")
}

func TestEndpointRateIsHTTPOnly(t *testing.T) {
	p := Rule{Action: ActionLimitEndpoint, System: SystemHAProxy}
	if !shouldSkipRuleForMode(p, "tcp") {
		t.Fatal("expected LIMIT_ENDPOINT_RATE to be skipped in tcp mode")
	}
	if shouldSkipRuleForMode(p, "http") {
		t.Fatal("did not expect LIMIT_ENDPOINT_RATE to be skipped in http mode")
	}
}

func TestLimitEndpointRateParsing(t *testing.T) {
	now := time.Unix(1000, 0)
	p, err := parseRuleLine("LIMIT_ENDPOINT_RATE 192.0.2.50 120/minute /login,/api/export,/login 10m", now)
	if err != nil {
		t.Fatalf("parseRuleLine() error = %v", err)
	}
	if p.Action != ActionLimitEndpoint || p.System != SystemHAProxy {
		t.Fatalf("unexpected rule routing: %+v", p)
	}
	if p.Parameter != "120/minute" {
		t.Fatalf("expected normalized rate, got %q", p.Parameter)
	}
	if p.EndpointRateLimit != 20 {
		t.Fatalf("expected 120/minute to normalize to 20 requests per 10s, got %d", p.EndpointRateLimit)
	}
	if strings.Join(p.Endpoints, ",") != "/api/export,/login" {
		t.Fatalf("unexpected endpoints: %#v", p.Endpoints)
	}
	if p.Duration != "10m" || !p.ExpiresAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("unexpected expiration: duration=%q expires=%v", p.Duration, p.ExpiresAt)
	}
}

func TestLimitEndpointRateRejectsUnsafeSyntax(t *testing.T) {
	now := time.Unix(1000, 0)
	badLines := []string{
		"LIMIT_ENDPOINT_RATE 192.0.2.10 5/hour /login",
		"LIMIT_ENDPOINT_RATE 192.0.2.10 5/second /",
		"LIMIT_ENDPOINT_RATE 192.0.2.10 5/second login",
		"LIMIT_ENDPOINT_RATE 192.0.2.10 5/second /login?next=/admin",
		"LIMIT_ENDPOINT_RATE 192.0.2.10 5/second /login|/admin",
		"LIMIT_ENDPOINT_RATE 192.0.2.0/24 5/second /login",
	}

	for _, line := range badLines {
		t.Run(line, func(t *testing.T) {
			if _, err := parseRuleLine(line, now); err == nil {
				t.Fatalf("expected %q to be rejected", line)
			}
		})
	}
}

func TestGlobalDropRejectRequiresExpiration(t *testing.T) {
	now := time.Unix(1000, 0)
	if _, err := parseRuleLine("DROP 0.0.0.0/0", now); err == nil {
		t.Fatal("expected permanent global DROP to be rejected")
	}
	if _, err := parseRuleLine("REJECT 0.0.0.0/0", now); err == nil {
		t.Fatal("expected permanent global REJECT to be rejected")
	}
	p, err := parseRuleLine("DROP 0.0.0.0/0 10s", now)
	if err != nil {
		t.Fatalf("expected expiring global DROP to parse: %v", err)
	}
	if p.IP != "0.0.0.0/0" || p.Duration != "10s" {
		t.Fatalf("unexpected global DROP parse: %+v", p)
	}
}

func TestNormalizeStateRuleKeys(t *testing.T) {
	state := normalizeStateRuleKeys(map[string]Rule{
		"192.0.2.10": {IP: "192.0.2.10", Action: ActionLimitRateSlow, System: SystemHAProxy},
	})
	if _, exists := state["192.0.2.10/32"]; !exists {
		t.Fatalf("expected legacy singleton IP state to normalize to /32: %#v", state)
	}
}

func TestLoadStateTreatsEmptyFileAsEmptyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, nil, privateFileMode); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)

	state := loadState(path)
	if len(state.Rules) != 0 {
		t.Fatalf("empty state file should load as no rules, got %#v", state.Rules)
	}
	if strings.Contains(logs.String(), "ERROR ACTION=LOAD_STATE") {
		t.Fatalf("empty state file should not log a load error, got %q", logs.String())
	}
}

func TestLoadInputRotatesAndRecreatesInbox(t *testing.T) {
	dir := t.TempDir()
	inbox := filepath.Join(dir, "inbox.tmp")
	if err := os.WriteFile(inbox, []byte("DROP 192.0.2.10 10s\n"), inboxFileMode); err != nil {
		t.Fatal(err)
	}

	rules := loadInput(inbox, time.Unix(1000, 0))
	if _, ok := rules["192.0.2.10/32"]; !ok {
		t.Fatalf("expected rule parsed from rotated inbox, got %#v", rules)
	}
	if _, err := os.Stat(inbox + ".processing"); !os.IsNotExist(err) {
		t.Fatalf("processing file should be removed after loadInput, err=%v", err)
	}
	info, err := os.Stat(inbox)
	if err != nil {
		t.Fatalf("fresh inbox was not recreated: %v", err)
	}
	if got := info.Mode().Perm(); got != inboxFileMode {
		t.Fatalf("fresh inbox mode = %#o, want %#o", got, inboxFileMode)
	}
	data, err := os.ReadFile(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("fresh inbox should be empty, got %q", data)
	}
}

func TestLoadInputLeavesEmptyInboxInPlace(t *testing.T) {
	dir := t.TempDir()
	inbox := filepath.Join(dir, "inbox.tmp")
	if err := os.WriteFile(inbox, nil, 0o666); err != nil {
		t.Fatal(err)
	}

	rules := loadInput(inbox, time.Unix(1000, 0))
	if len(rules) != 0 {
		t.Fatalf("expected no rules from empty inbox, got %#v", rules)
	}
	if _, err := os.Stat(inbox + ".processing"); !os.IsNotExist(err) {
		t.Fatalf("empty inbox should not be rotated, err=%v", err)
	}
	info, err := os.Stat(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != inboxFileMode {
		t.Fatalf("empty inbox mode = %#o, want %#o", got, inboxFileMode)
	}
}

func mustContain(t *testing.T, value, needle string) {
	t.Helper()
	if !strings.Contains(value, needle) {
		t.Fatalf("expected %q to contain %q", value, needle)
	}
}

func mustNotContain(t *testing.T, value, needle string) {
	t.Helper()
	if strings.Contains(value, needle) {
		t.Fatalf("expected %q not to contain %q", value, needle)
	}
}

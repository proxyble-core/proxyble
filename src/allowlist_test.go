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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	oldEndpointAllowListFile := endpointAllowListFile
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("proxyble-endpoint-allow-list-test-%d", os.Getpid()))
	endpointAllowListFile = filepath.Join(dir, "endpoint.sources")
	code := m.Run()
	endpointAllowListFile = oldEndpointAllowListFile
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestNormalizeBasicAllowListSource(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"203.0.113.25", "203.0.113.25"},
		{" 203.0.113.0/24 ", "203.0.113.0/24"},
		{"203.0.113.25/24", "203.0.113.0/24"},
	}
	for _, tc := range cases {
		got, err := normalizeBasicAllowListSource(tc.input)
		if err != nil {
			t.Fatalf("normalizeBasicAllowListSource(%q) returned error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeBasicAllowListSource(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	for _, input := range []string{"", "203.0.113.1 203.0.113.2", "2001:db8::1", "0.0.0.0/0"} {
		if got, err := normalizeBasicAllowListSource(input); err == nil {
			t.Fatalf("normalizeBasicAllowListSource(%q) = %q, want error", input, got)
		}
	}
}

func TestBasicAllowListSourceSetCanonicalizesCoveredEntries(t *testing.T) {
	sources := []string{"203.0.113.25"}
	updated, added, covered := addBasicAllowListSourceToSet(sources, "203.0.113.0/24")
	if !added || covered {
		t.Fatalf("add CIDR over existing IP = added %v covered %v", added, covered)
	}
	if len(updated) != 1 || updated[0] != "203.0.113.0/24" {
		t.Fatalf("updated sources = %#v, want only covering CIDR", updated)
	}

	updated, added, covered = addBasicAllowListSourceToSet(updated, "203.0.113.44")
	if added || !covered {
		t.Fatalf("covered IP add = added %v covered %v", added, covered)
	}
	if len(updated) != 1 || updated[0] != "203.0.113.0/24" {
		t.Fatalf("covered IP should not change sources: %#v", updated)
	}
}

func TestBasicAllowListSourceFileParsingAndWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "basic.sources")
	body := "# comment\n203.0.113.25\n203.0.113.0/24\n198.51.100.7\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	sources, err := loadBasicAllowListSources(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(sources, ","), "203.0.113.0/24,198.51.100.7"; got != want {
		t.Fatalf("loaded sources = %q, want %q", got, want)
	}

	out := filepath.Join(t.TempDir(), "allow-list", "basic.sources")
	if err := writeBasicAllowListSources(out, sources); err != nil {
		t.Fatal(err)
	}
	if got, want := readTestFile(t, out), "203.0.113.0/24\n198.51.100.7\n"; got != want {
		t.Fatalf("written sources = %q, want %q", got, want)
	}
}

func TestBuildBasicAllowListNFTBatch(t *testing.T) {
	batch, err := buildBasicAllowListNFTBatch(completeRuntimeConfig(), []string{"203.0.113.0/24", "198.51.100.7"}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"delete table inet proxyble_allowlist",
		"add table inet proxyble_allowlist",
		"add set inet proxyble_allowlist basic_sources { type ipv4_addr; flags interval; }",
		"add element inet proxyble_allowlist basic_sources { 203.0.113.0/24, 198.51.100.7 }",
		"add chain inet proxyble_allowlist basic_input { type filter hook input priority -10; policy accept; }",
		"add rule inet proxyble_allowlist basic_input tcp dport 80 ip saddr @basic_sources accept",
		"add rule inet proxyble_allowlist basic_input tcp dport 80 reject with tcp reset",
	} {
		if !strings.Contains(batch, want) {
			t.Fatalf("batch missing %q\n%s", want, batch)
		}
	}

	batch, err = buildBasicAllowListNFTBatch(completeRuntimeConfig(), []string{"203.0.113.25"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(batch, "delete table") {
		t.Fatalf("missing-table retry batch should not delete table\n%s", batch)
	}
}

func TestBasicAllowListSourceMenuPlacesRemoveAllBeforeBack(t *testing.T) {
	items := basicAllowListSourceMenuItems([]string{"203.0.113.25", "198.51.100.0/24"})
	if got, want := menuChoiceTag(items[len(items)-2][0]), "remove-all"; got != want {
		t.Fatalf("next-to-last item = %q, want %q", got, want)
	}
	if got, want := menuChoiceTag(items[len(items)-1][0]), "back"; got != want {
		t.Fatalf("last item = %q, want %q", got, want)
	}
}

func TestParseBasicAllowListArgs(t *testing.T) {
	opts, err := parseBasicAllowListArgs([]string{"--add", "127.0.0.1"})
	if err != nil {
		t.Fatalf("parse add returned error: %v", err)
	}
	if opts.add != "127.0.0.1" || opts.remove != "" || opts.removeAll || opts.yes {
		t.Fatalf("add options = %#v", opts)
	}

	opts, err = parseBasicAllowListArgs([]string{"--add=10.10.10.0/24"})
	if err != nil {
		t.Fatalf("parse add= returned error: %v", err)
	}
	if opts.add != "10.10.10.0/24" {
		t.Fatalf("add = %q, want CIDR", opts.add)
	}

	opts, err = parseBasicAllowListArgs([]string{"--remove", "127.0.0.1", "--yes"})
	if err != nil {
		t.Fatalf("parse remove returned error: %v", err)
	}
	if opts.remove != "127.0.0.1" || !opts.yes {
		t.Fatalf("remove options = %#v", opts)
	}

	opts, err = parseBasicAllowListArgs([]string{"--remove-all", "--yes"})
	if err != nil {
		t.Fatalf("parse remove-all returned error: %v", err)
	}
	if !opts.removeAll || !opts.yes {
		t.Fatalf("remove-all options = %#v", opts)
	}
}

func TestParseBasicAllowListArgsRejectsInvalidActionSelection(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--add", "127.0.0.1", "--remove", "127.0.0.1"},
		{"--remove-all", "--add", "127.0.0.1"},
		{"--unknown"},
	} {
		if opts, err := parseBasicAllowListArgs(args); err == nil {
			t.Fatalf("parseBasicAllowListArgs(%v) = %#v, want error", args, opts)
		}
	}
}

func TestBasicAllowListRemovalConfirmItems(t *testing.T) {
	items := basicAllowListRemovalConfirmItems("203.0.113.25")
	if got, want := menuChoiceTag(items[0][0]), "yes"; got != want {
		t.Fatalf("first confirmation choice = %q, want %q", got, want)
	}
	if !strings.Contains(items[0][1], "Remove 203.0.113.25 from allow-list.") {
		t.Fatalf("single-source confirmation description = %q", items[0][1])
	}
	if got, want := menuChoiceTag(items[1][0]), "cancel"; got != want {
		t.Fatalf("second confirmation choice = %q, want %q", got, want)
	}
	if !strings.Contains(items[1][1], "Leave allow-list as is.") {
		t.Fatalf("cancel confirmation description = %q", items[1][1])
	}

	items = basicAllowListRemovalConfirmItems("ALL")
	if !strings.Contains(items[0][1], "Remove ALL from allow-list.") {
		t.Fatalf("remove-all confirmation description = %q", items[0][1])
	}
}

func TestNormalizeEndpointAllowListEndpoint(t *testing.T) {
	for _, input := range []string{"/", "/login", "/api/v1", "/orders;v=1"} {
		got, err := normalizeEndpointAllowListEndpoint(input)
		if err != nil {
			t.Fatalf("normalizeEndpointAllowListEndpoint(%q) returned error: %v", input, err)
		}
		if got != input {
			t.Fatalf("normalizeEndpointAllowListEndpoint(%q) = %q", input, got)
		}
	}

	for _, input := range []string{"", "login", "/api v1", "/api?x=1", "/api#frag", "/api\\v1", "/api\"v1"} {
		if got, err := normalizeEndpointAllowListEndpoint(input); err == nil {
			t.Fatalf("normalizeEndpointAllowListEndpoint(%q) = %q, want error", input, got)
		}
	}
}

func TestEndpointAllowListEntrySetCanonicalizesPerEndpoint(t *testing.T) {
	entries := []endpointAllowListEntry{{Source: "203.0.113.25", Endpoint: "/api"}}
	updated, added, covered := addEndpointAllowListEntriesToSet(entries, "203.0.113.0/24", []string{"/api", "/login"})
	if added != 2 || covered != 0 {
		t.Fatalf("add covering CIDR = added %d covered %d", added, covered)
	}
	if got, want := endpointAllowListEntriesString(updated), "203.0.113.0/24 /api\n203.0.113.0/24 /login"; got != want {
		t.Fatalf("updated entries = %q, want %q", got, want)
	}

	updated, added, covered = addEndpointAllowListEntriesToSet(updated, "203.0.113.44", []string{"/api"})
	if added != 0 || covered != 1 {
		t.Fatalf("covered endpoint source add = added %d covered %d", added, covered)
	}
	if got, want := endpointAllowListEntriesString(updated), "203.0.113.0/24 /api\n203.0.113.0/24 /login"; got != want {
		t.Fatalf("covered add should not change entries = %q, want %q", got, want)
	}
}

func TestEndpointAllowListEntryFileParsingAndWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint.sources")
	body := "# comment\n203.0.113.25 /api\n203.0.113.0/24 /api\n198.51.100.7 /login\n\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := loadEndpointAllowListEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := endpointAllowListEntriesString(entries), "203.0.113.0/24 /api\n198.51.100.7 /login"; got != want {
		t.Fatalf("loaded entries = %q, want %q", got, want)
	}

	out := filepath.Join(t.TempDir(), "allow-list", "endpoint.sources")
	if err := writeEndpointAllowListEntries(out, entries); err != nil {
		t.Fatal(err)
	}
	if got, want := readTestFile(t, out), "203.0.113.0/24 /api\n198.51.100.7 /login\n"; got != want {
		t.Fatalf("written entries = %q, want %q", got, want)
	}
}

func TestEndpointAllowListEntryMenuPlacesRemoveAllBeforeBack(t *testing.T) {
	items := endpointAllowListEntryMenuItems([]endpointAllowListEntry{
		{Source: "203.0.113.25", Endpoint: "/api"},
		{Source: "198.51.100.0/24", Endpoint: "/login"},
	})
	if got, want := menuChoiceTag(items[len(items)-2][0]), "remove-all"; got != want {
		t.Fatalf("next-to-last item = %q, want %q", got, want)
	}
	if got, want := menuChoiceTag(items[len(items)-1][0]), "back"; got != want {
		t.Fatalf("last item = %q, want %q", got, want)
	}
}

func TestParseEndpointAllowListArgs(t *testing.T) {
	opts, err := parseEndpointAllowListArgs([]string{"--add", "127.0.0.1", "--endpoints", "/api", "/login"})
	if err != nil {
		t.Fatalf("parse add returned error: %v", err)
	}
	if opts.add != "127.0.0.1" || opts.remove != "" || opts.removeAll || strings.Join(opts.endpoints, ",") != "/api,/login" {
		t.Fatalf("add options = %#v", opts)
	}

	opts, err = parseEndpointAllowListArgs([]string{"--add=10.10.10.0/24", "--endpoints=/api,/health"})
	if err != nil {
		t.Fatalf("parse add= returned error: %v", err)
	}
	if opts.add != "10.10.10.0/24" || strings.Join(opts.endpoints, ",") != "/api,/health" {
		t.Fatalf("add= options = %#v", opts)
	}

	opts, err = parseEndpointAllowListArgs([]string{"--remove", "127.0.0.1", "--endpoint", "/api", "--yes"})
	if err != nil {
		t.Fatalf("parse remove returned error: %v", err)
	}
	if opts.remove != "127.0.0.1" || strings.Join(opts.endpoints, ",") != "/api" || !opts.yes {
		t.Fatalf("remove options = %#v", opts)
	}

	opts, err = parseEndpointAllowListArgs([]string{"--remove-all", "--yes"})
	if err != nil {
		t.Fatalf("parse remove-all returned error: %v", err)
	}
	if !opts.removeAll || !opts.yes {
		t.Fatalf("remove-all options = %#v", opts)
	}
}

func TestParseEndpointAllowListArgsRejectsInvalidActionSelection(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--add", "127.0.0.1"},
		{"--remove", "127.0.0.1"},
		{"--remove-all", "--endpoints", "/api"},
		{"--add", "127.0.0.1", "--remove", "127.0.0.1", "--endpoints", "/api"},
		{"--unknown"},
	} {
		if opts, err := parseEndpointAllowListArgs(args); err == nil {
			t.Fatalf("parseEndpointAllowListArgs(%v) = %#v, want error", args, opts)
		}
	}
}

func TestEndpointAllowListRemovalConfirmItems(t *testing.T) {
	items := endpointAllowListRemovalConfirmItems("203.0.113.25 /api")
	if got, want := menuChoiceTag(items[0][0]), "yes"; got != want {
		t.Fatalf("first confirmation choice = %q, want %q", got, want)
	}
	if !strings.Contains(items[0][1], "Remove 203.0.113.25 /api from allow-list.") {
		t.Fatalf("single-entry confirmation description = %q", items[0][1])
	}
	if got, want := menuChoiceTag(items[1][0]), "cancel"; got != want {
		t.Fatalf("second confirmation choice = %q, want %q", got, want)
	}

	items = endpointAllowListRemovalConfirmItems("ALL")
	if !strings.Contains(items[0][1], "Remove ALL from allow-list.") {
		t.Fatalf("remove-all confirmation description = %q", items[0][1])
	}
}

func TestBuildEndpointAllowListHAProxyRules(t *testing.T) {
	rules := buildEndpointAllowListHAProxyRules([]endpointAllowListEntry{
		{Source: "203.0.113.0/24", Endpoint: "/api"},
		{Source: "198.51.100.7", Endpoint: "/api"},
		{Source: "192.0.2.55", Endpoint: "/login"},
	})
	for _, want := range []string{
		"acl proxyble_endpoint_allow_001 path_beg -i /api",
		"acl proxyble_endpoint_allow_001_src src 203.0.113.0/24 198.51.100.7",
		"http-request set-var(txn.proxyble_endpoint_allow_active) str(1) if proxyble_endpoint_allow_001",
		"http-request set-var(txn.proxyble_endpoint_allow_source) str(1) if proxyble_endpoint_allow_001 proxyble_endpoint_allow_001_src",
		"acl proxyble_endpoint_allow_002 path_beg -i /login",
		"http-request deny deny_status 403 if { var(txn.proxyble_endpoint_allow_active) -m str 1 } !{ var(txn.proxyble_endpoint_allow_source) -m str 1 }",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("HAProxy rules missing %q\n%s", want, rules)
		}
	}
}

func endpointAllowListEntriesString(entries []endpointAllowListEntry) string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, entry.Source+" "+entry.Endpoint)
	}
	return strings.Join(lines, "\n")
}

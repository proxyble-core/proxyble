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

// allowlist.go owns deny-by-default allow-list workflows. Basic allow-list
// enforcement is separate from the rule agent and its pmgr table so manual and
// analytics rules can continue to reconcile independently.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultAllowListDir          = "/etc/proxyble/allow-list"
	defaultBasicAllowListFile    = defaultAllowListDir + "/basic.sources"
	defaultBasicAllowListNFTFile = defaultAllowListDir + "/basic.nft"
	defaultEndpointAllowListFile = defaultAllowListDir + "/endpoint.sources"

	basicAllowListNFTFamily = "inet"
	basicAllowListNFTTable  = "proxyble_allowlist"
	basicAllowListNFTChain  = "basic_input"
	basicAllowListNFTSet    = "basic_sources"
)

var endpointAllowListFile = defaultEndpointAllowListFile

func runAllowListMenu(ctx context.Context, a *App) error {
	for {
		choice, err := menu("[proxyble] Allow-list", "Allow-list denies traffic by default and allows configured source exceptions.\nThis applies only to the Proxyble listening port, not the entire server.", allowListMenuItems(a.Config))
		if err != nil {
			return err
		}
		switch choice {
		case "basic":
			if err := runBasicAllowListMenu(ctx, a); err != nil {
				return err
			}
		case "endpoint":
			if err := runEndpointAllowListMenu(ctx, a); err != nil {
				return err
			}
		case "back", "exit":
			return nil
		}
	}
}

func allowListMenuItems(c *Config) [][2]string {
	items := [][2]string{
		{"basic", "Access to the listening port will be rejected by default, allowing an exception list"},
	}
	if mode, err := c.TrafficMode(); err == nil && (mode == "http" || mode == "https") {
		items = append(items, [2]string{"endpoint", "Access to specific endpoints on the listening port will be rejected, allowing an exception list"})
	}
	items = append(items, [2]string{"back", "Return to previous menu"})
	return items
}

func runBasicAllowListMenu(ctx context.Context, a *App) error {
	for {
		choice, err := menu("[proxyble] Allow-list -> Basic", "Basic allow-list rejects traffic to the listening port by default and allows listed IPv4 sources.", basicAllowListMenuItems())
		if err != nil {
			return err
		}
		switch choice {
		case "add":
			if err := a.PrepareLog("[proxyble] Allow-list -> Basic -> Add"); err != nil {
				return err
			}
			actionPage("[proxyble] Allow-list -> Basic -> Add", "Add an IPv4 address or CIDR block that may connect to the listening port.")
			err = addBasicAllowListSourceInteractive(ctx, a)
			a.CloseLog()
			if err != nil {
				if errors.Is(err, errActionCancelled) {
					continue
				}
				return err
			}
			pause()
		case "view-remove":
			if err := a.PrepareLog("[proxyble] Allow-list -> Basic -> View / Remove"); err != nil {
				return err
			}
			err = viewRemoveBasicAllowListSources(ctx, a)
			a.CloseLog()
			if err != nil {
				if errors.Is(err, errActionCancelled) {
					continue
				}
				return err
			}
		case "back", "exit":
			return nil
		}
	}
}

func basicAllowListMenuItems() [][2]string {
	return [][2]string{
		{"add", "Deny all requests to the listening port by default, allowing only added sources to connect"},
		{"view-remove", "Display current basic allow-list sources and remove selected entries"},
		{"back", "Return to previous menu"},
	}
}

func runEndpointAllowListMenu(ctx context.Context, a *App) error {
	for {
		choice, err := menu("[proxyble] Allow-list -> Endpoint", "Endpoint allow-list rejects traffic to selected HTTP endpoints by default and allows listed source exceptions.", endpointAllowListMenuItems())
		if err != nil {
			return err
		}
		switch choice {
		case "add":
			if err := a.PrepareLog("[proxyble] Allow-list -> Endpoint -> Add"); err != nil {
				return err
			}
			actionPage("[proxyble] Allow-list -> Endpoint -> Add", "Add an IPv4 address or CIDR block and one or more HTTP endpoint paths that may connect.")
			err = addEndpointAllowListEntriesInteractive(ctx, a)
			a.CloseLog()
			if err != nil {
				if errors.Is(err, errActionCancelled) {
					continue
				}
				return err
			}
			pause()
		case "view-remove":
			if err := a.PrepareLog("[proxyble] Allow-list -> Endpoint -> View / Remove"); err != nil {
				return err
			}
			err = viewRemoveEndpointAllowListEntries(ctx, a)
			a.CloseLog()
			if err != nil {
				if errors.Is(err, errActionCancelled) {
					continue
				}
				return err
			}
		case "back", "exit":
			return nil
		}
	}
}

func endpointAllowListMenuItems() [][2]string {
	return [][2]string{
		{"add", "Deny requests to selected endpoints by default, allowing only added source exceptions"},
		{"view-remove", "Display current endpoint allow-list sources and remove selected entries"},
		{"back", "Return to previous menu"},
	}
}

func addEndpointAllowListEntriesInteractive(ctx context.Context, a *App) error {
	if err := requireEndpointAllowListRuntime(a.Config); err != nil {
		return err
	}
	source, err := promptBasicAllowListSource()
	if err != nil {
		return err
	}
	endpoints, err := promptEndpointAllowListEndpoints()
	if err != nil {
		return err
	}
	result, err := addEndpointAllowListEntries(ctx, a, source, endpoints)
	if err != nil {
		return err
	}
	a.Printf("%s\n", result)
	a.Printf("Allow-list file: %s\n", endpointAllowListFile)
	return nil
}

func promptEndpointAllowListEndpoints() ([]string, error) {
	for {
		value, err := promptValue("Allowed endpoint path(s), space separated", "", true)
		if err != nil {
			return nil, err
		}
		endpoints, err := normalizeEndpointAllowListEndpoints(strings.Fields(value))
		if err == nil {
			return endpoints, nil
		}
		fmt.Fprintf(os.Stderr, "\n[ERROR] %s\n\n", sentenceCaseError(err.Error()))
	}
}

func addEndpointAllowListEntries(ctx context.Context, a *App, source string, endpoints []string) (string, error) {
	source, err := normalizeBasicAllowListSource(source)
	if err != nil {
		return "", err
	}
	endpoints, err = normalizeEndpointAllowListEndpoints(endpoints)
	if err != nil {
		return "", err
	}
	if err := requireEndpointAllowListRuntime(a.Config); err != nil {
		return "", err
	}
	if err := ensureEndpointAllowListStore(); err != nil {
		return "", err
	}
	entries, err := loadEndpointAllowListEntries(endpointAllowListFile)
	if err != nil {
		return "", err
	}
	updated, added, covered := addEndpointAllowListEntriesToSet(entries, source, endpoints)
	if added > 0 {
		if err := writeEndpointAllowListEntries(endpointAllowListFile, updated); err != nil {
			return "", err
		}
	}
	if err := applyEndpointAllowList(ctx, a); err != nil {
		return "", err
	}
	if a.LogFile != nil && added > 0 {
		fmt.Fprintf(a.LogFile, "%s ACTION=ALLOWLIST_ENDPOINT_ADD SOURCE=%s ENDPOINTS=%s FILE=%s\n", logTimestamp(), source, strings.Join(endpoints, ","), endpointAllowListFile)
	}
	return endpointAllowListAddMessage(added, covered), nil
}

type endpointAllowListCLIOptions struct {
	add       string
	remove    string
	endpoints []string
	removeAll bool
	yes       bool
}

func parseEndpointAllowListArgs(args []string) (endpointAllowListCLIOptions, error) {
	var opts endpointAllowListCLIOptions
	value := func(i *int, arg string) (string, error) {
		if _, after, ok := strings.Cut(arg, "="); ok {
			return after, nil
		}
		*i = *i + 1
		if *i >= len(args) {
			return "", fmt.Errorf("missing value for %s", arg)
		}
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--add":
			v, err := value(&i, arg)
			if err != nil {
				return opts, err
			}
			opts.add = v
		case strings.HasPrefix(arg, "--add="):
			opts.add, _ = value(&i, arg)
		case arg == "--remove":
			v, err := value(&i, arg)
			if err != nil {
				return opts, err
			}
			opts.remove = v
		case strings.HasPrefix(arg, "--remove="):
			opts.remove, _ = value(&i, arg)
		case arg == "--endpoints" || arg == "--endpoint":
			values, err := endpointAllowListArgValues(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.endpoints = append(opts.endpoints, values...)
		case strings.HasPrefix(arg, "--endpoints=") || strings.HasPrefix(arg, "--endpoint="):
			values, err := endpointAllowListArgValues(args, &i, arg)
			if err != nil {
				return opts, err
			}
			opts.endpoints = append(opts.endpoints, values...)
		case arg == "--remove-all":
			opts.removeAll = true
		case arg == "--yes" || arg == "-y":
			opts.yes = true
		default:
			return opts, fmt.Errorf("unknown option for --endpoint-allow-list: %s", arg)
		}
	}
	actions := 0
	if strings.TrimSpace(opts.add) != "" {
		actions++
	}
	if strings.TrimSpace(opts.remove) != "" {
		actions++
	}
	if opts.removeAll {
		actions++
	}
	if actions != 1 {
		return opts, fmt.Errorf("--endpoint-allow-list requires exactly one of --add SOURCE, --remove SOURCE, or --remove-all")
	}
	if !opts.removeAll {
		endpoints, err := normalizeEndpointAllowListEndpoints(opts.endpoints)
		if err != nil {
			return opts, err
		}
		opts.endpoints = endpoints
	}
	if opts.removeAll && len(opts.endpoints) > 0 {
		return opts, fmt.Errorf("--endpoint-allow-list --remove-all does not accept --endpoints")
	}
	return opts, nil
}

func endpointAllowListArgValues(args []string, i *int, arg string) ([]string, error) {
	if _, after, ok := strings.Cut(arg, "="); ok {
		values := splitEndpointAllowListArg(after)
		if len(values) == 0 {
			return nil, fmt.Errorf("missing value for %s", strings.SplitN(arg, "=", 2)[0])
		}
		return values, nil
	}
	values := []string{}
	for *i+1 < len(args) {
		next := args[*i+1]
		if strings.HasPrefix(next, "--") || next == "-y" {
			break
		}
		*i = *i + 1
		values = append(values, splitEndpointAllowListArg(next)...)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("missing value for %s", arg)
	}
	return values, nil
}

func splitEndpointAllowListArg(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func endpointAllowListCLI(ctx context.Context, a *App, args []string) error {
	opts, err := parseEndpointAllowListArgs(args)
	if err != nil {
		return err
	}
	if err := requireEndpointAllowListRuntime(a.Config); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(opts.add) != "":
		result, err := addEndpointAllowListEntries(ctx, a, opts.add, opts.endpoints)
		if err != nil {
			return err
		}
		a.Printf("%s\n", result)
		a.Printf("Allow-list file: %s\n", endpointAllowListFile)
		return nil
	case strings.TrimSpace(opts.remove) != "":
		source, err := normalizeBasicAllowListSource(opts.remove)
		if err != nil {
			return err
		}
		assumeYes := a.AssumeYes || opts.yes
		ok, err := commandLineConfirm(fmt.Sprintf("Remove %s for %s from endpoint allow-list?", source, strings.Join(opts.endpoints, ", ")), assumeYes)
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Endpoint allow-list removal cancelled.\n")
			return nil
		}
		result, err := removeEndpointAllowListEntries(ctx, a, source, opts.endpoints)
		if err != nil {
			return err
		}
		a.Printf("%s\n", result)
		return nil
	case opts.removeAll:
		assumeYes := a.AssumeYes || opts.yes
		ok, err := commandLineConfirm("Remove ALL from endpoint allow-list?", assumeYes)
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Endpoint allow-list removal cancelled.\n")
			return nil
		}
		result, err := removeAllEndpointAllowListEntries(ctx, a)
		if err != nil {
			return err
		}
		a.Printf("%s\n", result)
		return nil
	default:
		return fmt.Errorf("--endpoint-allow-list requires exactly one of --add SOURCE, --remove SOURCE, or --remove-all")
	}
}

func addBasicAllowListSourceInteractive(ctx context.Context, a *App) error {
	if !haproxyListenerComplete(a.Config) {
		return fmt.Errorf("listener must be configured before using the basic allow-list")
	}
	source, err := promptBasicAllowListSource()
	if err != nil {
		return err
	}
	result, err := addBasicAllowListSource(ctx, a, source)
	if err != nil {
		return err
	}
	a.Printf("%s\n", result)
	a.Printf("Allow-list file: %s\n", defaultBasicAllowListFile)
	return nil
}

func promptBasicAllowListSource() (string, error) {
	for {
		value, err := promptValue("Allowed IPv4 address or CIDR block", "", true)
		if err != nil {
			return "", err
		}
		source, err := normalizeBasicAllowListSource(value)
		if err == nil {
			return source, nil
		}
		fmt.Fprintf(os.Stderr, "\n[ERROR] %s\n\n", sentenceCaseError(err.Error()))
	}
}

func addBasicAllowListSource(ctx context.Context, a *App, source string) (string, error) {
	source, err := normalizeBasicAllowListSource(source)
	if err != nil {
		return "", err
	}
	if err := ensureBasicAllowListStore(); err != nil {
		return "", err
	}
	sources, err := loadBasicAllowListSources(defaultBasicAllowListFile)
	if err != nil {
		return "", err
	}
	updated, added, covered := addBasicAllowListSourceToSet(sources, source)
	if covered {
		if err := applyBasicAllowList(ctx, a, updated); err != nil {
			return "", err
		}
		return fmt.Sprintf("[NOTICE] %s is already covered by the current basic allow-list.", source), nil
	}
	if err := writeBasicAllowListSources(defaultBasicAllowListFile, updated); err != nil {
		return "", err
	}
	if err := applyBasicAllowList(ctx, a, updated); err != nil {
		return "", err
	}
	if a.LogFile != nil && added {
		fmt.Fprintf(a.LogFile, "%s ACTION=ALLOWLIST_BASIC_ADD SOURCE=%s FILE=%s\n", logTimestamp(), source, defaultBasicAllowListFile)
	}
	return fmt.Sprintf("[OK] Added %s to the basic allow-list.", source), nil
}

type basicAllowListCLIOptions struct {
	add       string
	remove    string
	removeAll bool
	yes       bool
}

func parseBasicAllowListArgs(args []string) (basicAllowListCLIOptions, error) {
	var opts basicAllowListCLIOptions
	value := func(i *int, arg string) (string, error) {
		if before, after, ok := strings.Cut(arg, "="); ok {
			_ = before
			return after, nil
		}
		*i = *i + 1
		if *i >= len(args) {
			return "", fmt.Errorf("missing value for %s", arg)
		}
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--add":
			v, err := value(&i, arg)
			if err != nil {
				return opts, err
			}
			opts.add = v
		case strings.HasPrefix(arg, "--add="):
			opts.add, _ = value(&i, arg)
		case arg == "--remove":
			v, err := value(&i, arg)
			if err != nil {
				return opts, err
			}
			opts.remove = v
		case strings.HasPrefix(arg, "--remove="):
			opts.remove, _ = value(&i, arg)
		case arg == "--remove-all":
			opts.removeAll = true
		case arg == "--yes" || arg == "-y":
			opts.yes = true
		default:
			return opts, fmt.Errorf("unknown option for --basic-allow-list: %s", arg)
		}
	}
	actions := 0
	if strings.TrimSpace(opts.add) != "" {
		actions++
	}
	if strings.TrimSpace(opts.remove) != "" {
		actions++
	}
	if opts.removeAll {
		actions++
	}
	if actions != 1 {
		return opts, fmt.Errorf("--basic-allow-list requires exactly one of --add SOURCE, --remove SOURCE, or --remove-all")
	}
	return opts, nil
}

func basicAllowListCLI(ctx context.Context, a *App, args []string) error {
	opts, err := parseBasicAllowListArgs(args)
	if err != nil {
		return err
	}
	if !haproxyListenerComplete(a.Config) {
		return fmt.Errorf("listener must be configured before using the basic allow-list")
	}
	switch {
	case strings.TrimSpace(opts.add) != "":
		result, err := addBasicAllowListSource(ctx, a, opts.add)
		if err != nil {
			return err
		}
		a.Printf("%s\n", result)
		a.Printf("Allow-list file: %s\n", defaultBasicAllowListFile)
		return nil
	case strings.TrimSpace(opts.remove) != "":
		source, err := normalizeBasicAllowListSource(opts.remove)
		if err != nil {
			return err
		}
		assumeYes := a.AssumeYes || opts.yes
		ok, err := commandLineConfirm(fmt.Sprintf("Remove %s from allow-list?", source), assumeYes)
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Basic allow-list removal cancelled.\n")
			return nil
		}
		result, err := removeBasicAllowListSource(ctx, a, source)
		if err != nil {
			return err
		}
		a.Printf("%s\n", result)
		return nil
	case opts.removeAll:
		assumeYes := a.AssumeYes || opts.yes
		ok, err := commandLineConfirm("Remove ALL from allow-list?", assumeYes)
		if err != nil {
			return err
		}
		if !ok {
			a.Printf("[NOTICE] Basic allow-list removal cancelled.\n")
			return nil
		}
		result, err := removeAllBasicAllowListSources(ctx, a)
		if err != nil {
			return err
		}
		a.Printf("%s\n", result)
		return nil
	default:
		return fmt.Errorf("--basic-allow-list requires exactly one of --add SOURCE, --remove SOURCE, or --remove-all")
	}
}

func viewRemoveBasicAllowListSources(ctx context.Context, a *App) error {
	for {
		if err := ensureBasicAllowListStore(); err != nil {
			return err
		}
		sources, err := loadBasicAllowListSources(defaultBasicAllowListFile)
		if err != nil {
			return err
		}
		if len(sources) == 0 {
			actionPage("[proxyble] Allow-list -> Basic -> View / Remove", "No sources are currently on the basic allow-list.\nDefault-deny access to the listening port is not active.")
			pause()
			return nil
		}
		choice, err := choiceMenu("[proxyble] Allow-list -> Basic -> View / Remove", "Select a source to remove from the basic allow-list.", basicAllowListSourceMenuItems(sources), "")
		if err != nil {
			return err
		}
		switch choice {
		case "back", "exit":
			return nil
		case "remove-all":
			ok, err := confirmBasicAllowListRemoval("ALL")
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			_, err = removeAllBasicAllowListSources(ctx, a)
			if err != nil {
				return err
			}
			actionPage("[proxyble] Allow-list -> Basic -> View / Remove", "All basic allow-list sources were removed.\nDefault-deny access to the listening port is no longer active.")
			pause()
			return nil
		default:
			ok, err := confirmBasicAllowListRemoval(choice)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if _, err := removeBasicAllowListSource(ctx, a, choice); err != nil {
				return err
			}
		}
	}
}

func removeBasicAllowListSource(ctx context.Context, a *App, source string) (string, error) {
	source, err := normalizeBasicAllowListSource(source)
	if err != nil {
		return "", err
	}
	if err := ensureBasicAllowListStore(); err != nil {
		return "", err
	}
	sources, err := loadBasicAllowListSources(defaultBasicAllowListFile)
	if err != nil {
		return "", err
	}
	updated := removeBasicAllowListSourceFromSet(sources, source)
	if len(updated) == len(sources) {
		return "", fmt.Errorf("source is not on the basic allow-list: %s", source)
	}
	if err := writeBasicAllowListSources(defaultBasicAllowListFile, updated); err != nil {
		return "", err
	}
	if err := applyBasicAllowList(ctx, a, updated); err != nil {
		return "", err
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=ALLOWLIST_BASIC_REMOVE SOURCE=%s FILE=%s\n", logTimestamp(), source, defaultBasicAllowListFile)
	}
	return fmt.Sprintf("[OK] Removed %s from the basic allow-list.", source), nil
}

func removeAllBasicAllowListSources(ctx context.Context, a *App) (string, error) {
	if err := ensureBasicAllowListStore(); err != nil {
		return "", err
	}
	if err := writeBasicAllowListSources(defaultBasicAllowListFile, nil); err != nil {
		return "", err
	}
	if err := applyBasicAllowList(ctx, a, nil); err != nil {
		return "", err
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=ALLOWLIST_BASIC_REMOVE_ALL FILE=%s\n", logTimestamp(), defaultBasicAllowListFile)
	}
	return "[OK] Removed all sources from the basic allow-list. Default-deny access is no longer active.", nil
}

func confirmBasicAllowListRemoval(source string) (bool, error) {
	choice, err := choiceMenu("[proxyble] Allow-list -> Basic -> Remove", basicAllowListRemovalPrompt(source), basicAllowListRemovalConfirmItems(source), "yes")
	if err != nil {
		return false, err
	}
	switch choice {
	case "yes":
		return true, nil
	case "cancel", "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown allow-list removal confirmation selection: %s", choice)
	}
}

func basicAllowListRemovalPrompt(source string) string {
	if source == "ALL" {
		return "Confirm removing every source from the basic allow-list."
	}
	return fmt.Sprintf("Confirm removing %s from the basic allow-list.", source)
}

func basicAllowListRemovalConfirmItems(source string) [][2]string {
	target := source
	if source == "ALL" {
		target = "ALL"
	}
	return [][2]string{
		{"yes|Yes", fmt.Sprintf("Remove %s from allow-list.", target)},
		{"back", "Return to previous menu"},
	}
}

func basicAllowListSourceMenuItems(sources []string) [][2]string {
	items := make([][2]string, 0, len(sources)+2)
	for _, source := range sources {
		items = append(items, [2]string{source, "Remove this source from the basic allow-list"})
	}
	items = append(items,
		[2]string{"remove-all", "Remove all sources and disable default-deny for the listening port"},
		[2]string{"back", "Return to previous menu"},
	)
	return items
}

type endpointAllowListEntry struct {
	Source   string
	Endpoint string
}

type endpointAllowListGroup struct {
	Endpoint string
	Sources  []string
}

func viewRemoveEndpointAllowListEntries(ctx context.Context, a *App) error {
	for {
		if err := ensureEndpointAllowListStore(); err != nil {
			return err
		}
		entries, err := loadEndpointAllowListEntries(endpointAllowListFile)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			actionPage("[proxyble] Allow-list -> Endpoint -> View / Remove", "No sources are currently on the endpoint allow-list.\nDefault-deny access to endpoints is not active.")
			pause()
			return nil
		}
		choice, err := choiceMenu("[proxyble] Allow-list -> Endpoint -> View / Remove", "Select a source and endpoint to remove from the endpoint allow-list.", endpointAllowListEntryMenuItems(entries), "")
		if err != nil {
			return err
		}
		switch choice {
		case "back", "exit":
			return nil
		case "remove-all":
			ok, err := confirmEndpointAllowListRemoval("ALL")
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			_, err = removeAllEndpointAllowListEntries(ctx, a)
			if err != nil {
				return err
			}
			actionPage("[proxyble] Allow-list -> Endpoint -> View / Remove", "All endpoint allow-list sources were removed.\nDefault-deny access to endpoints is no longer active.")
			pause()
			return nil
		default:
			entry, err := endpointAllowListEntryForChoice(entries, choice)
			if err != nil {
				return err
			}
			ok, err := confirmEndpointAllowListRemoval(endpointAllowListEntryLabel(entry))
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if _, err := removeEndpointAllowListEntries(ctx, a, entry.Source, []string{entry.Endpoint}); err != nil {
				return err
			}
		}
	}
}

func removeEndpointAllowListEntries(ctx context.Context, a *App, source string, endpoints []string) (string, error) {
	source, err := normalizeBasicAllowListSource(source)
	if err != nil {
		return "", err
	}
	endpoints, err = normalizeEndpointAllowListEndpoints(endpoints)
	if err != nil {
		return "", err
	}
	if err := requireEndpointAllowListRuntime(a.Config); err != nil {
		return "", err
	}
	if err := ensureEndpointAllowListStore(); err != nil {
		return "", err
	}
	entries, err := loadEndpointAllowListEntries(endpointAllowListFile)
	if err != nil {
		return "", err
	}
	updated, removed := removeEndpointAllowListEntriesFromSet(entries, source, endpoints)
	if removed == 0 {
		return "", fmt.Errorf("source and endpoint selection is not on the endpoint allow-list: %s %s", source, strings.Join(endpoints, ","))
	}
	if err := writeEndpointAllowListEntries(endpointAllowListFile, updated); err != nil {
		return "", err
	}
	if err := applyEndpointAllowList(ctx, a); err != nil {
		return "", err
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=ALLOWLIST_ENDPOINT_REMOVE SOURCE=%s ENDPOINTS=%s FILE=%s\n", logTimestamp(), source, strings.Join(endpoints, ","), endpointAllowListFile)
	}
	return fmt.Sprintf("[OK] Removed %d endpoint allow-list %s.", removed, plural(removed, "entry", "entries")), nil
}

func removeAllEndpointAllowListEntries(ctx context.Context, a *App) (string, error) {
	if err := requireEndpointAllowListRuntime(a.Config); err != nil {
		return "", err
	}
	if err := ensureEndpointAllowListStore(); err != nil {
		return "", err
	}
	if err := writeEndpointAllowListEntries(endpointAllowListFile, nil); err != nil {
		return "", err
	}
	if err := applyEndpointAllowList(ctx, a); err != nil {
		return "", err
	}
	if a.LogFile != nil {
		fmt.Fprintf(a.LogFile, "%s ACTION=ALLOWLIST_ENDPOINT_REMOVE_ALL FILE=%s\n", logTimestamp(), endpointAllowListFile)
	}
	return "[OK] Removed all sources from the endpoint allow-list. Default-deny access to endpoints is no longer active.", nil
}

func confirmEndpointAllowListRemoval(target string) (bool, error) {
	choice, err := choiceMenu("[proxyble] Allow-list -> Endpoint -> Remove", endpointAllowListRemovalPrompt(target), endpointAllowListRemovalConfirmItems(target), "yes")
	if err != nil {
		return false, err
	}
	switch choice {
	case "yes":
		return true, nil
	case "cancel", "back", "exit":
		return false, nil
	default:
		return false, fmt.Errorf("unknown endpoint allow-list removal confirmation selection: %s", choice)
	}
}

func endpointAllowListRemovalPrompt(target string) string {
	if target == "ALL" {
		return "Confirm removing every source from the endpoint allow-list."
	}
	return fmt.Sprintf("Confirm removing %s from the endpoint allow-list.", target)
}

func endpointAllowListRemovalConfirmItems(target string) [][2]string {
	if target == "" {
		target = "source"
	}
	return [][2]string{
		{"yes|Yes", fmt.Sprintf("Remove %s from allow-list.", target)},
		{"back", "Return to previous menu"},
	}
}

func endpointAllowListEntryMenuItems(entries []endpointAllowListEntry) [][2]string {
	items := make([][2]string, 0, len(entries)+2)
	for i, entry := range entries {
		items = append(items, [2]string{
			fmt.Sprintf("entry-%d|%s", i, entry.Source),
			fmt.Sprintf("Remove endpoint %s from this source", entry.Endpoint),
		})
	}
	items = append(items,
		[2]string{"remove-all", "Remove all sources and disable default-deny for endpoints"},
		[2]string{"back", "Return to previous menu"},
	)
	return items
}

func endpointAllowListEntryForChoice(entries []endpointAllowListEntry, choice string) (endpointAllowListEntry, error) {
	if !strings.HasPrefix(choice, "entry-") {
		return endpointAllowListEntry{}, fmt.Errorf("unknown endpoint allow-list selection: %s", choice)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(choice, "entry-"))
	if err != nil || n < 0 || n >= len(entries) {
		return endpointAllowListEntry{}, fmt.Errorf("unknown endpoint allow-list selection: %s", choice)
	}
	return entries[n], nil
}

func endpointAllowListEntryLabel(entry endpointAllowListEntry) string {
	return fmt.Sprintf("%s %s", entry.Source, entry.Endpoint)
}

func ensureEndpointAllowListStore() error {
	if err := mkdirOwned(filepath.Dir(endpointAllowListFile), 0o700, "root", "root"); err != nil {
		return err
	}
	if err := touchFile(endpointAllowListFile, 0o600); err != nil {
		return err
	}
	_ = chownPath(endpointAllowListFile, "root", "root")
	return chmodPath(endpointAllowListFile, 0o600)
}

func loadEndpointAllowListEntries(path string) ([]endpointAllowListEntry, error) {
	f, err := openFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var entries []endpointAllowListEntry
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s line %d: expected SOURCE ENDPOINT", path, lineNo)
		}
		source, err := normalizeBasicAllowListSource(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, lineNo, err)
		}
		endpoint, err := normalizeEndpointAllowListEndpoint(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, lineNo, err)
		}
		entries, _, _ = addEndpointAllowListEntriesToSet(entries, source, []string{endpoint})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func writeEndpointAllowListEntries(path string, entries []endpointAllowListEntry) error {
	var buf bytes.Buffer
	for _, entry := range entries {
		source, err := normalizeBasicAllowListSource(entry.Source)
		if err != nil {
			return err
		}
		endpoint, err := normalizeEndpointAllowListEndpoint(entry.Endpoint)
		if err != nil {
			return err
		}
		buf.WriteString(source)
		buf.WriteByte(' ')
		buf.WriteString(endpoint)
		buf.WriteByte('\n')
	}
	if err := atomicWriteFile(path, buf.Bytes(), 0o600); err != nil {
		return err
	}
	_ = chownPath(path, "root", "root")
	return chmodPath(path, 0o600)
}

func normalizeEndpointAllowListEndpoints(endpoints []string) ([]string, error) {
	seen := map[string]bool{}
	normalized := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		value, err := normalizeEndpointAllowListEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("enter at least one endpoint path, such as /login or /api/v1")
	}
	return normalized, nil
}

func normalizeEndpointAllowListEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("enter an endpoint path, such as /login or /api/v1")
	}
	if !strings.HasPrefix(endpoint, "/") {
		return "", fmt.Errorf("endpoint paths must start with /, such as /login or /api/v1")
	}
	if strings.ContainsAny(endpoint, " \t\r\n?#\\\"") {
		return "", fmt.Errorf("endpoint paths must not contain whitespace, query strings, fragments, quotes, or backslashes")
	}
	for _, r := range endpoint {
		if r < 33 || r > 126 {
			return "", fmt.Errorf("endpoint paths must use printable ASCII characters")
		}
	}
	return endpoint, nil
}

func addEndpointAllowListEntriesToSet(entries []endpointAllowListEntry, source string, endpoints []string) (updated []endpointAllowListEntry, added int, covered int) {
	updated = append([]endpointAllowListEntry(nil), entries...)
	for _, endpoint := range endpoints {
		next, wasAdded, wasCovered := addEndpointAllowListEntryToSet(updated, source, endpoint)
		updated = next
		if wasAdded {
			added++
		}
		if wasCovered {
			covered++
		}
	}
	return updated, added, covered
}

func addEndpointAllowListEntryToSet(entries []endpointAllowListEntry, source, endpoint string) (updated []endpointAllowListEntry, added bool, covered bool) {
	source, err := normalizeBasicAllowListSource(source)
	if err != nil {
		return append([]endpointAllowListEntry(nil), entries...), false, false
	}
	endpoint, err = normalizeEndpointAllowListEndpoint(endpoint)
	if err != nil {
		return append([]endpointAllowListEntry(nil), entries...), false, false
	}
	newPrefix, err := basicAllowListPrefix(source)
	if err != nil {
		return append([]endpointAllowListEntry(nil), entries...), false, false
	}
	updated = make([]endpointAllowListEntry, 0, len(entries)+1)
	for _, existing := range entries {
		if existing.Endpoint != endpoint {
			updated = append(updated, existing)
			continue
		}
		existingPrefix, err := basicAllowListPrefix(existing.Source)
		if err != nil {
			continue
		}
		if basicAllowListPrefixContains(existingPrefix, newPrefix) {
			return append([]endpointAllowListEntry(nil), entries...), false, true
		}
		if basicAllowListPrefixContains(newPrefix, existingPrefix) {
			added = true
			continue
		}
		updated = append(updated, endpointAllowListEntry{Source: prefixToBasicAllowListSource(existingPrefix), Endpoint: endpoint})
	}
	updated = append(updated, endpointAllowListEntry{Source: prefixToBasicAllowListSource(newPrefix), Endpoint: endpoint})
	return updated, true, false
}

func removeEndpointAllowListEntriesFromSet(entries []endpointAllowListEntry, source string, endpoints []string) (updated []endpointAllowListEntry, removed int) {
	endpointSet := map[string]bool{}
	for _, endpoint := range endpoints {
		endpointSet[endpoint] = true
	}
	updated = make([]endpointAllowListEntry, 0, len(entries))
	for _, existing := range entries {
		if existing.Source == source && endpointSet[existing.Endpoint] {
			removed++
			continue
		}
		updated = append(updated, existing)
	}
	return updated, removed
}

func endpointAllowListAddMessage(added, covered int) string {
	switch {
	case added > 0 && covered > 0:
		return fmt.Sprintf("[OK] Added %d endpoint allow-list %s. %d requested %s already covered.", added, plural(added, "entry", "entries"), covered, plural(covered, "entry was", "entries were"))
	case added > 0:
		return fmt.Sprintf("[OK] Added %d endpoint allow-list %s.", added, plural(added, "entry", "entries"))
	default:
		return "[NOTICE] The requested source and endpoint selection is already covered by the endpoint allow-list."
	}
}

func endpointAllowListGroups(entries []endpointAllowListEntry) []endpointAllowListGroup {
	index := map[string]int{}
	groups := []endpointAllowListGroup{}
	for _, entry := range entries {
		endpoint, err := normalizeEndpointAllowListEndpoint(entry.Endpoint)
		if err != nil {
			continue
		}
		source, err := normalizeBasicAllowListSource(entry.Source)
		if err != nil {
			continue
		}
		i, ok := index[endpoint]
		if !ok {
			index[endpoint] = len(groups)
			groups = append(groups, endpointAllowListGroup{Endpoint: endpoint})
			i = len(groups) - 1
		}
		if !contains(groups[i].Sources, source) {
			groups[i].Sources = append(groups[i].Sources, source)
		}
	}
	return groups
}

func buildEndpointAllowListHAProxyRules(entries []endpointAllowListEntry) string {
	groups := endpointAllowListGroups(entries)
	if len(groups) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("    # Proxyble endpoint allow-list\n")
	for i, group := range groups {
		name := fmt.Sprintf("proxyble_endpoint_allow_%03d", i+1)
		fmt.Fprintf(&b, "    acl %s path_beg -i %s\n", name, group.Endpoint)
		fmt.Fprintf(&b, "    acl %s_src src %s\n", name, strings.Join(group.Sources, " "))
		fmt.Fprintf(&b, "    http-request set-var(txn.proxyble_endpoint_allow_active) str(1) if %s\n", name)
		fmt.Fprintf(&b, "    http-request set-var(txn.proxyble_endpoint_allow_source) str(1) if %s %s_src\n", name, name)
	}
	b.WriteString("    http-request deny deny_status 403 if { var(txn.proxyble_endpoint_allow_active) -m str 1 } !{ var(txn.proxyble_endpoint_allow_source) -m str 1 }\n\n")
	return b.String()
}

func applyEndpointAllowList(ctx context.Context, a *App) error {
	if err := requireEndpointAllowListRuntime(a.Config); err != nil {
		return err
	}
	return withHAProxyCoordinationLock(func() error {
		if err := renderHAProxyConfigLocked(ctx, a); err != nil {
			return err
		}
		return reloadHAProxyForEndpointAllowList(ctx, a)
	})
}

func reloadHAProxyForEndpointAllowList(ctx context.Context, a *App) error {
	out := stepOutput(a)
	if !systemctlQuiet(ctx, "is-active", "--quiet", "haproxy") {
		fmt.Fprintln(out, "[NOTICE] HAProxy is not active; endpoint allow-list config will apply when HAProxy starts.")
		return nil
	}
	if err := timeoutCommand(ctx, out, 10, "systemctl", "reload", "haproxy"); err != nil {
		fmt.Fprintln(out, "[NOTICE] HAProxy reload failed; attempting restart.")
		if restartErr := timeoutCommand(ctx, out, 10, "systemctl", "restart", "haproxy"); restartErr != nil {
			return fmt.Errorf("failed to reload HAProxy for endpoint allow-list: reload failed: %v; restart failed: %w", err, restartErr)
		}
	}
	fmt.Fprintln(out, "[OK] HAProxy reloaded for endpoint allow-list.")
	return nil
}

func requireEndpointAllowListRuntime(c *Config) error {
	if !haproxyListenerComplete(c) {
		return fmt.Errorf("listener must be configured before using the endpoint allow-list")
	}
	mode, err := c.TrafficMode()
	if err != nil {
		return err
	}
	if mode != "http" && mode != "https" {
		return fmt.Errorf("endpoint allow-list is only available in HTTP and HTTPS modes")
	}
	if !haproxyBackendComplete(c) {
		return fmt.Errorf("backend must be configured before applying the endpoint allow-list")
	}
	return nil
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

func ensureBasicAllowListStore() error {
	if err := mkdirOwned(defaultAllowListDir, 0o700, "root", "root"); err != nil {
		return err
	}
	if err := touchFile(defaultBasicAllowListFile, 0o600); err != nil {
		return err
	}
	_ = chownPath(defaultBasicAllowListFile, "root", "root")
	if err := chmodPath(defaultBasicAllowListFile, 0o600); err != nil {
		return err
	}
	if err := touchFile(defaultBasicAllowListNFTFile, 0o600); err != nil {
		return err
	}
	_ = chownPath(defaultBasicAllowListNFTFile, "root", "root")
	return chmodPath(defaultBasicAllowListNFTFile, 0o600)
}

func loadBasicAllowListSources(path string) ([]string, error) {
	f, err := openFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var sources []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		source, err := normalizeBasicAllowListSource(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, lineNo, err)
		}
		sources, _, _ = addBasicAllowListSourceToSet(sources, source)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sources, nil
}

func writeBasicAllowListSources(path string, sources []string) error {
	var buf bytes.Buffer
	for _, source := range sources {
		normalized, err := normalizeBasicAllowListSource(source)
		if err != nil {
			return err
		}
		buf.WriteString(normalized)
		buf.WriteByte('\n')
	}
	if err := atomicWriteFile(path, buf.Bytes(), 0o600); err != nil {
		return err
	}
	_ = chownPath(path, "root", "root")
	return chmodPath(path, 0o600)
}

func normalizeBasicAllowListSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	if source == "" || strings.ContainsAny(source, " \t\r\n") {
		return "", fmt.Errorf("enter one IPv4 address or CIDR block with no spaces")
	}
	if strings.Contains(source, "/") {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || !prefix.Addr().Is4() {
			return "", fmt.Errorf("enter a valid IPv4 address or CIDR block, such as 203.0.113.25 or 203.0.113.0/24")
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return "", fmt.Errorf("0.0.0.0/0 is not allowed; use remove all to disable default-deny")
		}
		return prefix.String(), nil
	}
	addr, err := netip.ParseAddr(source)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("enter a valid IPv4 address or CIDR block, such as 203.0.113.25 or 203.0.113.0/24")
	}
	return addr.String(), nil
}

func addBasicAllowListSourceToSet(sources []string, source string) (updated []string, added bool, covered bool) {
	newPrefix, err := basicAllowListPrefix(source)
	if err != nil {
		return append([]string(nil), sources...), false, false
	}
	updated = make([]string, 0, len(sources)+1)
	for _, existing := range sources {
		existingPrefix, err := basicAllowListPrefix(existing)
		if err != nil {
			continue
		}
		if basicAllowListPrefixContains(existingPrefix, newPrefix) {
			return append([]string(nil), sources...), false, true
		}
		if basicAllowListPrefixContains(newPrefix, existingPrefix) {
			added = true
			continue
		}
		updated = append(updated, prefixToBasicAllowListSource(existingPrefix))
	}
	updated = append(updated, prefixToBasicAllowListSource(newPrefix))
	return updated, true, false
}

func removeBasicAllowListSourceFromSet(sources []string, source string) []string {
	updated := make([]string, 0, len(sources))
	for _, existing := range sources {
		if existing != source {
			updated = append(updated, existing)
		}
	}
	return updated
}

func basicAllowListPrefix(source string) (netip.Prefix, error) {
	source, err := normalizeBasicAllowListSource(source)
	if err != nil {
		return netip.Prefix{}, err
	}
	if strings.Contains(source, "/") {
		return netip.ParsePrefix(source)
	}
	addr, err := netip.ParseAddr(source)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, 32), nil
}

func basicAllowListPrefixContains(container, contained netip.Prefix) bool {
	return container.Addr().Is4() &&
		contained.Addr().Is4() &&
		container.Bits() <= contained.Bits() &&
		container.Contains(contained.Addr())
}

func prefixToBasicAllowListSource(prefix netip.Prefix) string {
	prefix = prefix.Masked()
	if prefix.Bits() == 32 {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func applyBasicAllowList(ctx context.Context, a *App, sources []string) error {
	return applyBasicAllowListForConfig(ctx, stepOutput(a), a.Config, sources)
}

func applyBasicAllowListForConfig(ctx context.Context, out io.Writer, c *Config, sources []string) error {
	return withNFTablesCoordinationLock(func() error {
		return applyBasicAllowListForConfigLocked(ctx, out, c, sources)
	})
}

func applyBasicAllowListForConfigLocked(ctx context.Context, out io.Writer, c *Config, sources []string) error {
	if len(sources) == 0 {
		return deleteBasicAllowListNFTTable(ctx, out)
	}
	batch, err := buildBasicAllowListNFTBatch(c, sources, true)
	if err != nil {
		return err
	}
	if err := applyAllowListNFTBatch(ctx, out, batch); err != nil {
		if !nftErrorIsMissing(err) {
			return err
		}
		batch, err = buildBasicAllowListNFTBatch(c, sources, false)
		if err != nil {
			return err
		}
		return applyAllowListNFTBatch(ctx, out, batch)
	}
	return nil
}

func buildBasicAllowListNFTBatch(c *Config, sources []string, deleteExistingTable bool) (string, error) {
	port, err := basicAllowListListenerPort(c)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if deleteExistingTable {
		sb.WriteString(fmt.Sprintf("delete table %s %s\n", basicAllowListNFTFamily, basicAllowListNFTTable))
	}
	sb.WriteString(fmt.Sprintf("add table %s %s\n", basicAllowListNFTFamily, basicAllowListNFTTable))
	sb.WriteString(fmt.Sprintf("add set %s %s %s { type ipv4_addr; flags interval; }\n", basicAllowListNFTFamily, basicAllowListNFTTable, basicAllowListNFTSet))
	sb.WriteString(fmt.Sprintf("add element %s %s %s { %s }\n", basicAllowListNFTFamily, basicAllowListNFTTable, basicAllowListNFTSet, strings.Join(sources, ", ")))
	sb.WriteString(fmt.Sprintf("add chain %s %s %s { type filter hook input priority -10; policy accept; }\n", basicAllowListNFTFamily, basicAllowListNFTTable, basicAllowListNFTChain))
	sb.WriteString(fmt.Sprintf("add rule %s %s %s tcp dport %s ip saddr @%s accept\n", basicAllowListNFTFamily, basicAllowListNFTTable, basicAllowListNFTChain, port, basicAllowListNFTSet))
	sb.WriteString(fmt.Sprintf("add rule %s %s %s tcp dport %s reject with tcp reset\n", basicAllowListNFTFamily, basicAllowListNFTTable, basicAllowListNFTChain, port))
	return sb.String(), nil
}

func basicAllowListListenerPort(c *Config) (string, error) {
	if !haproxyListenerComplete(c) {
		return "", fmt.Errorf("listener must be configured before applying the basic allow-list")
	}
	port := c.Get("haproxy", "listener_port", "")
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid listener port: %s", port)
	}
	return port, nil
}

func deleteBasicAllowListNFTTable(ctx context.Context, out io.Writer) error {
	batch := fmt.Sprintf("delete table %s %s\n", basicAllowListNFTFamily, basicAllowListNFTTable)
	if err := writeBasicAllowListNFTBatch(batch); err != nil {
		return err
	}
	err := runAllowListNFTCommand(ctx, out, "-f", defaultBasicAllowListNFTFile)
	if err != nil && !nftErrorIsMissing(err) {
		return err
	}
	return nil
}

func applyAllowListNFTBatch(ctx context.Context, out io.Writer, batch string) error {
	if err := writeBasicAllowListNFTBatch(batch); err != nil {
		return err
	}
	return runAllowListNFTCommand(ctx, out, "-f", defaultBasicAllowListNFTFile)
}

func writeBasicAllowListNFTBatch(batch string) error {
	if err := atomicWriteFile(defaultBasicAllowListNFTFile, []byte(batch), 0o600); err != nil {
		return err
	}
	_ = chownPath(defaultBasicAllowListNFTFile, "root", "root")
	return chmodPath(defaultBasicAllowListNFTFile, 0o600)
}

func runAllowListNFTCommand(ctx context.Context, out io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "nft", args...)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if buf.Len() > 0 {
		fmt.Fprint(out, buf.String())
	}
	if err != nil {
		return fmt.Errorf("nft %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(buf.String()))
	}
	return nil
}

func nftErrorIsMissing(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "no such file") ||
		strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "no such table")
}

func applyBasicAllowListFromDisk(ctx context.Context, out io.Writer, c *Config) error {
	return withNFTablesCoordinationLock(func() error {
		return applyBasicAllowListFromDiskLocked(ctx, out, c)
	})
}

func applyBasicAllowListFromDiskLocked(ctx context.Context, out io.Writer, c *Config) error {
	sources, err := loadBasicAllowListSources(defaultBasicAllowListFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return applyBasicAllowListForConfigLocked(ctx, out, c, sources)
}

#!/usr/bin/env bash
# Proxyble protects APIs, web applications, and TCP services.
# Copyright (C) 2026 Lucio D'Orazio Pedro de Matos
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LIBEXEC_DIR="$SCRIPT_DIR/../libexec"

if [[ -f "$LIBEXEC_DIR/lib/printhr.sh" ]]; then
    # shellcheck disable=SC1091
    source "$LIBEXEC_DIR/lib/printhr.sh"
fi

if [[ -f "$LIBEXEC_DIR/lib/common.sh" ]]; then
    # shellcheck disable=SC1091
    source "$LIBEXEC_DIR/lib/common.sh"
fi

if [[ -f "$LIBEXEC_DIR/lib/config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$LIBEXEC_DIR/lib/config.sh"
fi

if ! declare -f proxyble_print_hr >/dev/null 2>&1; then
    proxyble_print_hr() {
        local width="${1:-79}"
        printf '%*s\n' "$width" '' | tr ' ' '-'
    }
fi

usage() {
    cat <<'EOF'
Usage:
  sudo ./test-policy-rule.sh [--wait SECONDS] "RULE"
  sudo ./test-policy-rule.sh [--wait SECONDS] [-a|--all]
  sudo ./test-policy-rule.sh [-h|--help]
  sudo ./test-policy-rule.sh

Examples:
  sudo ./test-policy-rule.sh "drop 192.0.81.141"
  sudo ./test-policy-rule.sh "limit_concurrent 192.0.142.1 55 30s"
  sudo ./test-policy-rule.sh --wait 5 "timeout 192.0.132.87 5s 30s"
  sudo ./test-policy-rule.sh "limit_endpoint_rate 192.0.2.50 10/second /login,/api/export 5m"
  sudo ./test-policy-rule.sh --wait 3 -a

The script appends the rule to /var/spool/proxyble/rules/inbox.tmp, waits, then checks
the live NFTables table or HAProxy runtime maps.

Options:
  -a, --all          Test IP and CIDR variants for supported policy types.
  --wait SECONDS    Wait this many seconds after each rule before verification.
  -h, --help        Show these instructions.
EOF
}

require_root() {
    if declare -f proxyble_require_root >/dev/null 2>&1; then
        proxyble_require_root
        return
    fi

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "[ERROR] Insufficient privileges. Please run as root (use sudo)."
        exit 1
    fi
}

config_get_or_default() {
    local section="$1"
    local key="$2"
    local default_value="$3"

    if declare -f proxyble_config_get_or_default >/dev/null 2>&1 && [[ -f "${PROXYBLE_CONFIG_FILE:-/etc/proxyble/config.ini}" ]]; then
        proxyble_config_get_or_default "$section" "$key" "$default_value"
        return
    fi

    printf '%s\n' "$default_value"
}

lower() {
    printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'
}

duration_to_seconds() {
    local value="$1"
    local number unit

    if [[ "$value" =~ ^([0-9]+)([smhdSMHD])$ ]]; then
        number="${BASH_REMATCH[1]}"
        unit="$(lower "${BASH_REMATCH[2]}")"
        case "$unit" in
            s) printf '%s\n' "$number" ;;
            m) printf '%s\n' "$((number * 60))" ;;
            h) printf '%s\n' "$((number * 3600))" ;;
            d) printf '%s\n' "$((number * 86400))" ;;
        esac
        return 0
    fi

    return 1
}

normalize_ipv4_cidr() {
    local target="$1"
    local ip prefix
    local -a octets=()
    local octet
    local value network_value mask
    local o1 o2 o3 o4

    ip="${target%/*}"
    prefix="${target#*/}"
    if [[ "$ip" == "$target" || ! "$prefix" =~ ^([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        return 1
    fi

    IFS='.' read -r -a octets <<< "$ip"
    if [[ "${#octets[@]}" -ne 4 ]]; then
        return 1
    fi
    for octet in "${octets[@]}"; do
        if [[ ! "$octet" =~ ^[0-9]+$ || "$octet" -gt 255 ]]; then
            return 1
        fi
    done

    value=$(( (10#${octets[0]} << 24) | (10#${octets[1]} << 16) | (10#${octets[2]} << 8) | 10#${octets[3]} ))
    if (( prefix == 0 )); then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi
    network_value=$(( value & mask ))
    o1=$(( (network_value >> 24) & 255 ))
    o2=$(( (network_value >> 16) & 255 ))
    o3=$(( (network_value >> 8) & 255 ))
    o4=$(( network_value & 255 ))
    printf '%s.%s.%s.%s/%s\n' "$o1" "$o2" "$o3" "$o4" "$prefix"
}

normalize_test_target() {
    local action="$1"
    local target="$2"

    if [[ "$action" == "limit_endpoint_rate" ]]; then
        printf '%s\n' "$target"
        return
    fi

    if [[ "$target" == */* ]]; then
        normalize_ipv4_cidr "$target" || printf '%s\n' "$target"
        return
    fi

    printf '%s/32\n' "$target"
}

parse_rule() {
    local -n out_action="$1"
    local -n out_ip="$2"
    local -n out_backend="$3"
    local -n out_param="$4"
    local -n out_expiration="$5"
    local -n out_endpoints="$6"
    shift 6
    local rule="$*"
    local parts=()

    read -r -a parts <<< "$rule"

    if [[ "${#parts[@]}" -lt 2 ]]; then
        echo "[ERROR] Rule must include at least an action and an IP."
        return 1
    fi

    out_action="$(lower "${parts[0]}")"
    out_ip="$(normalize_test_target "$out_action" "${parts[1]}")"
    out_backend=""
    out_param=""
    out_expiration=""
    out_endpoints=""

    case "$out_action" in
        drop|reject|limit_rate_slow|busy_deflection)
            if [[ "${#parts[@]}" -gt 3 ]]; then
                echo "[ERROR] $out_action accepts only an optional expiration."
                return 1
            fi
            [[ "${#parts[@]}" -eq 3 ]] && out_expiration="${parts[2]}"
            ;;
        limit_concurrent|limit_conn_rate|limit_bandwidth|timeout)
            if [[ "${#parts[@]}" -lt 3 || "${#parts[@]}" -gt 4 ]]; then
                echo "[ERROR] $out_action requires a parameter and optional expiration."
                return 1
            fi
            out_param="${parts[2]}"
            [[ "${#parts[@]}" -eq 4 ]] && out_expiration="${parts[3]}"
            ;;
        limit_endpoint_rate)
            if [[ "${#parts[@]}" -lt 4 || "${#parts[@]}" -gt 5 ]]; then
                echo "[ERROR] $out_action requires a rate, comma-separated endpoints, and optional expiration."
                return 1
            fi
            out_param="${parts[2]}"
            out_endpoints="${parts[3]}"
            [[ "${#parts[@]}" -eq 5 ]] && out_expiration="${parts[4]}"
            ;;
        *)
            echo "[ERROR] Unknown action: $out_action"
            return 1
            ;;
    esac

    case "$out_action" in
        drop|reject|limit_concurrent|limit_conn_rate)
            out_backend="nftables"
            ;;
        limit_bandwidth|timeout|limit_rate_slow|busy_deflection|limit_endpoint_rate)
            out_backend="haproxy"
            ;;
    esac
}

endpoint_rate_limit_per_10s() {
    local rate
    local count unit

    rate="$(lower "$1")"
    if [[ ! "$rate" =~ ^([1-9][0-9]*)/(s|sec|second|m|min|minute)$ ]]; then
        return 1
    fi

    count="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    case "$unit" in
        s|sec|second)
            printf '%s\n' "$((count * 10))"
            ;;
        m|min|minute)
            printf '%s\n' "$(((count * 10 + 59) / 60))"
            ;;
    esac
}

append_rule() {
    local inbox="$1"
    local rule="$2"

    mkdir -p "$(dirname -- "$inbox")"
    touch "$inbox"
    printf '%s\n' "$rule" >> "$inbox"
}

maybe_trigger_rule_agent() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[NOTICE] systemctl not found; relying on the installed file watcher or timer."
        return
    fi

    if systemctl is-active --quiet proxyble-rule-agent.path; then
        echo "[INFO] proxyble-rule-agent.path is active; appended rule should trigger processing."
        return
    fi

    echo "[NOTICE] proxyble-rule-agent.path is not active; starting proxyble-rule-agent.service once."
    if ! systemctl start proxyble-rule-agent.service; then
        echo "[WARN] Could not start proxyble-rule-agent.service. Verification may fail."
    fi
}

wait_for_processing() {
    local wait_seconds="$1"

    echo "[INFO] Waiting ${wait_seconds}s before live verification..."
    sleep "$wait_seconds"
}

expect_contains() {
    local haystack="$1"
    local needle="$2"
    local label="$3"

    if grep -Fq -- "$needle" <<< "$haystack"; then
        echo "[PASS] $label"
        return 0
    fi

    echo "[FAIL] $label"
    echo "       Missing: $needle"
    return 1
}

expect_target_contains() {
    local haystack="$1"
    local target="$2"
    local label="$3"
    local singleton="${target%/32}"

    if grep -Fq -- "$target" <<< "$haystack"; then
        echo "[PASS] $label"
        return 0
    fi

    if [[ "$target" == */32 && "$singleton" != "$target" ]] && grep -Fq -- "$singleton" <<< "$haystack"; then
        echo "[PASS] $label"
        return 0
    fi

    echo "[FAIL] $label"
    echo "       Missing: $target"
    return 1
}

verify_nftables() {
    local action="$1"
    local ip="$2"
    local param="$3"
    local output
    local rc=0

    if ! command -v nft >/dev/null 2>&1; then
        echo "[ERROR] nft command not found."
        return 1
    fi

    if ! output="$(nft list table inet pmgr 2>&1)"; then
        echo "[ERROR] Could not read NFTables table inet pmgr:"
        echo "$output"
        return 1
    fi

    case "$action" in
        drop)
            expect_target_contains "$output" "$ip" "NFTables contains source target $ip" || rc=1
            expect_contains "$output" " drop" "NFTables DROP rule is live" || rc=1
            ;;
        reject)
            expect_target_contains "$output" "$ip" "NFTables contains source target $ip" || rc=1
            expect_contains "$output" " reject" "NFTables REJECT rule is live" || rc=1
            ;;
        limit_concurrent)
            if [[ "$ip" == "0.0.0.0/0" ]]; then
                echo "[PASS] NFTables global source scope is represented by direct per-IP metering"
            else
                expect_target_contains "$output" "$ip" "NFTables contains source target $ip" || rc=1
            fi
            expect_contains "$output" "flags dynamic" "NFTables per-IP concurrent counter set exists" || rc=1
            expect_contains "$output" "ip saddr ct count over $param" "NFTables per-IP concurrent-connection limit is live" || rc=1
            ;;
        limit_conn_rate)
            if [[ "$ip" == "0.0.0.0/0" ]]; then
                echo "[PASS] NFTables global source scope is represented by direct per-IP metering"
            else
                expect_target_contains "$output" "$ip" "NFTables contains source target $ip" || rc=1
            fi
            expect_contains "$output" "ct state new" "NFTables connection-rate rule tracks new connections" || rc=1
            expect_contains "$output" "flags dynamic" "NFTables per-IP connection-rate counter set exists" || rc=1
            expect_contains "$output" "ip saddr limit rate over $param" "NFTables per-IP connection-rate limit is live" || rc=1
            ;;
        *)
            echo "[ERROR] $action is not an NFTables action."
            return 1
            ;;
    esac

    return "$rc"
}

haproxy_socket_cmd() {
    local socket_path="$1"
    local command_text="$2"

    if [[ ! -S "$socket_path" ]]; then
        echo "[ERROR] HAProxy runtime socket not found: $socket_path"
        return 1
    fi

    if command -v socat >/dev/null 2>&1; then
        printf '%s\n' "$command_text" | socat -t 3 - "UNIX-CONNECT:$socket_path"
        return
    fi

    if command -v nc >/dev/null 2>&1 && nc -h 2>&1 | grep -q -- '-U'; then
        printf '%s\n' "$command_text" | nc -U -w 3 "$socket_path"
        return
    fi

    if command -v python3 >/dev/null 2>&1; then
        PROXYBLE_HAPROXY_SOCKET="$socket_path" PROXYBLE_HAPROXY_COMMAND="$command_text" python3 -c '
import os
import socket
import sys

socket_path = os.environ["PROXYBLE_HAPROXY_SOCKET"]
command_text = os.environ["PROXYBLE_HAPROXY_COMMAND"] + "\n"

try:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(socket_path)
    client.sendall(command_text.encode("utf-8"))
    client.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        try:
            chunk = client.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    sys.stdout.buffer.write(b"".join(chunks))
except Exception as exc:
    print(f"[ERROR] Python Unix-socket query failed: {exc}", file=sys.stderr)
    sys.exit(1)
'
        return
    fi

    echo "[ERROR] Need socat, nc with Unix-socket support, or python3 to query HAProxy live maps."
    return 1
}

haproxy_show_map() {
    local socket_path="$1"
    local map_path="$2"
    local output
    local map_list
    local map_id

    output="$(haproxy_socket_cmd "$socket_path" "show map $map_path" 2>&1 || true)"
    if ! grep -Eqi 'unknown|no such|not found|invalid|can.?t find|error' <<< "$output"; then
        printf '%s\n' "$output"
        return 0
    fi

    map_list="$(haproxy_socket_cmd "$socket_path" "show map" 2>&1 || true)"
    map_id="$(awk -v map="$map_path" '
        index($0, "(" map ")") {
            gsub(/^#/, "", $1)
            print $1
            exit
        }
    ' <<< "$map_list")"

    if [[ -z "$map_id" ]]; then
        echo "$output"
        echo "$map_list"
        return 1
    fi

    haproxy_socket_cmd "$socket_path" "show map #$map_id"
}

map_has_entry() {
    local output="$1"
    local key="$2"
    local value="$3"

    awk -v key="$key" -v value="$value" '
        ($1 == key && $2 == value) || ($2 == key && $3 == value) { found = 1 }
        END { exit(found ? 0 : 1) }
    ' <<< "$output"
}

verify_haproxy() {
    local action="$1"
    local ip="$2"
    local param="$3"
    local socket_path="$4"
    local rules_map="$5"
    local params_map="$6"
    local endpoint_rates_map="$7"
    local endpoints="$8"
    local expected_code
    local rules_output
    local params_output
    local rc=0

    case "$action" in
        limit_bandwidth) expected_code="BW_LIM" ;;
        timeout) expected_code="T_OUT" ;;
        limit_rate_slow) expected_code="RATE_REJ" ;;
        busy_deflection) expected_code="BUSY" ;;
        limit_endpoint_rate) expected_code="ENDPOINT_RATE" ;;
        *)
            echo "[ERROR] $action is not a HAProxy action."
            return 1
            ;;
    esac

    if ! rules_output="$(haproxy_show_map "$socket_path" "$rules_map")"; then
        echo "[ERROR] Could not read HAProxy rules map."
        echo "$rules_output"
        return 1
    fi

    if map_has_entry "$rules_output" "$ip" "$expected_code"; then
        echo "[PASS] HAProxy rules.map contains $ip -> $expected_code"
    else
        echo "[FAIL] HAProxy rules.map does not contain $ip -> $expected_code"
        rc=1
    fi

    if [[ -n "$param" ]]; then
        if ! params_output="$(haproxy_show_map "$socket_path" "$params_map")"; then
            echo "[ERROR] Could not read HAProxy params map."
            echo "$params_output"
            return 1
        fi

        if map_has_entry "$params_output" "$ip" "$param"; then
            echo "[PASS] HAProxy params.map contains $ip -> $param"
        else
            echo "[FAIL] HAProxy params.map does not contain $ip -> $param"
            rc=1
        fi
    fi

    if [[ "$action" == "limit_endpoint_rate" ]]; then
        local endpoint_limit endpoint_rates_output endpoint key
        local -a endpoint_list

        if ! endpoint_limit="$(endpoint_rate_limit_per_10s "$param")"; then
            echo "[ERROR] Could not normalize endpoint rate $param to the HAProxy 10s window."
            return 1
        fi

        if ! endpoint_rates_output="$(haproxy_show_map "$socket_path" "$endpoint_rates_map")"; then
            echo "[ERROR] Could not read HAProxy endpoint-rates map."
            echo "$endpoint_rates_output"
            return 1
        fi

        IFS=',' read -r -a endpoint_list <<< "$endpoints"
        for endpoint in "${endpoint_list[@]}"; do
            key="${ip}|${endpoint}"
            if map_has_entry "$endpoint_rates_output" "$key" "$endpoint_limit"; then
                echo "[PASS] HAProxy endpoint-rates.map contains $key -> $endpoint_limit"
            else
                echo "[FAIL] HAProxy endpoint-rates.map does not contain $key -> $endpoint_limit"
                rc=1
            fi
        done
    fi

    return "$rc"
}

show_recent_diagnostics() {
    proxyble_print_hr 79
    echo "[INFO] Recent proxyble-rule-agent diagnostics"

    if command -v systemctl >/dev/null 2>&1 && command -v journalctl >/dev/null 2>&1; then
        systemctl --no-pager --full status proxyble-rule-agent.service 2>/dev/null | tail -n 20 || true
        journalctl -u proxyble-rule-agent.service -n 20 --no-pager 2>/dev/null || true
    fi

    local log_dir
    log_dir="$(config_get_or_default rule_agent log_dir "/var/log/proxyble-rule-agent")"
    if [[ -d "$log_dir" ]]; then
        local latest_log
        latest_log="$(find "$log_dir" -maxdepth 1 -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -n 1 | awk '{print $2}')"
        if [[ -n "$latest_log" ]]; then
            echo "[INFO] Tail of $latest_log"
            tail -n 20 "$latest_log" || true
        fi
    fi
}

all_policy_test_rules() {
    cat <<'EOF'
drop 192.0.2.10 5m
drop 198.51.100.0/24 5m
reject 192.0.2.11 5m
reject 198.51.101.0/24 5m
limit_concurrent 192.0.2.12 50 5m
limit_concurrent 198.51.102.0/24 50 5m
limit_conn_rate 192.0.2.13 20/second 5m
limit_conn_rate 198.51.103.0/24 20/second 5m
limit_bandwidth 192.0.2.14 10mb 5m
limit_bandwidth 198.51.104.0/24 10mb 5m
timeout 192.0.2.15 5s 5m
timeout 198.51.105.0/24 5s 5m
limit_rate_slow 192.0.2.16 5m
limit_rate_slow 198.51.106.0/24 5m
busy_deflection 192.0.2.17 5m
busy_deflection 198.51.107.0/24 5m
limit_endpoint_rate 192.0.2.18 10/second /login,/api/export 5m
EOF
}

run_policy_rule_test() {
    local rule="$1"
    local wait_seconds="$2"
    local show_diagnostics="${3:-1}"

    rule="$(sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s/[[:space:]]+/ /g' <<< "$rule")"
    if [[ -z "$rule" ]]; then
        echo "[ERROR] Empty rule."
        return 1
    fi

    local action ip backend param expiration endpoints
    if ! parse_rule action ip backend param expiration endpoints "$rule"; then
        return 1
    fi

    if [[ -n "$expiration" ]]; then
        local expiration_seconds
        if expiration_seconds="$(duration_to_seconds "$expiration")"; then
            if (( expiration_seconds <= wait_seconds )); then
                echo "[WARN] Rule expires in ${expiration_seconds}s but the verification wait is ${wait_seconds}s."
                if (( expiration_seconds <= 1 )); then
                    echo "[ERROR] Expiration is too short for a live verification check."
                    return 1
                fi
                wait_seconds=$((expiration_seconds - 1))
                echo "[INFO] Adjusting verification wait to ${wait_seconds}s so the rule should still be live."
            fi
        fi
    fi

    local inbox socket_path rules_map params_map endpoint_rates_map
    inbox="$(config_get_or_default rule_agent watch_file "/var/spool/proxyble/rules/inbox.tmp")"
    socket_path="$(config_get_or_default haproxy runtime_socket "/run/haproxy/admin.sock")"
    rules_map="$(config_get_or_default haproxy rules_map "/etc/haproxy/maps/rules.map")"
    params_map="$(config_get_or_default haproxy params_map "/etc/haproxy/maps/params.map")"
    endpoint_rates_map="$(config_get_or_default haproxy endpoint_rates_map "/etc/haproxy/maps/endpoint-rates.map")"

    proxyble_print_hr 79
    echo "[INFO] Rule tester"
    echo "[INFO] Rule    : $rule"
    echo "[INFO] Backend : $backend"
    echo "[INFO] Inbox   : $inbox"
    proxyble_print_hr 79

    append_rule "$inbox" "$rule"
    echo "[PASS] Rule appended"

    maybe_trigger_rule_agent
    wait_for_processing "$wait_seconds"

    local rc=0
    case "$backend" in
        nftables)
            verify_nftables "$action" "$ip" "$param" || rc=1
            ;;
        haproxy)
            verify_haproxy "$action" "$ip" "$param" "$socket_path" "$rules_map" "$params_map" "$endpoint_rates_map" "$endpoints" || rc=1
            ;;
    esac

    if [[ "$rc" -eq 0 ]]; then
        proxyble_print_hr 79
        echo "[PASS] Rule is live and matched expected enforcement."
        proxyble_print_hr 79
        return 0
    fi

    proxyble_print_hr 79
    echo "[FAIL] Rule was not verified as live/correct after ${wait_seconds}s."
    proxyble_print_hr 79
    if [[ "$show_diagnostics" == "1" ]]; then
        show_recent_diagnostics
    fi
    return 1
}

run_all_policy_tests() {
    local wait_seconds="$1"
    local rule
    local total=0
    local passed=0
    local failed=0
    local -a failed_rules=()
    local -a test_rules=()

    mapfile -t test_rules < <(all_policy_test_rules)

    proxyble_print_hr 79
    echo "[INFO] Rule test suite"
    echo "[INFO] Rules   : ${#test_rules[@]}"
    echo "[INFO] Wait    : ${wait_seconds}s per rule"
    echo "[INFO] Scope   : IP and CIDR for supported rules; LIMIT_ENDPOINT_RATE is IP-only"
    proxyble_print_hr 79

    for rule in "${test_rules[@]}"; do
        total=$((total + 1))
        echo
        proxyble_print_hr 79
        echo "[INFO] Running policy test ${total}/${#test_rules[@]}: $rule"
        proxyble_print_hr 79
        if run_policy_rule_test "$rule" "$wait_seconds" 0; then
            passed=$((passed + 1))
        else
            failed=$((failed + 1))
            failed_rules+=("$rule")
        fi
    done

    echo
    proxyble_print_hr 79
    echo "[INFO] Rule test summary"
    echo "[INFO] Total  : $total"
    echo "[PASS] Passed : $passed"
    echo "[FAIL] Failed : $failed"

    if (( failed == 0 )); then
        echo "[PASS] All rule tests passed."
        proxyble_print_hr 79
        return 0
    fi

    proxyble_print_hr 79
    echo "[FAIL] Failed rules:"
    for rule in "${failed_rules[@]}"; do
        echo "  - $rule"
    done
    proxyble_print_hr 79
    show_recent_diagnostics
    return 1
}

main() {
    local wait_seconds=10
    local rule=""
    local run_all=0

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --wait)
                if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
                    echo "[ERROR] --wait requires a non-negative integer."
                    exit 1
                fi
                wait_seconds="$2"
                shift 2
                ;;
            -a|--all)
                run_all=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                if [[ -n "$rule" ]]; then
                    rule+=" "
                fi
                rule+="$1"
                shift
                ;;
        esac
    done

    require_root

    if [[ "$run_all" -eq 1 ]]; then
        if [[ -n "$rule" ]]; then
            echo "[ERROR] -a/--all cannot be combined with an explicit rule."
            exit 1
        fi
        run_all_policy_tests "$wait_seconds"
        return
    fi

    if [[ -z "$rule" ]]; then
        read -rp "Enter rule: " rule
    fi

    run_policy_rule_test "$rule" "$wait_seconds" 1
}

main "$@"

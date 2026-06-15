#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
STAGE_SCRIPT="$SCRIPT_DIR/stage.sh"
PROXYBLE_BIN="${PROXYBLE_BIN:-/opt/proxyble/proxyble}"
LISTENER_PORT="${PROXYBLE_LISTENER_PORT:-18080}"
BACKEND_HOST="${PROXYBLE_BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${PROXYBLE_BACKEND_PORT:-18081}"
TIMEOUT="${PROXYBLE_TIMEOUT:-60s}"
RULE_BATCH_WAIT="${PROXYBLE_RULE_BATCH_WAIT:-6}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '[ERROR] Proxyble CLI regression must run as root.\n' >&2
    printf '[ERROR] Run: sudo %s\n' "$0" >&2
    exit 1
fi
SUDO=()

failures=0
ran_teardown=0
cleanup_enabled=0

print_header() {
    printf '\n%s\n' "================================================================================"
    printf '%s\n' "$1"
    printf '%s\n' "================================================================================"
}

run_ok() {
    local label="$1"
    shift

    printf '\n[TEST] %s\n' "$label"
    printf '       '
    printf '%q ' "$@"
    printf '\n'

    "$@"
    local rc=$?
    if [[ "$rc" -eq 0 ]]; then
        printf '[PASS] %s\n' "$label"
        return 0
    fi

    printf '[FAIL] %s returned %d\n' "$label" "$rc" >&2
    failures=$((failures + 1))
    return "$rc"
}

run_proxyble() {
    run_ok "$1" "${SUDO[@]}" "$PROXYBLE_BIN" "${@:2}"
}

teardown() {
    ran_teardown=1
    run_proxyble "installation teardown" --installation-remove --yes --keep-java
}

finish() {
    local rc=$?
    if [[ "$cleanup_enabled" -eq 1 && "$ran_teardown" -eq 0 ]]; then
        print_header "Proxyble CLI teardown"
        teardown || true
    fi
    if [[ "$failures" -eq 0 && "$rc" -eq 0 ]]; then
        printf '\n[SUCCESS] Proxyble CLI regression completed with all commands returning 0.\n'
        exit 0
    fi
    if [[ "$failures" -eq 0 ]]; then
        printf '\n[FAILED] Proxyble CLI regression stopped before command checks completed (exit %d).\n' "$rc" >&2
        exit 1
    fi
    printf '\n[FAILED] Proxyble CLI regression finished with %d command failure(s).\n' "$failures" >&2
    exit 1
}
trap finish EXIT

print_header "Proxyble CLI regression"
printf '[INFO] Project root   : %s\n' "$PROJECT_DIR"
printf '[INFO] Proxyble binary : %s\n' "$PROXYBLE_BIN"
printf '[INFO] Listener        : 0.0.0.0:%s\n' "$LISTENER_PORT"
printf '[INFO] Backend         : %s:%s\n' "$BACKEND_HOST" "$BACKEND_PORT"
printf '[INFO] Rule batch wait : %s second(s)\n' "$RULE_BATCH_WAIT"

if ! "${SUDO[@]}" test -x "$PROXYBLE_BIN"; then
    printf '[ERROR] Proxyble binary is not executable: %s\n' "$PROXYBLE_BIN" >&2
    printf '[ERROR] Run %s first, or set PROXYBLE_BIN=/path/to/proxyble.\n' "$STAGE_SCRIPT" >&2
    exit 1
fi

cleanup_enabled=1

print_header "Installation commands"
run_proxyble "install" --install --with-riodb --yes --accept-license || exit 1
run_proxyble "installation license" --installation-license || exit 1
run_ok "policy templates installed" "${SUDO[@]}" test -d /opt/proxyble/templates/RioSQL/policies || exit 1
run_ok "legacy root license file absent" "${SUDO[@]}" test ! -e /opt/proxyble/LICENSE || exit 1
run_proxyble "installation list" --installation-list || exit 1

print_header "Config commands"
run_proxyble "config listener tcp" --config-listener --yes \
    --mode tcp \
    --port "$LISTENER_PORT" \
    --timeout "$TIMEOUT" \
    --no-start \
    --reset-active-rules || exit 1
run_proxyble "config backend" --config-backend --yes \
    --primary-host "$BACKEND_HOST" \
    --primary-port "$BACKEND_PORT" \
    --no-secondary \
    --no-start || exit 1

print_header "Policy commands"
run_proxyble "policies list initially" --policies-list || exit 1
run_proxyble "policies deploy tcp-compatible" --policies-deploy \
    --policy api_flood_control || exit 1
run_proxyble "policies list after tcp deploy" --policies-list || exit 1
run_proxyble "policies remove tcp-compatible" --policies-remove --yes \
    --policy api_flood_control || exit 1
run_proxyble "policies view alias after tcp remove" --policies-view --policy all || exit 1

print_header "Config commands continued"
run_proxyble "config listener http" --config-listener --yes \
    --mode http \
    --port "$LISTENER_PORT" \
    --timeout "$TIMEOUT" \
    --no-start \
    --reset-active-rules || exit 1
run_proxyble "config view" --config-view || exit 1

print_header "HTTP policy commands"
run_proxyble "policies deploy http-only" --policies-deploy \
    --policy cache_miss_and_origin_pressure_control || exit 1
run_proxyble "policies list after http deploy" --policies-list || exit 1
run_proxyble "policies remove http-only" --policies-remove --yes \
    --policy cache_miss_and_origin_pressure_control || exit 1

run_proxyble "config restart" --config-restart --yes || exit 1
run_proxyble "config status" --config-status || exit 1

print_header "Rule commands"
run_proxyble "rules list" --rules-list || exit 1
run_proxyble "rules add BUSY_DEFLECTION" --rules-add --yes \
    --rule BUSY_DEFLECTION \
    --target 192.0.2.10 \
    --expiration 10m || exit 1
run_proxyble "rules add DROP" --rules-add --yes \
    --rule DROP \
    --target 192.0.2.11 \
    --expiration 10m || exit 1
run_proxyble "rules add LIMIT_BANDWIDTH" --rules-add --yes \
    --rule LIMIT_BANDWIDTH \
    --target 192.0.2.12 \
    --bandwidth 10mb \
    --expiration 10m || exit 1
run_proxyble "rules add LIMIT_CONCURRENT" --rules-add --yes \
    --rule LIMIT_CONCURRENT \
    --target 192.0.2.13 \
    --limit 50 \
    --expiration 10m || exit 1
run_proxyble "rules add LIMIT_CONN_RATE" --rules-add --yes \
    --rule LIMIT_CONN_RATE \
    --target 192.0.2.14 \
    --rate 25/second \
    --expiration 10m || exit 1
run_proxyble "rules add LIMIT_ENDPOINT_RATE" --rules-add --yes \
    --rule LIMIT_ENDPOINT_RATE \
    --target 192.0.2.15 \
    --rate 10/second \
    --endpoints /login,/api \
    --expiration 10m || exit 1
run_proxyble "rules add LIMIT_RATE_SLOW" --rules-add --yes \
    --rule LIMIT_RATE_SLOW \
    --target 192.0.2.16 \
    --expiration 10m || exit 1
run_proxyble "rules add REJECT" --rules-add --yes \
    --rule REJECT \
    --target 192.0.2.17 \
    --expiration 10m || exit 1
run_proxyble "rules add TIMEOUT" --rules-add --yes \
    --rule TIMEOUT \
    --target 192.0.2.18 \
    --timeout-value 5s \
    --expiration 10m || exit 1
run_ok "wait for rule-agent batch window" sleep "$RULE_BATCH_WAIT" || exit 1
run_proxyble "rules list after batch wait" --rules-list || exit 1
run_proxyble "rules check IP" --rules-check --ip 192.0.2.11 || exit 1
run_proxyble "rules reset LIMIT_RATE_SLOW" --rules-reset --type LIMIT_RATE_SLOW --yes || exit 1
run_proxyble "rules reset ALL" --rules-reset --type ALL --yes || exit 1

print_header "Service stop command"
run_proxyble "config stop" --config-stop --yes || exit 1

print_header "Proxyble CLI teardown"
teardown || exit 1

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
SOURCE_APP_DIR="$PROJECT_DIR"
SOURCE_GO_DIR="$SOURCE_APP_DIR/src"
RULE_AGENT_SRC_DIR="$SOURCE_APP_DIR/proxyble-rule-agent"
RIODB_SETTINGS="$SOURCE_APP_DIR/bin/riodb-settings.json"
BUILD_DIR="$(mktemp -d /tmp/proxyble-stage.XXXXXX)"
STAGED_PROXYBLE="$BUILD_DIR/proxyble"
STAGED_RULE_AGENT="$BUILD_DIR/proxyble-rule-agent"
trap 'rm -rf "$BUILD_DIR"' EXIT

if [[ ! -f "$SOURCE_GO_DIR/go.mod" ]]; then
    echo "[ERROR] Missing Go app source module: $SOURCE_GO_DIR/go.mod" >&2
    exit 1
fi

if [[ ! -f "$RULE_AGENT_SRC_DIR/go.mod" ]]; then
    echo "[ERROR] Missing rule-agent source module: $RULE_AGENT_SRC_DIR/go.mod" >&2
    exit 1
fi

if [[ ! -f "$RIODB_SETTINGS" ]]; then
    echo "[ERROR] Missing RioDB settings file: $RIODB_SETTINGS" >&2
    exit 1
fi

if [[ ! -d "$SOURCE_APP_DIR/templates/RioSQL/policies" ]]; then
    echo "[ERROR] Missing RioSQL policy templates: $SOURCE_APP_DIR/templates/RioSQL/policies" >&2
    exit 1
fi

if ! find "$SOURCE_APP_DIR/templates/RioSQL/policies" -maxdepth 1 -type f -name '*.sql' | grep -q .; then
    echo "[ERROR] No deployable RioSQL policy templates found in $SOURCE_APP_DIR/templates/RioSQL/policies" >&2
    exit 1
fi

for license_file in GPL-2.0.txt THIRD-PARTY-NOTICES.txt; do
    if [[ ! -f "$SOURCE_APP_DIR/LICENSES/$license_file" ]]; then
        echo "[ERROR] Missing license bundle file: $SOURCE_APP_DIR/LICENSES/$license_file" >&2
        exit 1
    fi
done

echo "[INFO] Checking stage.sh syntax"
bash -n "$0"

echo "[INFO] Running Proxyble Go tests"
(
    cd "$SOURCE_GO_DIR"
    GOCACHE="${GOCACHE:-/tmp/go-build}" go test ./...
)

echo "[INFO] Running Proxyble Go vet checks"
(
    cd "$SOURCE_GO_DIR"
    GOCACHE="${GOCACHE:-/tmp/go-build}" go vet ./...
)

echo "[INFO] Running Proxyble rule-agent Go tests"
(
    cd "$RULE_AGENT_SRC_DIR"
    GOCACHE="${GOCACHE:-/tmp/go-build}" go test ./...
)

echo "[INFO] Running Proxyble rule-agent Go vet checks"
(
    cd "$RULE_AGENT_SRC_DIR"
    GOCACHE="${GOCACHE:-/tmp/go-build}" go vet ./...
)

echo "[INFO] Building Proxyble Go installer for staging"
(
    cd "$SOURCE_GO_DIR"
    GOCACHE="${GOCACHE:-/tmp/go-build}" go build -buildvcs=false -o "$STAGED_PROXYBLE" .
)

echo "[INFO] Building Proxyble rule-agent for staging"
(
    cd "$RULE_AGENT_SRC_DIR"
    GOCACHE="${GOCACHE:-/tmp/go-build}" go build -buildvcs=false -o "$STAGED_RULE_AGENT" .
)

echo "[INFO] Copying Proxyble app tree to /opt/proxyble"
sudo rsync -a --delete \
    --exclude '.agents/' \
    --exclude '.codex' \
    --exclude '.codex/' \
    --exclude '.git/' \
    --exclude 'src/' \
    --exclude 'proxyble-rule-agent/' \
    --exclude '*.go' \
    --exclude 'go.mod' \
    --exclude 'go.sum' \
    --exclude 'proxyble' \
    --exclude 'bin/stage.sh' \
    --exclude 'bin/test-cli.sh' \
    --exclude 'bin/package.sh' \
    --exclude 'bin/package-arm.sh' \
    --exclude 'PRODUCT-LAYOUT.md' \
    --exclude 'DESIGN.md' \
    --exclude 'bin/riodb-*.tar.*' \
    --exclude 'codex-installer-inventory.md' \
    --exclude 'requirements.md' \
    "$SOURCE_APP_DIR/" /opt/proxyble/
sudo rm -f /opt/proxyble/PRODUCT-LAYOUT.md /opt/proxyble/DESIGN.md
sudo rm -f /opt/proxyble/bin/stage.sh /opt/proxyble/bin/test-cli.sh /opt/proxyble/bin/package.sh /opt/proxyble/bin/package-arm.sh

echo "[INFO] Installing freshly built proxyble Go binary into staged tree"
sudo install -o root -g root -m 700 "$STAGED_PROXYBLE" /opt/proxyble/proxyble

echo "[INFO] Installing freshly built proxyble-rule-agent binary into staged tree"
sudo install -o root -g root -m 700 "$STAGED_RULE_AGENT" /opt/proxyble/bin/proxyble-rule-agent

riodb_archive_path="$(awk -F'"' '/"archive_path"[[:space:]]*:/ { print $4; exit }' "$RIODB_SETTINGS")"
if [[ -z "$riodb_archive_path" ]]; then
    echo "[ERROR] Missing riodb.archive_path in $RIODB_SETTINGS" >&2
    exit 1
fi
if [[ "$riodb_archive_path" == /* || "$riodb_archive_path" == *..* ]]; then
    echo "[ERROR] riodb.archive_path must be relative to $SOURCE_APP_DIR/bin" >&2
    exit 1
fi

if [[ -e /usr/local/bin/proxyble ]]; then
    echo "[INFO] Updating active /usr/local/bin/proxyble binary"
    sudo install -o root -g root -m 755 "$STAGED_PROXYBLE" /usr/local/bin/proxyble
fi

if [[ -e /usr/local/bin/proxyble-rule-agent ]]; then
    echo "[INFO] Updating active /usr/local/bin/proxyble-rule-agent binary"
    sudo install -o root -g root -m 700 "$STAGED_RULE_AGENT" /usr/local/bin/proxyble-rule-agent
fi

sudo chown -R root:root /opt/proxyble
sudo find /opt/proxyble -type d -exec chmod 700 {} \;
sudo find /opt/proxyble -type f -exec chmod 600 {} \;
sudo find /opt/proxyble -type f -name '*.sh' -exec chmod 700 {} \;

sudo chmod 700 /opt/proxyble/proxyble
sudo chmod 700 /opt/proxyble/bin/proxyble-rule-agent
sudo chmod 600 /opt/proxyble/bin/riodb-*.tar.* 2>/dev/null || true
sudo test -d /opt/proxyble/templates/RioSQL/policies

if sudo systemctl cat proxyble-rule-agent.service >/dev/null 2>&1; then
    echo "[INFO] restarting proxyble-rule-agent.service"
    sudo systemctl start proxyble-rule-agent.service
else
    echo "[NOTICE] proxyble-rule-agent.service is not installed yet; skipping restart"
fi

echo "to run proxyble, type:"
echo "sudo /opt/proxyble/proxyble"

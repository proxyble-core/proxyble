#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
ROOT_DIR="$(cd -- "$PROJECT_DIR/.." && pwd -P)"
cd "$ROOT_DIR"

VERSION="${1:-${PROXYBLE_RELEASE_VERSION:-}}"
PLATFORM="arm"
GOARM_ARCH="arm64"
PROXYBLE_SRC_DIR="$PROJECT_DIR/src"
RULE_AGENT_SRC_DIR="$PROJECT_DIR/proxyble-rule-agent"
BUILD_DIR="$(mktemp -d /tmp/proxyble-arm-package.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

[[ -n "$VERSION" ]] || { printf "Version: "; read -r VERSION; }
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "[ERROR] Version may only contain letters, numbers, dots, underscores, and hyphens"; exit 1; }

RIODB_SETTINGS="$PROJECT_DIR/bin/riodb-settings.json"
ARM_RIODB_ARCHIVE_PATH="riodb-lin-arm-2026-3.tar.gz"
[[ -f "$RIODB_SETTINGS" ]] || { echo "[ERROR] Missing $RIODB_SETTINGS"; exit 1; }
RIODB_ARCHIVE_PATH="$(awk -F'"' '/"archive_path"[[:space:]]*:/ { print $4; exit }' "$RIODB_SETTINGS")"
[[ -n "$RIODB_ARCHIVE_PATH" ]] || { echo "[ERROR] Missing riodb.archive_path in $RIODB_SETTINGS"; exit 1; }
[[ "$RIODB_ARCHIVE_PATH" != /* && "$RIODB_ARCHIVE_PATH" != *..* ]] || { echo "[ERROR] riodb.archive_path must be relative to proxyble/bin"; exit 1; }
[[ -d "$PROJECT_DIR/templates/RioSQL/policies" ]] || { echo "[ERROR] Missing $PROJECT_DIR/templates/RioSQL/policies"; exit 1; }
find "$PROJECT_DIR/templates/RioSQL/policies" -maxdepth 1 -type f -name '*.sql' | grep -q . || { echo "[ERROR] No deployable policy SQL templates found"; exit 1; }

ARCHIVE="proxyble-linux-$PLATFORM.$VERSION.tar.gz"
CHECKSUM="proxyble-linux-$PLATFORM.$VERSION.checksum"
LATEST_ARCHIVE="proxyble-linux-$PLATFORM.latest.tar.gz"
LATEST_CHECKSUM="proxyble-linux-$PLATFORM.latest.checksum"
PKG_DIR="$BUILD_DIR/proxyble"

mkdir -p "$PKG_DIR/bin"

echo "[1/4] Building proxyble for linux/$GOARM_ARCH"
GOOS=linux GOARCH="$GOARM_ARCH" CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/go-build}" \
    go build -C "$PROXYBLE_SRC_DIR" -buildvcs=false -o "$PKG_DIR/proxyble" .

echo "[2/4] Building proxyble-rule-agent for linux/$GOARM_ARCH"
GOOS=linux GOARCH="$GOARM_ARCH" CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/go-build}" \
    go build -C "$RULE_AGENT_SRC_DIR" -buildvcs=false -o "$PKG_DIR/bin/proxyble-rule-agent" .

echo "[3/4] Copying release resources"
cp -a "$PROJECT_DIR/README.md" "$PKG_DIR/"
cp -a "$PROJECT_DIR/LICENSES" "$PKG_DIR/"
cp -a "$PROJECT_DIR/templates" "$PKG_DIR/"
awk -v archive="$ARM_RIODB_ARCHIVE_PATH" '
    /"archive_path"[[:space:]]*:/ {
        sub(/"archive_path"[[:space:]]*:[[:space:]]*"[^"]*"/, "\"archive_path\": \"" archive "\"")
    }
	    { print }
	' "$RIODB_SETTINGS" > "$PKG_DIR/bin/riodb-settings.json"
cp -a "$PROJECT_DIR/utils" "$PKG_DIR/"

echo "[4/4] Creating $ARCHIVE"
tar -czf "$ROOT_DIR/$ARCHIVE" -C "$BUILD_DIR" proxyble
(
    cd "$ROOT_DIR"
    sha256sum "$ARCHIVE" > "$CHECKSUM"
    cp -f "$ARCHIVE" "$LATEST_ARCHIVE"
    sha256sum "$LATEST_ARCHIVE" > "$LATEST_CHECKSUM"
)

echo "[SUCCESS] Created $ROOT_DIR/$ARCHIVE and $ROOT_DIR/$CHECKSUM"
echo "[SUCCESS] Created $ROOT_DIR/$LATEST_ARCHIVE and $ROOT_DIR/$LATEST_CHECKSUM"

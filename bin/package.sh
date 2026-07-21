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
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
ROOT_DIR="$(cd -- "$PROJECT_DIR/.." && pwd -P)"
DOWNLOADS_DIR="$ROOT_DIR/downloads"
cd "$ROOT_DIR"

VERSION="${1:-${PROXYBLE_RELEASE_VERSION:-}}"
TARGET="${2:-all}"
PROXYBLE_SRC_DIR="$PROJECT_DIR/src"
RULE_AGENT_SRC_DIR="$PROJECT_DIR/proxyble-rule-agent"
BANNER_FILE="$PROXYBLE_SRC_DIR/ui.go"
BUILD_ROOT="$(mktemp -d /tmp/proxyble-package.XXXXXX)"
PUBLISH_TMP=""
cleanup() {
    rm -rf "$BUILD_ROOT"
    [[ -z "$PUBLISH_TMP" ]] || rm -rf "$PUBLISH_TMP"
}
trap cleanup EXIT

[[ -n "$VERSION" ]] || { printf "Version: "; read -r VERSION; }
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "[ERROR] Version may only contain letters, numbers, dots, underscores, and hyphens"; exit 1; }

case "$TARGET" in
    all) TARGETS=(x32 x64 arm32 arm64) ;;
    x32|x64|arm32|arm64) TARGETS=("$TARGET") ;;
    *)
        echo "Usage: $0 VERSION {all|x32|x64|arm32|arm64}" >&2
        exit 1
        ;;
esac

RIODB_SETTINGS="$PROJECT_DIR/bin/riodb-settings.json"
[[ -f "$RIODB_SETTINGS" ]] || { echo "[ERROR] Missing $RIODB_SETTINGS"; exit 1; }
[[ -f "$PROXYBLE_SRC_DIR/allowlist.go" ]] || { echo "[ERROR] Missing allow-list source file: $PROXYBLE_SRC_DIR/allowlist.go"; exit 1; }
RIODB_ARCHIVE_PATH="$(awk -F'"' '/"archive_path"[[:space:]]*:/ { print $4; exit }' "$RIODB_SETTINGS")"
[[ -n "$RIODB_ARCHIVE_PATH" ]] || { echo "[ERROR] Missing riodb.archive_path in $RIODB_SETTINGS"; exit 1; }
[[ "$RIODB_ARCHIVE_PATH" != /* && "$RIODB_ARCHIVE_PATH" != *..* ]] || { echo "[ERROR] riodb.archive_path must be relative to proxyble/bin"; exit 1; }
[[ -f "$BANNER_FILE" ]] || { echo "[ERROR] Missing banner source file: $BANNER_FILE"; exit 1; }
[[ -d "$PROJECT_DIR/templates/RioSQL/policies" ]] || { echo "[ERROR] Missing $PROJECT_DIR/templates/RioSQL/policies"; exit 1; }
find "$PROJECT_DIR/templates/RioSQL/policies" -maxdepth 1 -type f -name '*.sql' | grep -q . || { echo "[ERROR] No deployable policy SQL templates found"; exit 1; }

BANNER_MATCHES="$(grep -Ec '^[[:space:]]*line\(colorBlueDark, "      \[proxyble\] Version [A-Za-z0-9._-]+        log:"\+logPath\)$' "$BANNER_FILE" || true)"
[[ "$BANNER_MATCHES" -eq 1 ]] || { echo "[ERROR] Expected exactly one Proxyble version banner in $BANNER_FILE; found $BANNER_MATCHES"; exit 1; }
sed -E -i 's|^([[:space:]]*line\(colorBlueDark, "      \[proxyble\] Version )[A-Za-z0-9._-]+(        log:"\+logPath\))$|\1'"$VERSION"'\2|' "$BANNER_FILE"
echo "[INFO] Updated Proxyble banner to version $VERSION"

mkdir -p "$DOWNLOADS_DIR"

package_target() {
    local target="$1"
    local goarch
    local goarm=""

    case "$target" in
        x32)
            goarch="386"
            ;;
        x64)
            goarch="amd64"
            ;;
        arm32)
            goarch="arm"
            goarm="6"
            ;;
        arm64)
            goarch="arm64"
            ;;
    esac

    local build_dir="$BUILD_ROOT/$target"
    local pkg_dir="$build_dir/proxyble"
    local archive="proxyble-linux-$target.$VERSION.tar.gz"
    local checksum="proxyble-linux-$target.$VERSION.checksum"
    local latest_archive="proxyble-linux-$target.latest.tar.gz"
    local latest_checksum="proxyble-linux-$target.latest.checksum"
    local riodb_archive_path="riodb-$target-${VERSION}.tar.gz"

    mkdir -p "$pkg_dir/bin"

    echo "[$target 1/4] Building proxyble for linux/$goarch${goarm:+ (GOARM=$goarm)}"
    if [[ -n "$goarm" ]]; then
        GOOS=linux GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/go-build}" \
            go build -C "$PROXYBLE_SRC_DIR" -buildvcs=false -o "$pkg_dir/proxyble" .
    else
        GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/go-build}" \
            go build -C "$PROXYBLE_SRC_DIR" -buildvcs=false -o "$pkg_dir/proxyble" .
    fi

    echo "[$target 2/4] Building proxyble-rule-agent for linux/$goarch${goarm:+ (GOARM=$goarm)}"
    if [[ -n "$goarm" ]]; then
        GOOS=linux GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/go-build}" \
            go build -C "$RULE_AGENT_SRC_DIR" -buildvcs=false -o "$pkg_dir/bin/proxyble-rule-agent" .
    else
        GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 GOCACHE="${GOCACHE:-/tmp/go-build}" \
            go build -C "$RULE_AGENT_SRC_DIR" -buildvcs=false -o "$pkg_dir/bin/proxyble-rule-agent" .
    fi

    echo "[$target 3/4] Copying release resources"
    cp -a "$PROJECT_DIR/README.md" "$pkg_dir/"
    cp -a "$PROJECT_DIR/LICENSES" "$pkg_dir/"
    cp -a "$PROJECT_DIR/templates" "$pkg_dir/"
    awk -v archive="$riodb_archive_path" '
        /"archive_path"[[:space:]]*:/ {
            sub(/"archive_path"[[:space:]]*:[[:space:]]*"[^"]*"/, "\"archive_path\": \"" archive "\"")
        }
        { print }
    ' "$RIODB_SETTINGS" > "$pkg_dir/bin/riodb-settings.json"
    cp -a "$PROJECT_DIR/utils" "$pkg_dir/"

    echo "[$target 4/4] Creating $archive"
    tar -czf "$build_dir/$archive" -C "$build_dir" proxyble
    (
        cd "$build_dir"
        sha256sum "$archive" > "$checksum"
        cp -f "$archive" "$latest_archive"
        sha256sum "$latest_archive" > "$latest_checksum"
    )

    PUBLISH_TMP="$(mktemp -d "$DOWNLOADS_DIR/.proxyble-package-$target.XXXXXX")"
    local artifact
    for artifact in "$archive" "$checksum" "$latest_archive" "$latest_checksum"; do
        cp -f "$build_dir/$artifact" "$PUBLISH_TMP/$artifact"
        chmod 0644 "$PUBLISH_TMP/$artifact"
    done
    for artifact in "$archive" "$checksum" "$latest_archive" "$latest_checksum"; do
        mv -f "$PUBLISH_TMP/$artifact" "$DOWNLOADS_DIR/$artifact"
    done
    rmdir "$PUBLISH_TMP"
    PUBLISH_TMP=""

    echo "[SUCCESS] Created $DOWNLOADS_DIR/$archive and $DOWNLOADS_DIR/$checksum"
    echo "[SUCCESS] Created $DOWNLOADS_DIR/$latest_archive and $DOWNLOADS_DIR/$latest_checksum"
}

for target in "${TARGETS[@]}"; do
    package_target "$target"
done

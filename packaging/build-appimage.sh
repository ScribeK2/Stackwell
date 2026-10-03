#!/usr/bin/env bash
# Builds Stackwell-<version>-x86_64.AppImage: the static binary, a .desktop
# file and an icon, wrapped in the static type2 runtime (no libfuse2 needed).
# Usage: VERSION=1.2.3 packaging/build-appimage.sh
set -euo pipefail

VERSION="${VERSION:?set VERSION}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$ROOT/build}"
APPDIR="$WORK/AppDir"
OUT="$ROOT/Stackwell-$VERSION-x86_64.AppImage"

mkdir -p "$WORK/tools"
fetch() { [ -s "$WORK/tools/$1" ] || curl -fsSL -o "$WORK/tools/$1" "$2"; chmod +x "$WORK/tools/$1"; }
fetch appimagetool https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
fetch runtime https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64

(cd "$ROOT/web" && npm ci --no-audit --no-fund && npm run build)

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
CGO_ENABLED=0 go build -C "$ROOT" -trimpath -ldflags "-s -w -X main.version=$VERSION" \
  -o "$APPDIR/usr/bin/stackwell" ./cmd/stackwell
cp "$ROOT/packaging/stackwell.desktop" "$ROOT/packaging/stackwell.svg" "$APPDIR/"
ln -s usr/bin/stackwell "$APPDIR/AppRun"
ln -s stackwell.svg "$APPDIR/.DirIcon"

ARCH=x86_64 "$WORK/tools/appimagetool" --appimage-extract-and-run --no-appstream \
  --runtime-file "$WORK/tools/runtime" "$APPDIR" "$OUT"
echo "Wrote $OUT"

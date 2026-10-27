#!/usr/bin/env bash
# Build the warden-verify release binaries into DIR (default: dist, relative to the
# repository root) with a SHA256SUMS file.
#
#   scripts/release-build.sh [DIR]
#
# Anyone with the same commit and the same Go toolchain gets byte-identical files:
# no cgo, no file system paths (-trimpath), and nothing in the build that depends
# on the machine or the clock. The release workflow builds on two different
# operating systems and refuses to publish unless every file matches.
set -euo pipefail
out="${1:-dist}"
cd "$(dirname "$0")/.."

platforms="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64"
rm -rf "$out"
mkdir -p "$out"
for p in $platforms; do
  goos="${p%/*}"
  goarch="${p#*/}"
  ext=""
  if [ "$goos" = windows ]; then ext=".exe"; fi
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -o "$out/warden-verify-$goos-$goarch$ext" ./cmd/warden-verify
done
(cd "$out" && shasum -a 256 warden-verify-* | sort -k2 > SHA256SUMS)

dirty=""
git diff --quiet HEAD -- || dirty=" (with uncommitted changes)"
echo "built $(git rev-parse HEAD)$dirty with $(go version)"
cat "$out/SHA256SUMS"

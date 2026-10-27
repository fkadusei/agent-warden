#!/usr/bin/env bash
# Fuzz every target in the module, one after another, for FUZZTIME each.
#
#   FUZZTIME=30s scripts/fuzz.sh
#
# A failing input is written to the package's testdata/fuzz/<Target>/ directory.
# Commit it once the bug is fixed: it then runs as a seed on every `go test`.
set -uo pipefail
cd "$(dirname "$0")/.."
fuzztime="${FUZZTIME:-30s}"

targets=$(grep -rlE '^func Fuzz[A-Za-z0-9_]*\(f \*testing\.F\)' --include='*_test.go' . | sort | while read -r file; do
  pkg="./$(dirname "${file#./}")"
  grep -oE '^func Fuzz[A-Za-z0-9_]*' "$file" | sed "s|^func |$pkg |"
done)
count=$(printf '%s\n' "$targets" | grep -c . || true)
if [ "$count" -eq 0 ]; then
  echo "no fuzz targets found: refusing to pass by fuzzing nothing" >&2
  exit 1
fi

echo "fuzzing $count targets for $fuzztime each"
failed=()
while read -r pkg name; do
  echo "::group::$pkg $name"
  if ! go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "$pkg"; then
    failed+=("$pkg $name")
  fi
  echo "::endgroup::"
done <<< "$targets"

if [ "${#failed[@]}" -gt 0 ]; then
  echo "fuzzing found failures in:" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "all $count targets ran for $fuzztime with no failures"

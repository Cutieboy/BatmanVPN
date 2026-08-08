#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
executable=${1:-"$repo_root/windows-gui/dist/MouseVPN-windows-x64.exe"}
wine_bin=${WINE_BIN:-wine}

if ! command -v "$wine_bin" >/dev/null 2>&1; then
    echo "Wine is not installed; set WINE_BIN to a Wine executable" >&2
    exit 1
fi
if [[ ! -f "$executable" ]]; then
    echo "Windows executable not found: $executable" >&2
    exit 1
fi

output=$(WINEDEBUG=-all "$wine_bin" "$executable" --diagnose)
printf '%s\n' "$output"
grep -qx 'platform=windows' <<<"$output"
grep -qx 'running_under_wine=true' <<<"$output"
grep -qx 'wintun_available=false' <<<"$output"

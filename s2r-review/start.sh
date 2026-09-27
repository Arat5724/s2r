#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == '-h' || "${1:-}" == '--help' ]]; then
  printf 'Usage: bash start.sh [shell-path-to-Windows-python.exe]\n'
  printf 'Run from WSL or Git Bash. The app host still runs under Windows Python.\n'
  exit 0
fi
if (( $# > 1 )); then
  printf 'Usage: bash start.sh [shell-path-to-Windows-python.exe]\n' >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if command -v wslpath >/dev/null 2>&1; then
  to_windows_path() { wslpath -w -- "$1"; }
elif command -v cygpath >/dev/null 2>&1; then
  to_windows_path() { cygpath -w -- "$1"; }
else
  printf 'S2R Review requires WSL or Git Bash with Windows path conversion.\n' >&2
  exit 1
fi

if (( $# == 1 )); then
  python_path="$1"
else
  python_path="$script_dir/.venv/Scripts/python.exe"
  if [[ ! -f "$python_path" ]]; then
    python_path="$script_dir/../samples/.venv-teamshelf/Scripts/python.exe"
  fi
fi
if [[ ! -f "$python_path" ]]; then
  printf 'Windows Python executable not found: %s\n' "$python_path" >&2
  exit 1
fi

python_path="$(realpath -- "$python_path")"
helper_path="$(to_windows_path "$script_dir/server_process.py")"
windows_python="$(to_windows_path "$python_path")"
"$python_path" -B "$helper_path" start --python "$windows_python"

#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/preview-process-lib.sh"
project="$here/techlab"
runtime="$here/techlab-runtime"
script="$project/run.py"
record="$runtime/server-process.bash-record"

if [[ "$#" -eq 1 && "$1" == --help ]]; then
    printf 'Usage: %s [PYTHON_PATH]\n' "$0"
    exit 0
fi
[[ "$#" -le 1 ]] || preview_die 'Usage: start-techlab-preview.sh [PYTHON_PATH]'
python="$project/.venv-linux/bin/python"
if [[ "$#" -eq 1 ]]; then python=$1; fi
if [[ "$python" != */* ]]; then
    python=$(command -v "$python") || preview_die 'Python executable not found.'
fi
python=$(readlink -f -- "$python") || preview_die 'Python executable not found. Create samples/techlab/.venv-linux first or pass PYTHON_PATH.'
[[ -x "$python" ]] || preview_die 'Python executable not found. Create samples/techlab/.venv-linux first or pass PYTHON_PATH.'
[[ -f "$script" ]] || preview_die 'TechLab run.py is missing.'
preview_require_record_available "$record" "$script" 'TechLab preview'
preview_port_open 8010 && preview_die 'Port 8010 is already in use. Inspect the existing process before starting TechLab.'

mkdir -p -- "$runtime"
cd -- "$project"
"$python" -B "$script" --port 8010 >"$runtime/server.out.log" 2>"$runtime/server.err.log" &
pid=$!
ticks=$(preview_start_ticks "$pid" 2>/dev/null) || ticks=''
cleanup=true
trap 'if [[ "$cleanup" == true ]]; then preview_cleanup_launch "$pid" "$ticks" "$script"; fi' EXIT
preview_wait_for_port "$pid" 8010 40 0.25 ||
    preview_die 'TechLab startup failed. Inspect samples/techlab-runtime/server.err.log.'
preview_write_record "$record" "$pid" "$script"
cleanup=false
printf 'TechLab is ready: http://127.0.0.1:8010\n'

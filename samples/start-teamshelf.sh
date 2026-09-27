#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/preview-process-lib.sh"
project="$here/teamshelf"
script="$project/run.py"
runtime="$here/teamshelf-runtime"
record="$runtime/preview-process.bash-record"
python="$here/.venv-teamshelf-linux/bin/python"
profile=baseline
port=8010
reports=false
background=false

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --profile)
            [[ "$#" -ge 2 ]] || preview_die '--profile requires baseline or hardened.'
            profile=$2; shift 2 ;;
        --port)
            [[ "$#" -ge 2 ]] || preview_die '--port requires a number.'
            port=$2; shift 2 ;;
        --reports)
            reports=true; shift ;;
        --python)
            [[ "$#" -ge 2 ]] || preview_die '--python requires an executable path.'
            python=$2; shift 2 ;;
        --background)
            background=true; shift ;;
        --help)
            printf 'Usage: %s [--profile baseline|hardened] [--port PORT] [--reports] [--python PATH] [--background]\n' "$0"
            exit 0 ;;
        *)
            preview_die "Unknown option: $1" ;;
    esac
done

[[ "$profile" == baseline || "$profile" == hardened ]] || preview_die 'Profile must be baseline or hardened.'
[[ "$port" =~ ^[0-9]+$ ]] || preview_die 'Port must be between 1 and 65535.'
port=$((10#$port))
((port >= 1 && port <= 65535)) || preview_die 'Port must be between 1 and 65535.'
if [[ "$python" != */* ]]; then
    python=$(command -v "$python") || preview_die 'Python executable not found.'
fi
python=$(readlink -f -- "$python") || preview_die 'Python executable not found.'
[[ -x "$python" ]] || preview_die 'Python environment missing. See samples/teamshelf/README.md or pass --python.'
[[ -f "$script" ]] || preview_die 'TeamShelf run.py is missing.'
cd -- "$project"

if [[ "$background" == false ]]; then
    if [[ "$reports" == true ]]; then
        exec "$python" -B "$script" --profile "$profile" --port "$port" --reports
    else
        exec "$python" -B "$script" --profile "$profile" --port "$port"
    fi
fi

preview_require_record_available "$record" "$script" 'TeamShelf preview'
preview_port_open "$port" && preview_die "Port $port is already in use. Inspect the existing process before starting TeamShelf."
mkdir -p -- "$runtime"
if [[ "$reports" == true ]]; then
    "$python" -B "$script" --profile "$profile" --port "$port" --reports >"$runtime/preview.out.log" 2>"$runtime/preview.err.log" &
else
    "$python" -B "$script" --profile "$profile" --port "$port" >"$runtime/preview.out.log" 2>"$runtime/preview.err.log" &
fi
pid=$!
ticks=$(preview_start_ticks "$pid" 2>/dev/null) || ticks=''
cleanup=true
trap 'if [[ "$cleanup" == true ]]; then preview_cleanup_launch "$pid" "$ticks" "$script"; fi' EXIT
preview_wait_for_port "$pid" "$port" 40 0.25 ||
    preview_die 'TeamShelf startup failed. Inspect samples/teamshelf-runtime/preview.err.log.'
preview_write_record "$record" "$pid" "$script"
cleanup=false
printf 'TeamShelf is ready: http://127.0.0.1:%s\n' "$port"

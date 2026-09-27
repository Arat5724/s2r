#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/preview-process-lib.sh"
[[ "$#" -eq 0 ]] || preview_die 'Usage: stop-techlab-preview.sh'
preview_stop_record "$here/techlab-runtime/server-process.bash-record" "$here/techlab/run.py" 'TechLab preview'

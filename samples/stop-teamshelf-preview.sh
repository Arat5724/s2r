#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/preview-process-lib.sh"
[[ "$#" -eq 0 ]] || preview_die 'Usage: stop-teamshelf-preview.sh'
preview_stop_record "$here/teamshelf-runtime/preview-process.bash-record" "$here/teamshelf/run.py" 'TeamShelf preview'

#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/preview-process-lib.sh"
[[ "$#" -eq 0 ]] || preview_die 'Usage: stop-spring-releasehub-preview.sh'
preview_stop_record "$here/spring-releasehub-runtime/server-process.bash-record" "$here/spring-releasehub/target/spring-releasehub-0.1.0.jar" 'ReleaseHub preview'

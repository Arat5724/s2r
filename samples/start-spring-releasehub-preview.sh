#!/usr/bin/env bash
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/preview-process-lib.sh"
project="$here/spring-releasehub"
runtime="$here/spring-releasehub-runtime"
jar="$project/target/spring-releasehub-0.1.0.jar"
record="$runtime/server-process.bash-record"

if [[ "$#" -eq 1 && "$1" == --help ]]; then
    printf 'Usage: %s [JAVA_PATH]\n' "$0"
    exit 0
fi
[[ "$#" -le 1 ]] || preview_die 'Usage: start-spring-releasehub-preview.sh [JAVA_PATH]'
java=java
if [[ "$#" -eq 1 ]]; then java=$1; fi
if [[ "$java" != */* ]]; then
    java=$(command -v "$java") || preview_die 'Java executable not found.'
fi
java=$(readlink -f -- "$java") || preview_die 'Java executable not found.'
[[ -x "$java" ]] || preview_die 'Java executable not found.'
[[ -d "$project" ]] || preview_die 'Spring ReleaseHub project is missing.'
preview_require_record_available "$record" "$jar" 'ReleaseHub preview'
preview_port_open 8030 && preview_die 'Port 8030 is already in use. Inspect the existing process before starting ReleaseHub.'

mkdir -p -- "$runtime"
cd -- "$project"
if [[ -f "$project/mvnw" ]]; then
    bash "$project/mvnw" -B -q -DskipTests package || preview_die 'ReleaseHub build failed.'
elif command -v mvn >/dev/null 2>&1; then
    mvn -B -q -DskipTests package || preview_die 'ReleaseHub build failed.'
else
    preview_die 'Maven Wrapper and Maven executable are both unavailable.'
fi
[[ -f "$jar" ]] || preview_die 'ReleaseHub JAR is missing after build.'
preview_port_open 8030 && preview_die 'Port 8030 became occupied during the build. No process was started.'

"$java" -jar "$jar" >"$runtime/server.out.log" 2>"$runtime/server.err.log" &
pid=$!
ticks=$(preview_start_ticks "$pid" 2>/dev/null) || ticks=''
cleanup=true
trap 'if [[ "$cleanup" == true ]]; then preview_cleanup_launch "$pid" "$ticks" "$jar"; fi' EXIT
preview_wait_for_port "$pid" 8030 100 0.3 ||
    preview_die 'ReleaseHub startup failed. Inspect samples/spring-releasehub-runtime/server.err.log.'
preview_write_record "$record" "$pid" "$jar"
cleanup=false
printf 'ReleaseHub is ready: http://127.0.0.1:8030\n'

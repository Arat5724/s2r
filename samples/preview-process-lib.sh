#!/usr/bin/env bash
# Shared Linux/WSL process checks for sample preview launchers.

preview_die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

preview_port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

preview_port_owned_by() {
    local pid=$1 port=$2 hex inode fd link
    [[ -d "/proc/$pid/fd" ]] || return 1
    printf -v hex '%04X' "$port"
    while IFS= read -r inode; do
        for fd in "/proc/$pid/fd/"*; do
            link=$(readlink -- "$fd" 2>/dev/null) || continue
            if [[ "$link" == "socket:[$inode]" ]]; then
                return 0
            fi
        done
    done < <(awk -v local_addr="0100007F:$hex" '$2 == local_addr && $4 == "0A" { print $10 }' /proc/net/tcp)
    return 1
}

preview_wait_for_port() {
    local pid=$1 port=$2 attempts=$3 delay=$4 i
    for ((i = 0; i < attempts; i++)); do
        if preview_port_owned_by "$pid" "$port"; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        sleep "$delay"
    done
    return 1
}

preview_process_has_arg() {
    tr '\0' '\n' < "/proc/$1/cmdline" | grep -Fx -- "$2" >/dev/null
}

preview_start_ticks() {
    awk '{print $22}' "/proc/$1/stat"
}

preview_cleanup_launch() {
    local pid=$1 ticks=$2 target=$3
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$ticks" =~ ^[0-9]+$ ]] || return 0
    [[ -r "/proc/$pid/stat" ]] || return 0
    [[ "$(preview_start_ticks "$pid")" == "$ticks" ]] || return 0
    preview_process_has_arg "$pid" "$target" || return 0
    kill -TERM "$pid" 2>/dev/null || true
}

preview_process_matches() {
    local pid=$1 ticks=$2 exe=$3 target=$4
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -r "/proc/$pid/stat" ]] || return 1
    [[ "$(preview_start_ticks "$pid")" == "$ticks" ]] || return 1
    [[ "$(readlink -f "/proc/$pid/exe")" == "$exe" ]] || return 1
    preview_process_has_arg "$pid" "$target"
}

preview_require_record_available() {
    local record=$1 expected=$2 label=$3 pid ticks exe target
    [[ -f "$record" ]] || return 0
    {
        IFS= read -r pid
        IFS= read -r ticks
        IFS= read -r exe
        IFS= read -r target
    } < "$record" || preview_die 'Invalid existing preview process record.'
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$ticks" =~ ^[0-9]+$ && "$target" == "$expected" ]] ||
        preview_die 'Invalid existing preview process record. No process was started.'
    if preview_process_matches "$pid" "$ticks" "$exe" "$target"; then
        preview_die "$label is already running as PID $pid. Stop it before starting another preview."
    fi
}

preview_write_record() {
    local record=$1 pid=$2 target=$3 ticks exe tmp
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || preview_die 'Invalid preview PID.'
    ticks=$(preview_start_ticks "$pid") || preview_die 'Preview process exited before it could be recorded.'
    exe=$(readlink -f "/proc/$pid/exe") || preview_die 'Cannot inspect preview executable.'
    preview_process_has_arg "$pid" "$target" || preview_die 'Preview process command does not match the expected target.'
    tmp=$(mktemp "$record.tmp.XXXXXX") || preview_die 'Cannot create preview process record.'
    printf '%s\n%s\n%s\n%s\n' "$pid" "$ticks" "$exe" "$target" > "$tmp"
    mv -f -- "$tmp" "$record"
}

preview_stop_record() {
    local record=$1 expected=$2 label=$3 pid ticks exe target
    [[ -f "$record" ]] || preview_die "No $label process record exists. No process was stopped."
    {
        IFS= read -r pid
        IFS= read -r ticks
        IFS= read -r exe
        IFS= read -r target
    } < "$record" || preview_die 'Invalid preview process record.'
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$ticks" =~ ^[0-9]+$ ]] ||
        preview_die 'Invalid preview process record.'
    [[ "$target" == "$expected" ]] ||
        preview_die 'Process target does not match this sample. No process was stopped.'
    if [[ ! -r "/proc/$pid/stat" ]]; then
        printf '%s is already stopped.\n' "$label"
        return 0
    fi
    if [[ "$(awk '{print $3}' "/proc/$pid/stat")" == Z ]]; then
        printf '%s is already stopped.\n' "$label"
        return 0
    fi
    preview_process_matches "$pid" "$ticks" "$exe" "$target" ||
        preview_die 'Process identity does not match the saved record. No process was stopped.'
    kill -TERM "$pid"
    printf '%s stopped. Data is preserved.\n' "$label"
}

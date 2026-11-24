#!/usr/bin/env bash
# roll-all.sh [--dry-run] --approved <image-tag>
#
# Rolls every live hub to <image-tag> one at a time, through roll.sh, with every condition
# the live host needs built in. The hubs are discovered, never listed: each proxd-*.container
# quadlet that declares Environment=CLIPROXY_INSTANCE_ID= and whose unit is not masked (a
# hub taken out of service keeps its quadlet but is masked, as gemini was on 2026-11-22).
#
#
#   - It runs inside its own `systemd-run --user` unit (idle IO class, nice 10). Started
#     from a shell, it re-executes itself there and follows the unit's log file, so a
#     terminal, T3 or Claude session that dies mid-roll (proxd-claude carries the
#     operator's own Claude sessions) cannot leave a hub half rolled.
#   - It refuses to start in a nightly window, or less than WINDOW_MARGIN_MIN (20) minutes
#     before one, and stops before the next hub if one comes up mid-run.
#   - It restarts a hub only when none of the sidecar timers that touch the hubs fires in
#     the next QUIET_BEFORE (120) seconds, none fired in the last QUIET_AFTER (60) seconds
#     and none of their services is running. The times come from
#     `systemctl --user list-timers`: those timers are OnUnitActiveSec timers, so the
#     minute they fire at moves with every boot and every run.
#   - After each hub it waits for /healthz (roll.sh) and then for the exporter line
#     proxd_usage_source_subscribed{instance="<CLIPROXY_INSTANCE_ID>"} 1 together with a
#     proxd_usage_source_subscribed_timestamp_seconds later than the one read before the
#     restart, so a stale gauge from before the restart cannot pass, and a
#     proxd_usage_source_subscribed_boot_info boot id other than the one read before the
#     restart, so a reconnect to the old hub process before it stopped cannot pass either.
#   - On any failure it rolls that hub back to the Image= line read from its quadlet
#     before the roll, and stops. Hubs not yet reached are not touched.
#
# A hub whose quadlet already names <image-tag> is skipped, so running the same command
# again after a stop rolls only the rest. Rollback records go under each hub's data dir
# (roll.sh); the run log goes to <LIVE_DATA_ROOT>/roll-all/<timestamp>.log.
# --dry-run only reads the quadlets, timers and exporter, and prints the plan.
set -euo pipefail

BIN=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SELF=$BIN/roll-all.sh
ROLL=$BIN/roll.sh
UNIT_DIR=${LIVE_UNIT_DIR:-$HOME/.config/containers/systemd}
DATA_ROOT=${LIVE_DATA_ROOT:-$HOME/.local/share/proxd}
EXPORTER_URL=${EXPORTER_URL:-http://127.0.0.1:9787/metrics}
HUBS=""  # discovered by read_quadlets
# Order only, never membership: these discovered hubs roll first, in this order, and any
# other discovered hub follows alphabetically. codex goes first so the image proves itself
# before proxd-claude, which carries the operator's own Claude sessions, restarts.
ROLL_ORDER=${ROLL_ORDER:-codex claude}
# UTC; 04:20 is prox-usage-nightly.
NIGHTLY_WINDOWS="01:00-04:00 04:20-07:00 12:20-13:00"
WINDOW_MARGIN_MIN=${WINDOW_MARGIN_MIN:-20}
# proxd-claude-ua-sync can itself restart proxd-claude.
QUIET_TIMERS=${QUIET_TIMERS:-proxd-recovery-check.timer proxd-rerank.timer prox-auth-janitor.timer proxd-claude-ua-sync.timer}
QUIET_BEFORE=${QUIET_BEFORE:-120}
QUIET_AFTER=${QUIET_AFTER:-60}
QUIET_WAIT=${QUIET_WAIT:-900}
SUBSCRIBE_TIMEOUT=${SUBSCRIBE_TIMEOUT:-180}
# Settings the unit needs from this environment (systemd-run does not pass it on).
PASS_ENV="PATH LIVE_UNIT_DIR LIVE_DATA_ROOT EXPORTER_URL WINDOW_MARGIN_MIN QUIET_TIMERS QUIET_BEFORE QUIET_AFTER QUIET_WAIT SUBSCRIBE_TIMEOUT ROLL_ALL_NOW ROLL_ORDER"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "error: $*" >&2; exit 1; }
# ROLL_ALL_NOW (epoch seconds) pins the clock for the window and timer checks (tests).
now_s() { echo "${ROLL_ALL_NOW:-$(date -u +%s)}"; }
hm() { echo $((10#${1%:*} * 60 + 10#${1#*:})); }

# window_reason <epoch>: why no roll may start at that time, or nothing.
window_reason() {
  local m=$((($1 % 86400) / 60)) w s e
  for w in $NIGHTLY_WINDOWS; do
    s=$(hm "${w%-*}") e=$(hm "${w#*-}")
    if [ "$m" -ge $((s - WINDOW_MARGIN_MIN)) ] && [ "$m" -lt "$e" ]; then
      echo "nightly window $w UTC (or less than $WINDOW_MARGIN_MIN min before it)"
      return
    fi
  done
}

# quiet_reason <epoch>: why no hub may restart at that time, or nothing.
quiet_reason() {
  local now_us=$(($1 * 1000000)) json t row next last svc state
  json=$(systemctl --user list-timers --all --output=json) || die "cannot read the user timers"
  for t in $QUIET_TIMERS; do
    row=$(jq -r --arg u "$t" '.[] | select(.unit == $u) | "\(.next // 0) \(.last // 0) \(.activates)"' <<<"$json")
    [ -n "$row" ] || die "timer $t is not loaded; set QUIET_TIMERS to the timers that touch the hubs"
    read -r next last svc <<<"$row"
    if [ "$next" -gt 0 ] && [ "$next" -lt $((now_us + QUIET_BEFORE * 1000000)) ]; then
      echo "$t fires in $(((next - now_us) / 1000000)) s"
      return
    fi
    if [ "$last" -gt $((now_us - QUIET_AFTER * 1000000)) ]; then
      echo "$t fired $(((now_us - last) / 1000000)) s ago"
      return
    fi
    state=$(systemctl --user is-active "$svc" || true)
    case "$state" in inactive | failed) ;; *) echo "$svc is ${state:-in an unknown state}"; return ;; esac
  done
}

# Read the whole page first, then match. `curl ... | grep -q` fails under pipefail: grep
# exits at the first match, curl gets EPIPE writing the rest of the ~300 KB page and exits
# 23. On 21 Nov 2026 that rolled back a healthy hub.
subscribed() { # subscribed <instance>
  local page
  page=$(curl -fsS -m 5 "$EXPORTER_URL" 2>/dev/null) || return 1
  grep -qxF "proxd_usage_source_subscribed{instance=\"$1\"} 1" <<<"$page"
}

# source_state <instance>: "<subscribed> <subscription time> <boot id>" from one page, "-" for
# a missing gauge or time. The boot id is the exporter's escaped label value of the hub
# process the source is subscribed to; empty while not subscribed, or when prox-usage or the
# exporter predates that series.
source_state() {
  local page
  page=$(curl -fsS -m 5 "$EXPORTER_URL" 2>/dev/null) || return 1
  awk -v i="{instance=\"$1\"}" -v p="proxd_usage_source_subscribed_boot_info{instance=\"$1\",boot_id=\"" '
    $1 == "proxd_usage_source_subscribed" i { s = $2 }
    $1 == "proxd_usage_source_subscribed_timestamp_seconds" i { at = $2 }
    index($0, p) == 1 && substr($0, length($0) - 3) == "\"} 1" {
      boot = substr($0, length(p) + 1, length($0) - length(p) - 4)
    }
    END { print (s == "" ? "-" : s), (at == "" ? "-" : at), boot }' <<<"$page"
}

# resubscribed <instance> <before> <before_boot>: subscribed, at a time later than <before>,
# the subscription time read before the restart, to a hub boot id other than <before_boot>,
# the one read then. The gauge alone can be stale: on 21 Nov 2026 it read 1 in the same
# second each hub came back. A usage event is no proof either: quiet hubs go hours without
# one. The time alone is not proof either: a source that reconnects to the old process
# between the read and the restart gets a later time but keeps the old boot id. A NaN
# <before> and an empty <before_boot> (not subscribed then) pass any time and boot id.
resubscribed() {
  local state s at boot
  state=$(source_state "$1") || return 1
  read -r s at boot <<<"$state"
  [ "$s" = 1 ] && [ -n "$boot" ] && [ "$boot" != "$3" ] || return 1
  awk -v at="$at" -v before="$2" 'BEGIN {
    num = "^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$"
    if (at !~ num) exit 1
    if (before == "NaN") exit 0
    exit !(before ~ num && at + 0 > before + 0)
  }'
}

wait_subscribed() { # wait_subscribed <instance> <before> <before_boot>
  local deadline=$((SECONDS + SUBSCRIBE_TIMEOUT))
  until resubscribed "$1" "$2" "$3"; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 3
  done
}

unit_path() { echo "$UNIT_DIR/proxd-$1.container"; }
unit_image() { sed -n 's/^Image=//p' "$(unit_path "$1")" | head -n1; }
# The hub's instance id. Our quadlets declare it on its own line as
# Environment=CLIPROXY_INSTANCE_ID=<id>, the only form read here (as before discovery).
# Any other mention of it (quoted, among other assignments) stops the run rather than
# being guessed at, so discovery and the subscription check can never disagree.
quadlet_instance() { # quadlet_instance <unit-file>; empty when the quadlet declares none
  local plain any
  # Quadlet joins a line ending in a backslash to the lines after it (skipping comments), so
  # no line of a hub quadlet can be read on its own then. Ours never continue a line.
  if grep -q 'CLIPROXY_INSTANCE_ID' "$1" && grep -q '\\$' "$1"; then
    die "$1 continues a line with a backslash; write each setting on one line"
  fi
  plain=$(sed -n 's/^Environment=CLIPROXY_INSTANCE_ID=\([A-Za-z0-9][A-Za-z0-9._-]*\)$/\1/p' "$1" | head -n1)
  any=$(grep -c 'CLIPROXY_INSTANCE_ID' "$1" || true)
  if [ "$any" != 0 ] && { [ -z "$plain" ] || [ "$any" != 1 ]; }; then
    die "$1 must declare its hub as one line Environment=CLIPROXY_INSTANCE_ID=<id>"
  fi
  printf '%s\n' "$plain"
}
unit_instance() { quadlet_instance "$(unit_path "$1")"; }

declare -A PREV INSTANCE
discover_hubs() {
  local unit hub state instance found=" " ordered=""
  for unit in "$UNIT_DIR"/proxd-*.container; do
    [ -e "$unit" ] || continue
    [ -r "$unit" ] || die "cannot read $unit"
    # quadlet_instance runs in a subshell here: its die only ends that, so stop on its status.
    instance=$(quadlet_instance "$unit") || exit 1
    [ -n "$instance" ] || continue
    hub=${unit##*/proxd-}
    hub=${hub%.container}
    [ "$hub" != staging ] || die "$unit declares a hub instance, but staging is not a live hub"
    state=$(systemctl --user is-enabled "proxd-$hub" 2>/dev/null || true)
    case $state in
      masked | masked-runtime)
        log "proxd-$hub is $state; not a live hub, not rolled"
        continue
        ;;
      "") die "cannot read the unit state of proxd-$hub (systemctl --user is-enabled)" ;;
    esac
    found="$found$hub "
  done
  for hub in $ROLL_ORDER; do
    [[ $found == *" $hub "* ]] && ordered="${ordered:+$ordered }$hub" && found=${found/ $hub / }
  done
  for hub in $found; do ordered="${ordered:+$ordered }$hub"; done
  HUBS=$ordered
  [ -n "$HUBS" ] || die "no hub quadlets (proxd-*.container with CLIPROXY_INSTANCE_ID) in $UNIT_DIR"
  # Every hub must be one roll.sh can roll, checked before any restart, so a run never
  # rolls some hubs and then stops on one it cannot.
  for hub in $HUBS; do
    "$ROLL" --dry-run "$hub" "${IMAGE:-localhost/proxd:check}" >/dev/null 2>&1 ||
      die "discovered hub $hub (proxd-$hub.container) is not a target roll.sh can roll"
  done
}

read_quadlets() {
  local hub
  discover_hubs
  for hub in $HUBS; do
    [ -f "$(unit_path "$hub")" ] || die "unit file $(unit_path "$hub") not found"
    PREV[$hub]=$(unit_image "$hub")
    INSTANCE[$hub]=$(unit_instance "$hub")
    [ -n "${PREV[$hub]}" ] || die "no Image= line in $(unit_path "$hub")"
    [ -n "${INSTANCE[$hub]}" ] || die "no Environment=CLIPROXY_INSTANCE_ID= line in $(unit_path "$hub")"
  done
}

print_rollback() { # print_rollback <hub...>
  local hub
  for hub in "$@"; do echo "  $ROLL --approved $hub ${PREV[$hub]}"; done
}

ROLLED=()
stop() {
  log "STOPPED: $*"
  if [ "${#ROLLED[@]}" -gt 0 ]; then
    log "rolled to $IMAGE and kept: ${ROLLED[*]}; to undo them:"
    print_rollback "${ROLLED[@]}"
  fi
  exit 1
}

wait_quiet() { # wait_quiet <hub>
  local i reason last=
  for ((i = 0; i < QUIET_WAIT / 5; i++)); do
    reason=$(window_reason "$(now_s)")
    [ -z "$reason" ] || stop "before proxd-$1: $reason"
    reason=$(quiet_reason "$(now_s)")
    [ -n "$reason" ] || return 0
    [ "$reason" = "$last" ] || log "proxd-$1 waits: $reason"
    last=$reason
    sleep 5
  done
  stop "before proxd-$1: no quiet moment in $QUIET_WAIT s ($reason)"
}

roll_hub() { # roll_hub <hub>
  local hub=$1 prev=${PREV[$1]} state before before_boot
  if [ "$prev" = "$IMAGE" ]; then
    log "proxd-$hub is already on $IMAGE; skipped"
    return
  fi
  wait_quiet "$hub"
  # The time and the boot id from one page, so they belong to the same subscription.
  state=$(source_state "${INSTANCE[$hub]}") ||
    stop "before proxd-$hub: cannot read ${INSTANCE[$hub]} on $EXPORTER_URL"
  read -r _ before before_boot <<<"$state"
  # Subscribed (a time, not NaN) without a boot id: a later reconnect to the old process
  # could not be told from one to the new process.
  if [ "$before" = - ] || { [ "$before" != NaN ] && [ -z "$before_boot" ]; }; then
    stop "before proxd-$hub: ${INSTANCE[$hub]} has no subscription time and boot id to compare against on $EXPORTER_URL (time $before, boot ${before_boot:-none})"
  fi
  log "roll proxd-$hub: $prev -> $IMAGE"
  if "$ROLL" --approved "$hub" "$IMAGE" &&
    log "waiting for ${INSTANCE[$hub]} to subscribe again (subscribed at $before to hub boot ${before_boot:-none} before the restart)" &&
    wait_subscribed "${INSTANCE[$hub]}" "$before" "$before_boot"; then
    log "proxd-$hub on $IMAGE: /healthz ok, ${INSTANCE[$hub]} subscribed again"
    ROLLED+=("$hub")
    return
  fi
  # At once, without waiting for a quiet moment: the hub is already broken.
  log "proxd-$hub FAILED health or subscription; rolling it back to $prev"
  if "$ROLL" --approved "$hub" "$prev"; then
    log "proxd-$hub is back on $prev and /healthz answers"
  else
    log "proxd-$hub rollback did NOT come back healthy; check it now"
  fi
  stop "proxd-$hub failed; the hubs after it were not touched"
}

# in_unit: true when this process already runs in a systemd service (its own unit from the
# re-exec below, or one the operator started with systemd-run), not in a session scope.
in_unit() {
  case "$(sed -n 's|^0::.*/||p' "${ROLL_ALL_CGROUP_FILE:-/proc/self/cgroup}")" in
    *.service) return 0 ;;
    *) return 1 ;;
  esac
}

dry_run() {
  local hub reason
  echo "roll-all dry-run: nothing will be changed"
  if podman image exists "$IMAGE"; then echo "image:    $IMAGE (present)"; else echo "image:    $IMAGE (NOT FOUND: a live run would refuse)"; fi
  reason=$(window_reason "$(now_s)")
  echo "window:   ${reason:-clear}"
  reason=$(quiet_reason "$(now_s)")
  echo "timers:   ${reason:-quiet now} (watching $QUIET_TIMERS)"
  echo "would run: systemd-run --user --wait --collect --unit=proxd-roll-all-<timestamp> -p IOSchedulingClass=idle -p Nice=10 $SELF --approved $IMAGE"
  echo "log:      $DATA_ROOT/roll-all/<timestamp>.log"
  for hub in $HUBS; do
    echo "== $hub (${INSTANCE[$hub]})"
    if [ "${PREV[$hub]}" = "$IMAGE" ]; then
      echo "  already on $IMAGE: would skip"
      continue
    fi
    "$ROLL" --dry-run "$hub" "$IMAGE" | sed 's/^/  /'
    echo "  then wait: proxd_usage_source_subscribed{instance=\"${INSTANCE[$hub]}\"} 1, a newer subscribed_timestamp_seconds and a new subscribed_boot_info boot id on $EXPORTER_URL"
  done
  echo "rollback (state before the run):"
  # shellcheck disable=SC2086
  print_rollback $HUBS
}

main() {
  local approved=0 dry=0 args=() a
  for a in "$@"; do
    case "$a" in
      --approved) approved=1 ;;
      --dry-run) dry=1 ;;
      -*) die "unknown flag $a" ;;
      *) args+=("$a") ;;
    esac
  done
  [ "${#args[@]}" -eq 1 ] || die "usage: roll-all.sh [--dry-run] --approved <image-tag>"
  case "${args[0]}" in */*) IMAGE=${args[0]} ;; *) IMAGE=localhost/proxd:${args[0]} ;; esac
  read_quadlets
  if [ "$dry" = 1 ]; then
    dry_run
    return
  fi
  [ "$approved" = 1 ] || die "rolling the live hubs requires --approved (or use --dry-run)"
  local reason
  reason=$(window_reason "$(now_s)")
  [ -z "$reason" ] || die "refusing to start: $reason"

  if ! in_unit; then
    local stamp unit v env_args=() rc=0 tail_pid
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    unit=proxd-roll-all-$stamp
    export ROLL_ALL_LOG=$DATA_ROOT/roll-all/$stamp.log
    mkdir -p "$DATA_ROOT/roll-all"
    : >>"$ROLL_ALL_LOG"
    for v in $PASS_ENV ROLL_ALL_LOG; do [ -z "${!v+x}" ] || env_args+=(-E "$v=${!v}"); done
    log "starting unit $unit; log $ROLL_ALL_LOG"
    log "it keeps running if this shell goes away: journalctl --user -u $unit, or the log"
    tail -n +1 -F "$ROLL_ALL_LOG" 2>/dev/null &
    tail_pid=$!
    systemd-run --user --wait --collect --quiet --unit="$unit" \
      -p IOSchedulingClass=idle -p Nice=10 "${env_args[@]}" -- "$SELF" "$@" || rc=$?
    sleep 1
    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    log "unit $unit finished with exit status $rc"
    exit "$rc"
  fi

  if [ -z "${ROLL_ALL_LOG:-}" ]; then
    ROLL_ALL_LOG=$DATA_ROOT/roll-all/$(date -u +%Y%m%dT%H%M%SZ).log
    mkdir -p "$DATA_ROOT/roll-all"
    echo "log: $ROLL_ALL_LOG"
  fi
  # A file, not a tee: a tee would be killed with the unit's cgroup before its last lines.
  exec >>"$ROLL_ALL_LOG" 2>&1

  exec 8>"$DATA_ROOT/roll-all/lock"
  flock -n 8 || die "another roll-all.sh run holds $DATA_ROOT/roll-all/lock"
  read_quadlets # again, under the lock: a run that just finished may have changed them
  podman image exists "$IMAGE" || die "image $IMAGE not found locally; refusing to roll"
  local hub running_id quadlet_id state at boot
  # Each hub must run exactly the image its quadlet names: that is what the skip trusts and
  # what a rollback restores. A tag rebuilt or removed since the hub started cannot be.
  for hub in $HUBS; do
    running_id=$(podman inspect --format '{{.Image}}' "proxd-$hub" 2>/dev/null || true)
    quadlet_id=$(podman image inspect --format '{{.Id}}' "${PREV[$hub]}" 2>/dev/null || true)
    [ -n "$running_id" ] && [ "$running_id" = "$quadlet_id" ] ||
      die "proxd-$hub runs image ${running_id:-<none>} but its quadlet's ${PREV[$hub]} is ${quadlet_id:-not present locally} (tag rebuilt or removed?); a rollback could not restore it, refusing to roll"
  done
  # The check after each roll cannot pass if a source is down before it: refuse instead
  # of rolling back a healthy hub.
  for hub in $HUBS; do
    subscribed "${INSTANCE[$hub]}" || die "${INSTANCE[$hub]} is not subscribed on $EXPORTER_URL before the roll; fix that first"
    state=$(source_state "${INSTANCE[$hub]}") || state="- -"
    read -r _ at boot <<<"$state"
    [ "$at" != - ] ||
      die "$EXPORTER_URL has no proxd_usage_source_subscribed_timestamp_seconds for ${INSTANCE[$hub]}, so a reconnect after the restart cannot be proven; deploy the new prox-usage and proxd-exporter first"
    # Every source is subscribed here, and a prox-usage that knows the boot id always sends
    # one while subscribed: no series means that prox-usage or the exporter predates it.
    [ -n "$boot" ] ||
      die "$EXPORTER_URL has no proxd_usage_source_subscribed_boot_info for ${INSTANCE[$hub]}, so a reconnect to the new hub process cannot be proven; deploy the prox-usage that sends subscribed_boot_id and the matching proxd-exporter first"
  done
  log "roll-all to $IMAGE; Image= lines before the run, to undo it by hand:"
  # shellcheck disable=SC2086
  print_rollback $HUBS
  for hub in $HUBS; do roll_hub "$hub"; done
  log "ROLL-ALL COMPLETE: every hub is on $IMAGE (rolled now: ${ROLLED[*]:-none})"
  if [ "${#ROLLED[@]}" -gt 0 ]; then
    log "to undo:"
    print_rollback "${ROLLED[@]}"
  fi
}

# Sourced by the tests for the helpers; run otherwise.
[ "${BASH_SOURCE[0]}" != "$0" ] || main "$@"

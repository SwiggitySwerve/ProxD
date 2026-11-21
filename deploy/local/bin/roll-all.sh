#!/usr/bin/env bash
# roll-all.sh [--dry-run] --approved <image-tag>
#
# Rolls the three live hubs (codex, claude, gemini) to <image-tag> one at a time, through
# roll.sh, with every condition the live host needs built in:
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
#     proxd_usage_source_subscribed{instance="<CLIPROXY_INSTANCE_ID>"} 1.
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
HUBS="codex claude gemini"
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
PASS_ENV="PATH LIVE_UNIT_DIR LIVE_DATA_ROOT EXPORTER_URL WINDOW_MARGIN_MIN QUIET_TIMERS QUIET_BEFORE QUIET_AFTER QUIET_WAIT SUBSCRIBE_TIMEOUT ROLL_ALL_NOW"

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

wait_subscribed() { # wait_subscribed <instance>
  local deadline=$((SECONDS + SUBSCRIBE_TIMEOUT))
  until subscribed "$1"; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 3
  done
}

unit_path() { echo "$UNIT_DIR/proxd-$1.container"; }
unit_image() { sed -n 's/^Image=//p' "$(unit_path "$1")" | head -n1; }
unit_instance() { sed -n 's/^Environment=CLIPROXY_INSTANCE_ID=//p' "$(unit_path "$1")" | head -n1; }

declare -A PREV INSTANCE
read_quadlets() {
  local hub
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
  local hub=$1 prev=${PREV[$1]}
  if [ "$prev" = "$IMAGE" ]; then
    log "proxd-$hub is already on $IMAGE; skipped"
    return
  fi
  wait_quiet "$hub"
  log "roll proxd-$hub: $prev -> $IMAGE"
  if "$ROLL" --approved "$hub" "$IMAGE" && log "waiting for ${INSTANCE[$hub]} to be subscribed" &&
    wait_subscribed "${INSTANCE[$hub]}"; then
    log "proxd-$hub on $IMAGE: /healthz ok, ${INSTANCE[$hub]} subscribed"
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
    echo "  then wait: proxd_usage_source_subscribed{instance=\"${INSTANCE[$hub]}\"} 1 on $EXPORTER_URL"
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
  local hub running_id quadlet_id
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

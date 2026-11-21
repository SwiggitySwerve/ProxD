#!/usr/bin/env bash
# roll.test.sh: checks for roll.sh and roll-all.sh that touch nothing live.
#
# Fake quadlets (LIVE_UNIT_DIR) and data dir (LIVE_DATA_ROOT) under a temp dir; systemctl,
# systemd-run, podman, curl and sleep are stubs on PATH; the clock is pinned with
# ROLL_ALL_NOW. Run: deploy/local/bin/roll.test.sh
set -euo pipefail
BIN=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
FAILS=0
PASSES=0
ok() { PASSES=$((PASSES + 1)); echo "ok   $*"; }
bad() { FAILS=$((FAILS + 1)); echo "FAIL $*"; }
check() { # check <name> <command...>
  local name=$1
  shift
  if "$@"; then ok "$name"; else bad "$name"; fi
}
has() { grep -qF -- "$2" "$1"; }  # has <file> <text>
hasnt() { ! grep -qF -- "$2" "$1"; }

OLD=localhost/proxd:v8.0.79-aaaaaaaa
NEW=localhost/proxd:v8.0.80-bbbbbbbb
NOW=$(date -u -d '2026-11-21 15:00:00' +%s)

mkdir -p "$T/stub" "$T/units" "$T/data"
export LIVE_UNIT_DIR=$T/units LIVE_DATA_ROOT=$T/data EXPORTER_URL=http://127.0.0.1:9787/metrics
export ROLL_ALL_NOW=$NOW STUB=$T PATH="$T/stub:$PATH"
export STAGING_DATA_DIR=$T/proxd-staging  # lib.sh's data dir: live rolls must not write here
export ROLL_ALL_CGROUP_FILE=$T/cgroup-scope
echo "0::/user.slice/user-1000.slice/user@1000.service/app.slice/test.scope" >"$T/cgroup-scope"
echo "0::/user.slice/user-1000.slice/user@1000.service/app.slice/proxd-roll-all-test.service" >"$T/cgroup-service"

reset_units() {
  local hub port
  for hub in codex claude gemini; do
    case $hub in codex) port=8317 ;; claude) port=8319 ;; gemini) port=8321 ;; esac
    cat >"$T/units/proxd-$hub.container" <<EOF
[Container]
Environment=CLIPROXY_INSTANCE_ID=$hub-primary
Image=$OLD
ContainerName=proxd-$hub
PublishPort=$port:8317
EOF
  done
  rm -rf "$T/data" "$T/calls" "$T/systemd-run.args" "$T/bad-hub" "$T/unsubscribed" "$T/unsub-hub" "$T/rebuilt" "$T/stale-ts" "$T/no-ts"
  mkdir -p "$T/data"
  : >"$T/calls"
}

# timers <rerank-next-offset-s> [rerank-last-offset-s]: list-timers JSON relative to NOW.
timers() {
  local us=$((NOW * 1000000)) rn=$((NOW * 1000000 + ${1:-600} * 1000000)) rl=$((NOW * 1000000 + ${2:--300} * 1000000))
  cat >"$T/timers.json" <<EOF
[{"next":$((us + 400000000)),"left":1,"last":$((us - 200000000)),"passed":1,"unit":"proxd-recovery-check.timer","activates":"proxd-recovery-check.service"},
 {"next":$rn,"left":1,"last":$rl,"passed":1,"unit":"proxd-rerank.timer","activates":"proxd-rerank.service"},
 {"next":$((us + 500000000)),"left":1,"last":$((us - 100000000)),"passed":1,"unit":"prox-auth-janitor.timer","activates":"prox-auth-janitor.service"},
 {"next":$((us + 3000000000)),"left":1,"last":$((us - 600000000)),"passed":1,"unit":"proxd-claude-ua-sync.timer","activates":"proxd-claude-ua-sync.service"},
 {"next":null,"left":null,"last":null,"passed":null,"unit":"other.timer","activates":"other.service"}]
EOF
}

# --- stubs -------------------------------------------------------------------
cat >"$T/stub/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"$STUB/calls"
[ "$2" != restart ] || [ ! -f "$STUB/restart-fails" ] || exit 1
case "$*" in
  "--user list-timers --all --output=json") cat "$STUB/timers.json" ;;
  "--user is-active "*) if [ -f "$STUB/active-$3" ]; then cat "$STUB/active-$3"; else echo inactive; exit 3; fi ;;
esac
EOF
cat >"$T/stub/podman" <<'EOF'
#!/usr/bin/env bash
echo "podman $*" >>"$STUB/calls"
case "$1 $2 $3" in
  "image exists "*) [ "$3" != localhost/proxd:missing ] ;;
  "image inspect --format") [ "$5" != localhost/proxd:missing ] && echo "id-$5" ;;
  "inspect --format {{.ImageName}}") echo localhost/cli-proxy-api:legacy-alias ;;
  "inspect --format {{.Image}}") # the container runs its quadlet's image, unless rebuilt
    if [ -f "$STUB/rebuilt" ]; then echo id-older-build; else echo "id-$(sed -n 's/^Image=//p' "$LIVE_UNIT_DIR/$4.container")"; fi ;;
esac
EOF
# curl: a hub is down while its quadlet names the image in $STUB/bad-hub ("<hub> <image>").
cat >"$T/stub/curl" <<'EOF'
#!/usr/bin/env bash
url=${*: -1}
down() {
  [ -f "$STUB/bad-hub" ] || return 1
  read -r hub image <"$STUB/bad-hub"
  [ "$hub" = "$1" ] && grep -qxF "Image=$image" "$LIVE_UNIT_DIR/proxd-$1.container"
}
hub_of() { case "$1" in *:8317/*) echo codex ;; *:8319/*) echo claude ;; *:8321/*) echo gemini ;; esac; }
case "$url" in
  */metrics)
    for h in codex claude gemini; do
      v=1
      down "$h" && v=0
      [ -f "$STUB/unsubscribed" ] && grep -qx "$h" "$STUB/unsubscribed" && v=0
      # "<hub> <image>": healthy, but its source never subscribes while on that image
      if [ -f "$STUB/unsub-hub" ]; then
        read -r uh ui <"$STUB/unsub-hub"
        [ "$uh" = "$h" ] && grep -qxF "Image=$ui" "$LIVE_UNIT_DIR/proxd-$h.container" && v=0
      fi
      echo "proxd_usage_source_subscribed{instance=\"$h-primary\"} $v"
      # Subscription time: one second later per restart of the hub, unless the hub is named
      # in $STUB/stale-ts; NaN while unsubscribed; no series at all with $STUB/no-ts.
      [ ! -f "$STUB/no-ts" ] || continue
      n=$(grep -c "restart proxd-$h\." "$STUB/calls")
      [ -f "$STUB/stale-ts" ] && grep -qx "$h" "$STUB/stale-ts" && n=0
      ts=$((1763700000 + n)).5
      [ "$v" = 1 ] || ts=NaN
      echo "proxd_usage_source_subscribed_timestamp_seconds{instance=\"$h-primary\"} $ts"
    done
    cat "$STUB/filler" ;; # the real page is ~300 KB: a reader that stops early breaks the pipe
  */healthz) down "$(hub_of "$url")" && exit 7; exit 0 ;;
  */v1/models) if down "$(hub_of "$url")"; then echo 000; exit 7; fi; echo 401 ;;
esac
EOF
cat >"$T/stub/systemd-run" <<'EOF'
#!/usr/bin/env bash
echo "$*" >"$STUB/systemd-run.args"
while [ "$1" != -- ]; do
  case "$1" in -E) export "${2?}"; shift ;; esac
  shift
done
shift
ROLL_ALL_CGROUP_FILE=$STUB/cgroup-service exec "$@"
EOF
printf '#!/bin/sh\nexit 0\n' >"$T/stub/sleep"
chmod +x "$T/stub/"*
for ((i = 0; i < 4500; i++)); do echo '# HELP proxd_filler_metric padding so the page is as large as the real one'; done >"$T/filler"

restarts() { grep -o 'restart proxd-[a-z]*' "$T/calls" | tr '\n' ' ' || true; }
img() { sed -n 's/^Image=//p' "$T/units/proxd-$1.container"; }

# --- roll.sh -----------------------------------------------------------------
reset_units
timers
for hub in codex claude gemini; do
  out=$("$BIN/roll.sh" --dry-run "$hub" "$NEW")
  case $hub in codex) port=8317 ;; claude) port=8319 ;; gemini) port=8321 ;; esac
  check "roll.sh dry-run $hub names its unit and port" \
    grep -q "unit: *$T/units/proxd-$hub.container" <<<"$out"
  check "roll.sh dry-run $hub checks port $port" grep -qF "127.0.0.1:$port/healthz" <<<"$out"
  check "roll.sh dry-run $hub restarts only proxd-$hub" grep -qF "restart proxd-$hub.service" <<<"$out"
  check "roll.sh dry-run $hub rolls back to the quadlet Image=, not podman's alias" \
    grep -qF "rollback:    $BIN/roll.sh $hub $OLD --approved" <<<"$out"
  check "roll.sh dry-run $hub records under the hub's data dir" \
    grep -qF "record in:   $T/data/$hub/rollback/" <<<"$out"
done
check "roll.sh dry-runs changed no quadlet" [ "$(img codex)$(img claude)$(img gemini)" = "$OLD$OLD$OLD" ]
check "roll.sh dry-runs restarted nothing" hasnt "$T/calls" "systemctl --user restart"
check "roll.sh refuses a live target without --approved" \
  bash -c '! "$1/roll.sh" gemini "$2" 2>/dev/null' _ "$BIN" "$NEW"
check "roll.sh refuses an unknown target" bash -c '! "$1/roll.sh" --dry-run nope "$2" 2>/dev/null' _ "$BIN" "$NEW"

out=$("$BIN/roll.sh" --approved gemini "$NEW")
check "roll.sh gemini rewrites Image=" [ "$(img gemini)" = "$NEW" ]
check "roll.sh gemini restarts proxd-gemini only" [ "$(restarts)" = "restart proxd-gemini " ]
rec=$(ls "$T/data/gemini/rollback/"gemini-*.txt 2>/dev/null || echo /nonexistent)
check "roll.sh gemini records the quadlet's previous Image=" grep -qx "previous_image=$OLD" "$rec"
check "roll.sh writes no record to the staging data dir" [ ! -e "$T/proxd-staging" ]
touch "$T/restart-fails"
"$BIN/roll.sh" --approved codex "$NEW" >/dev/null 2>&1 || true
"$BIN/roll.sh" --approved codex "$OLD" >/dev/null 2>&1 || true
rm "$T/restart-fails"
check "roll.sh keeps both records when a rollback follows a failed restart at once" \
  [ "$(ls "$T/data/codex/rollback/" | wc -l)" = 2 ]
check "roll.sh gemini prints the rollback command" grep -qF "rollback: $BIN/roll.sh gemini $OLD --approved" <<<"$out"

# --- nightly windows ---------------------------------------------------------
# shellcheck source=roll-all.sh
. "$BIN/roll-all.sh"
at() { date -u -d "2026-11-21 $1" +%s; }
for t in 00:39 07:00 11:59 13:00 15:00 23:59; do
  check "window clear at $t UTC" [ -z "$(window_reason "$(at "$t")")" ]
done
for t in 00:40 01:00 02:30 03:59 04:00 04:19 04:20 06:59 12:00 12:20 12:59; do
  check "window blocks at $t UTC" [ -n "$(window_reason "$(at "$t")")" ]
done

# --- quiet timers ------------------------------------------------------------
timers 600 -300
check "timers quiet when nothing fires within 120 s or fired within 60 s" [ -z "$(quiet_reason "$NOW")" ]
timers 90 -300
check "timers busy when rerank fires in 90 s" grep -q "proxd-rerank.timer fires in 90 s" <<<"$(quiet_reason "$NOW")"
timers 600 -30
check "timers busy when rerank fired 30 s ago" grep -q "proxd-rerank.timer fired 30 s ago" <<<"$(quiet_reason "$NOW")"
timers 600 -300
echo activating >"$T/active-proxd-claude-ua-sync.service"
check "timers busy while ua-sync runs" grep -q "proxd-claude-ua-sync.service is activating" <<<"$(quiet_reason "$NOW")"
echo "" >"$T/active-proxd-claude-ua-sync.service"
check "timers busy when a service state cannot be read" grep -q "proxd-claude-ua-sync.service is in an unknown state" <<<"$(quiet_reason "$NOW")"
rm "$T/active-proxd-claude-ua-sync.service"
(QUIET_TIMERS=gone.timer quiet_reason "$NOW" >/dev/null 2>&1) && bad "a missing timer fails closed" ||
  ok "a missing timer fails closed"

# --- subscription check under set -euo pipefail -------------------------------
reset_units
naive() { curl -s "$EXPORTER_URL" | grep -q '^proxd_usage_source_subscribed{instance="codex-primary"} 1$'; }
check "reproduction: curl | grep -q fails under pipefail on a healthy hub" bash -c "$(declare -f naive); set -euo pipefail; ! naive"
check "subscribed reads the body first and passes" bash -c "$(declare -f subscribed); EXPORTER_URL=$EXPORTER_URL; set -euo pipefail; subscribed codex-primary"
echo gemini >"$T/unsubscribed"
check "subscribed is false for a 0 line" bash -c "$(declare -f subscribed); EXPORTER_URL=$EXPORTER_URL; set -euo pipefail; ! subscribed gemini-primary"
check "subscribed is false for an unknown instance" bash -c "$(declare -f subscribed); EXPORTER_URL=$EXPORTER_URL; set -euo pipefail; ! subscribed codex"
fns="$(declare -f subscribed_at resubscribed); EXPORTER_URL=$EXPORTER_URL; set -euo pipefail"
check "subscribed_at reads the subscription time" bash -c "$fns; [ \"\$(subscribed_at codex-primary)\" = 1763700000.5 ]"
check "subscribed_at is NaN while not subscribed" bash -c "$fns; [ \"\$(subscribed_at gemini-primary)\" = NaN ]"
check "resubscribed passes a time later than before" bash -c "$fns; resubscribed codex-primary 1763699999.5"
check "resubscribed refuses an unchanged time" bash -c "$fns; ! resubscribed codex-primary 1763700000.5"
check "resubscribed refuses an older time" bash -c "$fns; ! resubscribed codex-primary 1763700001"
check "resubscribed after a NaN before passes any finite time" bash -c "$fns; resubscribed codex-primary NaN"
check "resubscribed refuses an unsubscribed source after a NaN before" bash -c "$fns; ! resubscribed gemini-primary NaN"
touch "$T/no-ts"
check "subscribed_at fails without the series" bash -c "$fns; ! subscribed_at codex-primary"
check "resubscribed fails without the series" bash -c "$fns; ! resubscribed codex-primary NaN"

# --- roll-all.sh ---------------------------------------------------------------
reset_units
timers
out=$("$BIN/roll-all.sh" --dry-run "$NEW")
for hub in codex claude gemini; do
  check "roll-all dry-run plans $hub" grep -qF "== $hub ($hub-primary)" <<<"$out"
  check "roll-all dry-run prints $hub rollback" grep -qF "$BIN/roll.sh --approved $hub $OLD" <<<"$out"
done
check "roll-all dry-run shows the systemd-run unit" grep -qF "systemd-run --user --wait" <<<"$out"
check "roll-all dry-run reports the timers" grep -qF "timers:   quiet now" <<<"$out"
check "roll-all dry-run touches nothing" [ "$(img codex)$(img claude)$(img gemini)$(restarts)" = "$OLD$OLD$OLD" ]
check "roll-all dry-run starts no unit" [ ! -e "$T/systemd-run.args" ]
check "roll-all refuses without --approved" bash -c '! "$1/roll-all.sh" "$2" 2>/dev/null' _ "$BIN" "$NEW"

reset_units
check "roll-all refuses in a nightly window" \
  bash -c '! ROLL_ALL_NOW=$3 "$1/roll-all.sh" --approved "$2" 2>/dev/null' _ "$BIN" "$NEW" "$(at 02:00)"
check "roll-all in a window started no unit" [ ! -e "$T/systemd-run.args" ]

reset_units
echo gemini >"$T/unsubscribed"
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all refuses when a source is down before the roll" ||
  ok "roll-all refuses when a source is down before the roll"
check "roll-all with a source down restarted nothing" [ -z "$(restarts)" ]

reset_units
timers 30 -300
QUIET_WAIT=10 "$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all stops when no quiet moment comes" ||
  ok "roll-all stops when no quiet moment comes"
check "roll-all without a quiet moment restarted nothing" [ -z "$(restarts)" ]
check "roll-all logs why it waited" has "$T/out" "proxd-codex waits: proxd-rerank.timer fires in 30 s"

reset_units
timers
sed -i "s|^Image=.*|Image=localhost/proxd:missing|" "$T/units/proxd-gemini.container"
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all refuses when a current image is gone" ||
  ok "roll-all refuses when a current image is gone"
check "roll-all with a current image gone restarted nothing" [ -z "$(restarts)" ]
check "roll-all says which image is gone" has "$T/out" "its quadlet's localhost/proxd:missing is not present locally"

reset_units
timers
sed -i "s|^Image=.*|Image=$NEW|" "$T/units/proxd-codex.container"
touch "$T/rebuilt"
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all refuses a rebuilt tag" || ok "roll-all refuses a rebuilt tag"
check "roll-all with a rebuilt tag restarted nothing" [ -z "$(restarts)" ]
check "roll-all says the tag was rebuilt" has "$T/out" "proxd-codex runs image id-older-build but its quadlet's"

reset_units
timers
touch "$T/rebuilt" # every hub still on $OLD, but $OLD now names a newer build
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all refuses a rebuilt current tag" || ok "roll-all refuses a rebuilt current tag"
check "roll-all with a rebuilt current tag restarted nothing" [ -z "$(restarts)" ]

reset_units
timers
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && ok "roll-all succeeds" || { bad "roll-all succeeds"; cat "$T/out"; }
check "roll-all ran in systemd-run --wait" grep -qF -- "--user --wait --collect" "$T/systemd-run.args"
check "roll-all unit has idle IO and nice 10" grep -qF -- "-p IOSchedulingClass=idle -p Nice=10" "$T/systemd-run.args"
check "roll-all passes LIVE_UNIT_DIR to the unit" grep -qF -- "-E LIVE_UNIT_DIR=$T/units" "$T/systemd-run.args"
check "roll-all restarts one hub at a time in order" [ "$(restarts)" = "restart proxd-codex restart proxd-claude restart proxd-gemini " ]
check "roll-all leaves every quadlet on the new image" [ "$(img codex)$(img claude)$(img gemini)" = "$NEW$NEW$NEW" ]
check "roll-all records each hub under its data dir" \
  bash -c 'ls "$1"/codex/rollback/codex-*.txt "$1"/claude/rollback/claude-*.txt "$1"/gemini/rollback/gemini-*.txt >/dev/null' _ "$T/data"
log=$(ls "$T/data/roll-all/"*.log 2>/dev/null || echo /nonexistent)
check "roll-all writes a log file" has "$log" "ROLL-ALL COMPLETE"
check "roll-all passes each hub on a fresh subscription time" has "$log" "gemini-primary subscribed again"
check "roll-all output shows the log" has "$T/out" "ROLL-ALL COMPLETE"
check "roll-all prints the rollback commands" has "$log" "$BIN/roll.sh --approved claude $OLD"

reset_units
timers
echo "claude $NEW" >"$T/bad-hub"
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all fails when a hub fails" || ok "roll-all fails when a hub fails"
check "roll-all rolled codex first" [ "$(img codex)" = "$NEW" ]
check "roll-all rolled the failed hub back to its quadlet Image=" [ "$(img claude)" = "$OLD" ]
check "roll-all did not touch the hub after the failure" [ "$(img gemini)" = "$OLD" ]
check "roll-all never restarted gemini" [ "$(restarts)" = "restart proxd-codex restart proxd-claude restart proxd-claude " ]
check "roll-all says it stopped" has "$T/out" "STOPPED: proxd-claude failed"
check "roll-all prints how to undo the kept hub" has "$T/out" "$BIN/roll.sh --approved codex $OLD"

# A re-run after the stop skips the hub that is already on the image.
rm "$T/bad-hub"
: >"$T/calls"
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && ok "roll-all re-run succeeds" || { bad "roll-all re-run succeeds"; cat "$T/out"; }
check "roll-all re-run skips the hub already rolled" has "$T/out" "proxd-codex is already on $NEW; skipped"
check "roll-all re-run restarts only the rest" [ "$(restarts)" = "restart proxd-claude restart proxd-gemini " ]

reset_units
timers
echo "claude $NEW" >"$T/unsub-hub"
SUBSCRIBE_TIMEOUT=1 "$BIN/roll-all.sh" --approved "$NEW" >"$T/out2" 2>&1 && bad "roll-all fails when a source does not subscribe" ||
  ok "roll-all fails when a source does not subscribe"
check "roll-all rolled back the healthy but unsubscribed hub" [ "$(img claude)" = "$OLD" ]
check "roll-all did not touch the hub after it" [ "$(img gemini)" = "$OLD" ]
check "roll-all after a subscription failure never restarted gemini" [ "$(restarts)" = "restart proxd-codex restart proxd-claude restart proxd-claude " ]
check "roll-all reports the subscription failure" has "$T/out2" "proxd-claude FAILED health or subscription"
rm "$T/unsub-hub"

# The gauge still reads 1 after the restart, but the subscription time has not moved.
reset_units
timers
echo claude >"$T/stale-ts"
SUBSCRIBE_TIMEOUT=1 "$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all fails on a stale subscription time" ||
  ok "roll-all fails on a stale subscription time"
check "roll-all rolled back the hub with a stale subscription time" [ "$(img claude)" = "$OLD" ]
check "roll-all after a stale subscription time did not touch the hub after it" [ "$(img gemini)" = "$OLD" ]
check "roll-all after a stale subscription time never restarted gemini" [ "$(restarts)" = "restart proxd-codex restart proxd-claude restart proxd-claude " ]
check "roll-all reports the stale subscription as a failure" has "$T/out" "proxd-claude FAILED health or subscription"
check "roll-all logs the time it compared against" has "$T/out" "(subscribed at 1763700000.5 before the restart)"

# An exporter or prox-usage from before the subscription time series.
reset_units
timers
touch "$T/no-ts"
"$BIN/roll-all.sh" --approved "$NEW" >"$T/out" 2>&1 && bad "roll-all refuses without the subscription time series" ||
  ok "roll-all refuses without the subscription time series"
check "roll-all without the subscription time series restarted nothing" [ -z "$(restarts)" ]
check "roll-all says to deploy the new prox-usage and exporter" has "$T/out" "deploy the new prox-usage and proxd-exporter first"

echo "$PASSES passed, $FAILS failed"
[ "$FAILS" = 0 ]

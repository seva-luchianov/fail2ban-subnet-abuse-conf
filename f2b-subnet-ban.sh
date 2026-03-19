#!/usr/bin/env bash
set -u -o pipefail

IP="${1:-}"
MASK="${2:-}"
THRESHOLD="${3:-}"
WINDOW="${4:-}"
BLOCKTIME="${5:-}"
SETNAME="${6:-}"

STATE_DIR="/var/lib/fail2ban/subnet-agg"
STATE_FILE="${STATE_DIR}/events.log"
LOCK_FILE="${STATE_DIR}/lock"

log() {
  logger -t fail2ban-subnet -- "$*"
}

fail() {
  log "ERROR: $*"
  exit 0
}

log "START ip=${IP:-<empty>} mask=${MASK:-<empty>} threshold=${THRESHOLD:-<empty>} window=${WINDOW:-<empty>} blocktime=${BLOCKTIME:-<empty>} setname=${SETNAME:-<empty>}"

# Basic arg validation
[[ -n "$IP" && -n "$MASK" && -n "$THRESHOLD" && -n "$WINDOW" && -n "$BLOCKTIME" && -n "$SETNAME" ]] \
  || fail "missing required arguments"

[[ "$THRESHOLD" =~ ^[0-9]+$ ]] || fail "threshold is not numeric: $THRESHOLD"
[[ "$WINDOW" =~ ^[0-9]+$ ]]    || fail "window is not numeric: $WINDOW"
[[ "$BLOCKTIME" =~ ^[0-9]+$ ]] || fail "blocktime is not numeric: $BLOCKTIME"

mkdir -p "$STATE_DIR" || fail "cannot create state dir: $STATE_DIR"
touch "$STATE_FILE" "$LOCK_FILE" || fail "cannot touch state files in: $STATE_DIR"

# IPv4 only
if [[ ! "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  log "SKIP non-ipv4 ip=$IP"
  exit 0
fi

IFS='.' read -r o1 o2 o3 o4 <<< "$IP"

# Loose octet sanity
for o in "$o1" "$o2" "$o3" "$o4"; do
  [[ "$o" =~ ^[0-9]+$ ]] || fail "invalid octet: $o"
  (( o >= 0 && o <= 255 )) || fail "octet out of range: $o"
done

case "$MASK" in
  16) SUBNET="${o1}.${o2}.0.0/16" ;;
  24) SUBNET="${o1}.${o2}.${o3}.0/24" ;;
  *) fail "unsupported subnet mask: $MASK (supported: 16,24)" ;;
esac

NOW="$(date +%s)"
CUTOFF="$((NOW - WINDOW))"

log "DERIVED subnet=${SUBNET} now=${NOW} cutoff=${CUTOFF}"

(
  flock -x 9 || fail "failed to acquire lock: $LOCK_FILE"

  # Append event
  echo "${NOW} ${SUBNET} ${IP}" >> "$STATE_FILE" || fail "failed to append event to $STATE_FILE"

  # Prune old events
  awk -v c="$CUTOFF" '$1 >= c' "$STATE_FILE" > "${STATE_FILE}.tmp" || fail "awk prune failed"
  mv "${STATE_FILE}.tmp" "$STATE_FILE" || fail "failed to replace state file"

  # Count subnet hits in window
  COUNT="$(awk -v s="$SUBNET" '$2 == s {n++} END {print n+0}' "$STATE_FILE")" || fail "awk count failed"

  log "COUNT subnet=${SUBNET} count=${COUNT} threshold=${THRESHOLD} window=${WINDOW}s"

  if (( COUNT >= THRESHOLD )); then
    log "THRESHOLD_REACHED subnet=${SUBNET} count=${COUNT}; attempting ipset add"
    if ipset add "$SETNAME" "$SUBNET" timeout "$BLOCKTIME" -exist 2>/tmp/f2b-subnet-ipset.err; then
      log "BAN_APPLIED subnet=${SUBNET} set=${SETNAME} timeout=${BLOCKTIME}s count=${COUNT}"
    else
      ERR_MSG="$(tr '\n' ' ' < /tmp/f2b-subnet-ipset.err 2>/dev/null || true)"
      log "ERROR ipset add failed subnet=${SUBNET} set=${SETNAME} err='${ERR_MSG}'"
    fi
    rm -f /tmp/f2b-subnet-ipset.err
  else
    log "NO_BAN subnet=${SUBNET} count=${COUNT} (<${THRESHOLD})"
  fi
) 9>"$LOCK_FILE"

log "END ip=${IP} subnet=${SUBNET}"
exit 0
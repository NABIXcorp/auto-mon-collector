#!/bin/bash
# otel-kmsg.sh: kernel warnings and errors (OOM killer, hung tasks, disk / filesystem errors) for the collector
# (file_log/kmsg -> stream kernel). Installed as <prefix>/netconn/otel-kmsg.sh (root:root 755, the helpers' directory).
# Runs as the collector user in unit monitoring-kmsg, which (with monitoring-sshd) alone has the extra group
# systemd-journal: the collector process itself cannot read the journal. Reads ONLY kernel messages (-k) with
# priority warning or higher: what other services log is never touched.
#
# One JSON line per kernel message (journalctl -o json, fields MESSAGE + PRIORITY + journal timestamps).
# Polling with a cursor (every POLL seconds), not `journalctl -f`: a long-running follower missed lines after the
# journal changed under it (seen in CI 2026-10-08, sshd helper). The position is kept in <dir>/.cursor, so a restart
# loses nothing; the first start begins at the current end (no history). -k = this boot only.
#
# Usage: otel-kmsg.sh --poll   (service)   |   otel-kmsg.sh --stdout   (last 20 messages to the terminal, test)
set -u
OUT_DIR="${KMSG_DIR:-/opt/monitoring/data/kmsg}"
POLL="${KMSG_POLL:-10}"
JOURNAL=(journalctl -k -p warning -o json --output-fields=MESSAGE,PRIORITY --no-pager -q)

case "${1:-}" in
  --stdout) exec "${JOURNAL[@]}" -n 20 ;;
  --poll)
    mkdir -p "$OUT_DIR"
    cur="$(cat "$OUT_DIR/.cursor" 2>/dev/null || true)"
    # -o json carries the cursor in each line ("__CURSOR"): start after the newest kernel message
    [ -n "$cur" ] || cur="$("${JOURNAL[@]}" -n 1 2>/dev/null | sed -n 's/.*"__CURSOR" *: *"\([^"]*\)".*/\1/p' | tail -1)"
    since="$(date '+%Y-%m-%d %H:%M:%S')"   # used only while there is no kernel warning yet this boot
    while :; do
      if [ -n "$cur" ]; then out="$("${JOURNAL[@]}" --after-cursor="$cur" 2>/dev/null)"
      else out="$("${JOURNAL[@]}" --since "$since" 2>/dev/null)"; since="$(date '+%Y-%m-%d %H:%M:%S')"; fi
      if [ -n "$out" ]; then
        f="$OUT_DIR/kmsg-$(date +%Y%m%d).jsonl"
        if [ ! -e "$f" ]; then
          : >> "$f" && chmod 640 "$f"   # explicit mode: a default ACL on a parent overrides UMask
          find "$OUT_DIR" -name 'kmsg-*.jsonl' -mtime +1 -delete   # keep ~2 days
        fi
        printf '%s\n' "$out" >> "$f"
        new="$(printf '%s\n' "$out" | sed -n 's/.*"__CURSOR" *: *"\([^"]*\)".*/\1/p' | tail -1)"
        if [ -n "$new" ]; then cur="$new"; printf '%s' "$cur" > "$OUT_DIR/.cursor"; fi
      fi
      sleep "$POLL"
    done ;;
  *) echo "usage: $0 --stdout | --poll" >&2; exit 2 ;;
esac

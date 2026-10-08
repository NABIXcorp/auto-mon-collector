#!/bin/bash
# otel-kmsg.sh: kernel warnings and errors (OOM killer, hung tasks, disk / filesystem errors) for the collector
# (file_log/kmsg -> stream kernel). Installed as <prefix>/netconn/otel-kmsg.sh (root:root 755, the helpers' directory).
# Runs as the collector user in unit monitoring-kmsg, which alone has the extra group systemd-journal: the collector
# process itself cannot read the journal. Reads ONLY kernel messages (-k) with priority warning or higher, and no
# history (-n 0): what other services log is never touched.
#
# One JSON line per kernel message (journalctl -o json, fields MESSAGE + PRIORITY + journal timestamps).
# Usage: otel-kmsg.sh --follow   (service)   |   otel-kmsg.sh --stdout   (last 20 messages to the terminal, test)
set -u
OUT_DIR="${KMSG_DIR:-/opt/monitoring/data/kmsg}"
JOURNAL=(journalctl -k -p warning -o json --output-fields=MESSAGE,PRIORITY --no-pager)

case "${1:-}" in
  --stdout) exec "${JOURNAL[@]}" -n 20 ;;
  --follow)
    mkdir -p "$OUT_DIR"
    day=""
    "${JOURNAL[@]}" -n 0 -f | while IFS= read -r line; do
      today="$(date +%Y%m%d)"
      if [ "$today" != "$day" ]; then
        day="$today"
        find "$OUT_DIR" -name 'kmsg-*.jsonl' -mtime +1 -delete   # keep ~2 days
        # explicit mode: a default ACL on a parent directory overrides the unit's UMask (seen on CI runners)
        : >> "$OUT_DIR/kmsg-$day.jsonl" && chmod 640 "$OUT_DIR/kmsg-$day.jsonl"
      fi
      printf '%s\n' "$line" >> "$OUT_DIR/kmsg-$day.jsonl"
    done ;;
  *) echo "usage: $0 --stdout | --follow" >&2; exit 2 ;;
esac

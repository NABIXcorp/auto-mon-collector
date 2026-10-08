#!/bin/bash
# otel-sshd.sh: SSH logins (accepted / failed / invalid user / session closed) for the collector
# (file_log/sshd -> stream ssh). Installed as <prefix>/netconn/otel-sshd.sh (root:root 755). Runs as the collector
# user in unit monitoring-sshd, which alone (with monitoring-kmsg) has the group systemd-journal.
# Reads ONLY sshd's own messages (SYSLOG_IDENTIFIER sshd / sshd-session) and keeps only the login lines.
# Privacy: the name of an UNKNOWN user is replaced by *** before anything is written (people type their password
# into the user field: "Invalid user <password> from ..."). Never sudo or other services.
#
# Polling with a cursor (every POLL seconds: "everything after my last position"), not `journalctl -f`: a long-running
# follower missed lines after the journal changed under it (seen in CI 2026-10-08). The position is kept in
# <dir>/.cursor, so a restart loses nothing; the first start begins at the current end (no history).
#
# Usage: otel-sshd.sh --poll   (service)   |   otel-sshd.sh --stdout   (last 20 login lines, test)
set -u
OUT_DIR="${SSHD_DIR:-/opt/monitoring/data/sshd}"
POLL="${SSHD_POLL:-10}"
JOURNAL=(journalctl -t sshd -t sshd-session -o cat --no-pager -q)
KEEP='^(Accepted |Failed |Invalid user |Connection closed by (authenticating|invalid) user |Disconnected from (authenticating |invalid )?user |pam_unix\(sshd:session\): session (opened|closed) for user )'

filter() {
  grep -E "$KEEP" |
    sed -E 's/([Ii]nvalid user) ([^ ]+ )?(from )/\1 *** \3/; s/([Ii]nvalid user) [^ ]+ ([0-9a-fA-F.:]+ port)/\1 *** \2/' |
    # one JSON line: the message only (no quotes / backslashes / control characters survive)
    sed -E 's/[\\"]/ /g; s/[[:cntrl:]]//g; s/^(.*)$/{"msg":"\1"}/'
}

case "${1:-}" in
  --stdout) "${JOURNAL[@]}" -n 200 | filter | tail -20 ;;
  --poll)
    mkdir -p "$OUT_DIR"
    cur="$(cat "$OUT_DIR/.cursor" 2>/dev/null || true)"
    [ -n "$cur" ] || cur="$("${JOURNAL[@]}" -n 1 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p')"
    since="$(date '+%Y-%m-%d %H:%M:%S')"   # used only while sshd has never logged anything (no cursor yet)
    while :; do
      if [ -n "$cur" ]; then out="$("${JOURNAL[@]}" --show-cursor --after-cursor="$cur" 2>/dev/null)"
      else out="$("${JOURNAL[@]}" --show-cursor --since "$since" 2>/dev/null)"; since="$(date '+%Y-%m-%d %H:%M:%S')"; fi
      new="$(printf '%s\n' "$out" | sed -n 's/^-- cursor: //p' | tail -1)"
      lines="$(printf '%s\n' "$out" | grep -v '^-- cursor: ' | filter)"
      if [ -n "$lines" ]; then
        f="$OUT_DIR/sshd-$(date +%Y%m%d).jsonl"
        if [ ! -e "$f" ]; then
          : >> "$f" && chmod 640 "$f"   # explicit mode: a default ACL on a parent overrides UMask
          find "$OUT_DIR" -name 'sshd-*.jsonl' -mtime +1 -delete   # keep ~2 days
        fi
        printf '%s\n' "$lines" >> "$f"
      fi
      if [ -n "$new" ]; then cur="$new"; printf '%s' "$cur" > "$OUT_DIR/.cursor"; fi
      sleep "$POLL"
    done ;;
  *) echo "usage: $0 --stdout | --poll" >&2; exit 2 ;;
esac

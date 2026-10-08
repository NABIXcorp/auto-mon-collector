#!/bin/bash
# otel-sshd.sh: SSH logins (accepted / failed / invalid user / session closed) for the collector
# (file_log/sshd -> stream ssh). Installed as <prefix>/netconn/otel-sshd.sh (root:root 755). Runs as the collector
# user in unit monitoring-sshd, which alone (with monitoring-kmsg) has the group systemd-journal.
# Reads ONLY sshd's own messages (SYSLOG_IDENTIFIER sshd / sshd-session), no history (-n 0), and keeps only the login
# lines. Privacy: the name of an UNKNOWN user is replaced by *** before anything is written (people type their
# password into the user field: "Invalid user <password> from ..."). Never sudo or other services.
#
# Usage: otel-sshd.sh --follow   (service)   |   otel-sshd.sh --stdout   (last 20 login lines, test)
set -u
OUT_DIR="${SSHD_DIR:-/opt/monitoring/data/sshd}"
# stdbuf -oL: journalctl -o cat into a pipe holds lines back in follow mode (seen in CI: --stdout worked, -f wrote
# nothing); line buffering makes every login line go through at once
JOURNAL=(stdbuf -oL journalctl -t sshd -t sshd-session -o cat --no-pager)
KEEP='^(Accepted |Failed |Invalid user |Connection closed by (authenticating|invalid) user |Disconnected from (authenticating |invalid )?user |pam_unix\(sshd:session\): session (opened|closed) for user )'

filter() {
  grep --line-buffered -E "$KEEP" |
    sed -u -E 's/([Ii]nvalid user) ([^ ]+ )?(from )/\1 *** \3/; s/([Ii]nvalid user) [^ ]+ ([0-9a-fA-F.:]+ port)/\1 *** \2/' |
    # one JSON line: the message only (no quotes / backslashes / control characters survive)
    sed -u -E 's/[\\"]/ /g; s/[[:cntrl:]]//g; s/^(.*)$/{"msg":"\1"}/'
}

case "${1:-}" in
  --stdout) "${JOURNAL[@]}" -n 200 | filter | tail -20 ;;
  --follow)
    mkdir -p "$OUT_DIR"
    day=""
    "${JOURNAL[@]}" -n 0 -f | filter | while IFS= read -r line; do
      today="$(date +%Y%m%d)"
      if [ "$today" != "$day" ]; then
        day="$today"
        find "$OUT_DIR" -name 'sshd-*.jsonl' -mtime +1 -delete   # keep ~2 days
        : >> "$OUT_DIR/sshd-$day.jsonl" && chmod 640 "$OUT_DIR/sshd-$day.jsonl"
      fi
      printf '%s\n' "$line" >> "$OUT_DIR/sshd-$day.jsonl"
    done ;;
  *) echo "usage: $0 --stdout | --follow" >&2; exit 2 ;;
esac

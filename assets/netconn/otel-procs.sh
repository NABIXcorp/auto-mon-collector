#!/bin/bash
# otel-procs.sh: top processes by CPU and by memory (RSS), for the collector (file_log/procs -> stream processes).
# Installed as <prefix>/netconn/otel-procs.sh (root:root 755). Runs as the collector user in unit monitoring-procs:
# no root, plain `ps`. Only the COMMAND NAME is written, never the arguments (they can hold passwords).
#
# Every INTERVAL seconds: two `ps` snapshots WINDOW seconds apart -> CPU % over the window (100 = one core; ps's own
# %cpu is the lifetime average and hides a process that just went wild). One JSON line per process that is in the
# top TOP by CPU or by RSS: pid, user, comm, rss_kb, cpu_pct, etime_s, top ("cpu", "rss" or "cpu,rss").
#
# Usage: otel-procs.sh --loop 60   (service)   |   otel-procs.sh --stdout   (one sample to the terminal, test)
set -u
OUT_DIR="${PROCS_DIR:-/opt/monitoring/data/procs}"
TOP="${PROCS_TOP:-10}"
WINDOW="${PROCS_WINDOW:-15}"

snap() { ps -eo pid=,user:32=,rss=,times=,etimes=,comm= 2>/dev/null; }

sample() {
  local a b
  a="$(snap)"
  sleep "$WINDOW"
  b="$(snap)"
  # plain POSIX awk (no gawk extensions: mawk on Debian / Ubuntu)
  awk -v ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -v top="$TOP" -v win="$WINDOW" '
    function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
    FNR == NR { t0[$1] = $4; next }
    {
      comm = $6; for (i = 7; i <= NF; i++) comm = comm " " $i
      if ($1 in t0) cpu = ($4 - t0[$1]) * 100.0 / win
      else if ($5 > 0 && $5 <= win) cpu = $4 * 100.0 / $5     # started inside the window
      else cpu = 0
      n++; P[n] = $1; U[n] = $2; R[n] = $3 + 0; C[n] = cpu; E[n] = $5; M[n] = comm
    }
    END {
      for (k = 1; k <= top && k <= n; k++) {          # top by CPU, then top by RSS (selection, n is small)
        bc = 0; br = 0
        for (i = 1; i <= n; i++) {
          if (!(i in tc) && (bc == 0 || C[i] > C[bc])) bc = i
          if (!(i in tr) && (br == 0 || R[i] > R[br])) br = i
        }
        if (bc) tc[bc] = 1
        if (br) tr[br] = 1
      }
      for (i = 1; i <= n; i++) {
        if (!(i in tc) && !(i in tr)) continue
        t = (i in tc) ? ((i in tr) ? "cpu,rss" : "cpu") : "rss"
        printf "{\"time\":\"%s\",\"pid\":%d,\"user\":\"%s\",\"comm\":\"%s\",\"rss_kb\":%d,\"cpu_pct\":%.1f,\"etime_s\":%d,\"top\":\"%s\"}\n",
               ts, P[i], esc(U[i]), esc(M[i]), R[i], C[i], E[i], t
      }
    }' <(printf '%s\n' "$a") <(printf '%s\n' "$b")
}

case "${1:-}" in
  --stdout) sample ;;
  --loop)
    interval="${2:-60}"
    mkdir -p "$OUT_DIR"
    while :; do
      f="$OUT_DIR/procs-$(date +%Y%m%d).jsonl"
      if [ ! -e "$f" ]; then
        : >> "$f" && chmod 640 "$f"   # explicit mode: a default ACL on a parent overrides UMask
        find "$OUT_DIR" -name 'procs-*.jsonl' -mtime +1 -delete   # keep ~2 days
      fi
      sample >> "$f"
      sleep $(( interval > WINDOW ? interval - WINDOW : 1 ))
    done ;;
  *) echo "usage: $0 --stdout | --loop SECONDS" >&2; exit 2 ;;
esac

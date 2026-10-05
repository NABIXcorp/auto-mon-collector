#!/bin/bash
# otel-netconn.sh: TCP connection counts per watched port, for the collector (file_log -> stream netconn).
# Installed as <prefix>/netconn/otel-netconn.sh (root:root 755). Runs as the collector user (unit monitoring-netconn).
# No root needed: plain `ss -tan` (no -p, processes are not read).
#
# One JSON line per port and direction every INTERVAL seconds:
#   direction "in"  = connections TO this port on this host   (e.g. clients -> listener 1521, nginx -> 8080)
#   direction "out" = connections FROM this host to that port (e.g. Tomcat pool / collector -> Oracle 1521)
# CLOSE_WAIT = the other side closed, our process did not close its socket (leak / hung thread).
#
# Usage: otel-netconn.sh --loop 30   (service)   |   otel-netconn.sh --stdout   (one sample to the terminal, test)
set -u
PORTS="${NETCONN_PORTS:-1521 8080 443}"
OUT_DIR="${NETCONN_DIR:-/opt/monitoring/data/netconn}"

sample() {
  ss -Htan | awk -v ports="$PORTS" -v ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
    BEGIN { n = split(ports, p, " "); for (i = 1; i <= n; i++) watch[p[i]] = 1 }
    $1 == "LISTEN" { next }
    {
      st = $1; lp = $4; rp = $5; sub(/.*:/, "", lp); sub(/.*:/, "", rp)
      if (lp in watch) { c[lp ",in," st]++; t[lp ",in"]++ }
      if (rp in watch) { c[rp ",out," st]++; t[rp ",out"]++ }
    }
    END {
      for (i = 1; i <= n; i++) for (d = 1; d <= 2; d++) {
        k = p[i] "," (d == 1 ? "in" : "out")
        e = c[k ",ESTAB"] + 0; cw = c[k ",CLOSE-WAIT"] + 0; tw = c[k ",TIME-WAIT"] + 0
        printf "{\"time\":\"%s\",\"port\":\"%s\",\"direction\":\"%s\",\"established\":%d,\"close_wait\":%d,\"time_wait\":%d,\"other\":%d}\n",
               ts, p[i], (d == 1 ? "in" : "out"), e, cw, tw, t[k] - e - cw - tw
      }
    }'
}

case "${1:-}" in
  --stdout) sample ;;
  --loop)
    interval="${2:-30}"
    mkdir -p "$OUT_DIR"
    while :; do
      sample >> "$OUT_DIR/netconn-$(date +%Y%m%d).jsonl"
      find "$OUT_DIR" -name 'netconn-*.jsonl' -mtime +1 -delete   # keep ~2 days
      sleep "$interval"
    done ;;
  *) echo "usage: $0 --stdout | --loop SECONDS" >&2; exit 2 ;;
esac

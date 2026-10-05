#!/usr/bin/env bash
# render-get.sh PUBKEY.pem OUT: write get.sh with the release public key embedded (release + CI test).
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 PUBKEY.pem OUT" >&2; exit 2; }
grep -q 'BEGIN PUBLIC KEY' "$1" || { echo "$1 is not a PEM public key" >&2; exit 1; }
awk 'FNR==NR { k = k $0 "\n"; next } /^@AMC_PUBKEY@$/ { printf "%s", k; next } { print }' "$1" "$(dirname "$0")/get.sh.tmpl" > "$2"
chmod 755 "$2"
! grep -q '@AMC_PUBKEY@' "$2" || { echo "key not embedded" >&2; exit 1; }

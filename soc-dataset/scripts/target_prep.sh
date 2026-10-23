#!/bin/bash
# Re-enable password auth (GCP guest agent resets it on reboot) and ensure decoy accounts exist.
sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null
sudo useradd -m -s /bin/bash svc_backup 2>/dev/null; echo 'svc_backup:Winter2025' | sudo chpasswd
sudo useradd -m -s /bin/bash svc_reports 2>/dev/null; echo 'svc_reports:Bilbo2026' | sudo chpasswd
sudo useradd -m -s /bin/bash testuser 2>/dev/null; echo 'testuser:Sup3rS3cure!2026' | sudo chpasswd
echo "PasswordAuth: $(sudo grep -c '^PasswordAuthentication yes' /etc/ssh/sshd_config)"
curl -s -o /dev/null -w "app_http:%{http_code}\n" http://127.0.0.1/
sudo systemctl is-active wazuh-agent vuln-app nginx

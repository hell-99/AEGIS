#!/bin/bash
echo "[AEGIS] Resetting for fresh demo..."
sudo iptables -F INPUT
echo '[]' | sudo tee /tmp/aegis_blocked.json
sudo sh -c '> /home/twi/AEGIS/ids-ips/alerts.log'
sudo sh -c '> /home/twi/AEGIS/ids-ips/ml_alerts.log'
sudo sh -c '> /home/twi/AEGIS/ids-ips/ensemble_alerts.log'
echo '{}' | sudo tee /tmp/aegis_votes.json
echo "[AEGIS] Reset complete — ready for demo!"
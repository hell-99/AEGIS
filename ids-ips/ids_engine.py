from scapy.all import sniff, IP, TCP, ICMP
from datetime import datetime
import collections
import json
import sys
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import apply_block_rule, create_policy_entry
from ensemble import cast_vote

connection_tracker = collections.defaultdict(list)
last_alert_time = collections.defaultdict(float)
ALERT_LOG = "/home/twi/AEGIS/ids-ips/alerts.log"

def log_alert(alert_type, src_ip, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT | {alert_type} | SRC: {src_ip} | {details}"
    print(f"\033[91m{message}\033[0m")
    with open(ALERT_LOG, "a") as f:
        f.write(message + "\n")
    policy_map = {
        "ICMP FLOOD": "POL-001",
        "SYN FLOOD": "POL-002",
        "PORT SCAN": "POL-003"
    }
    policy_id = policy_map.get(alert_type, "POL-UNKNOWN")
    create_policy_entry(
        action="ALERT",
        src_ip=src_ip,
        rule=policy_id,
        reason=f"{alert_type}: {details}"
    )

def block_ip(src_ip, reason):
    apply_block_rule(src_ip, reason)

def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        src = packet[IP].src
        key = f"syn_{src}"
        now = datetime.now().timestamp()
        connection_tracker[key].append(now)
        connection_tracker[key] = [t for t in connection_tracker[key] if now - t < 5]
        if len(connection_tracker[key]) > 20:
            if now - last_alert_time[key] >= 0.5:
                last_alert_time[key] = now
                log_alert("SYN FLOOD", src, f"packets={len(connection_tracker[key])} in 5s")

def detect_port_scan(packet):
    if packet.haslayer(TCP):
        src = packet[IP].src
        dst_port = packet[TCP].dport
        key = f"portscan_{src}"
        now = datetime.now().timestamp()
        connection_tracker[key].append(dst_port)
        unique_ports = set(connection_tracker[key][-50:])
        if len(unique_ports) > 15:
            if now - last_alert_time[key] >= 3:
                last_alert_time[key] = now
                log_alert("PORT SCAN", src, f"unique_ports={len(unique_ports)}")

def detect_icmp_flood(packet):
    if packet.haslayer(ICMP):
        src = packet[IP].src
        key = f"icmp_{src}"
        now = datetime.now().timestamp()
        connection_tracker[key].append(now)
        connection_tracker[key] = [t for t in connection_tracker[key] if now - t < 3]
        if len(connection_tracker[key]) > 10:
            if now - last_alert_time[key] >= 1:
                last_alert_time[key] = now
                log_alert("ICMP FLOOD", src, f"packets={len(connection_tracker[key])} in 3s")
                # cast_vote("rule_based", src, "BLOCK", f"ICMP FLOOD: {len(connection_tracker[key])} packets in 3s")
                # NO block_ip here — ensemble handles it

def packet_callback(packet):
    if packet.haslayer(IP):
        detect_syn_flood(packet)
        detect_port_scan(packet)
        detect_icmp_flood(packet)

print("[AEGIS-IDS] Starting intrusion detection engine...")
print("[AEGIS-IDS] Monitoring all interfaces. Press Ctrl+C to stop.")
iface = sys.argv[1] if len(sys.argv) > 1 else "s1-eth1"
print(f"[AEGIS-IDS] Sniffing on interface: {iface}")
sniff(filter="ip", promisc=True, prn=packet_callback, store=0, iface=iface)
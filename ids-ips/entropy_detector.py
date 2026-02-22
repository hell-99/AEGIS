import math
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import create_policy_entry, apply_block_rule

ALERT_LOG = "/home/twi/AEGIS/ids-ips/entropy_alerts.log"
HIGH_ENTROPY_THRESHOLD = 7.2  # Close to 8.0 = highly random = likely encrypted/exfil
SUSPICIOUS_THRESHOLD   = 6.0  # Worth flagging
MIN_PAYLOAD_BYTES      = 32   # Ignore tiny packets

# Track entropy history per IP for trend analysis
entropy_history = defaultdict(list)
blocked_ips = set()

def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    Returns value between 0 (perfectly ordered) and 8.0 (perfectly random).
    """
    if not data:
        return 0.0
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def classify_traffic(entropy: float, dst_port: int) -> str:
    """Classify traffic based on entropy and destination port"""
    known_encrypted_ports = {443, 8443, 993, 995, 465, 22}
    if dst_port in known_encrypted_ports:
        return "KNOWN-ENCRYPTED"   # Expected — HTTPS, SSH, etc.
    if entropy >= HIGH_ENTROPY_THRESHOLD:
        return "SUSPICIOUS-EXFIL"  # High entropy on unexpected port
    if entropy >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "NORMAL"

def log_entropy_alert(src_ip, dst_port, entropy, classification, payload_size):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (f"[{timestamp}] ENTROPY-ALERT | SRC: {src_ip} | "
           f"port={dst_port} | entropy={entropy} | "
           f"size={payload_size}B | class={classification}")
    color = "\033[91m" if "EXFIL" in classification else "\033[93m"
    print(f"{color}{msg}\033[0m")
    with open(ALERT_LOG, "a") as f:
        f.write(msg + "\n")
    create_policy_entry("ENTROPY-DETECT", src_ip, classification,
                       f"entropy={entropy} port={dst_port}")

def analyze_trend(ip):
    """
    Detect slow exfiltration — attacker sends small high-entropy
    packets over time to evade threshold detection
    """
    history = entropy_history[ip]
    if len(history) < 5:
        return
    recent = history[-5:]
    avg_entropy = sum(recent) / len(recent)
    if avg_entropy > 6.5:
        log_entropy_alert(ip, 0, avg_entropy, "SLOW-EXFIL-TREND", 0)
        if ip not in blocked_ips:
            apply_block_rule(ip, f"Slow exfiltration trend detected — avg entropy={avg_entropy:.2f}")
            blocked_ips.add(ip)

def packet_callback(packet):
    if not packet.haslayer(IP):
        return
    if not packet.haslayer(Raw):
        return  # No payload to analyze

    payload = bytes(packet[Raw].load)
    if len(payload) < MIN_PAYLOAD_BYTES:
        return

    src_ip = packet[IP].src
    dst_port = 0
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    entropy = shannon_entropy(payload)
    classification = classify_traffic(entropy, dst_port)
    entropy_history[src_ip].append(entropy)

    if classification in ("SUSPICIOUS-EXFIL", "SUSPICIOUS"):
        log_entropy_alert(src_ip, dst_port, entropy, classification, len(payload))
        if classification == "SUSPICIOUS-EXFIL" and src_ip not in blocked_ips:
            apply_block_rule(src_ip, f"High entropy payload detected — possible C2/exfil")
            blocked_ips.add(src_ip)

    # Check for slow exfiltration trend
    analyze_trend(src_ip)

def stats_loop():
    """Print entropy statistics every 30 seconds"""
    while True:
        time.sleep(30)
        if entropy_history:
            print(f"\n[AEGIS-ENTROPY] === Statistics ===")
            for ip, history in entropy_history.items():
                if history:
                    avg = sum(history) / len(history)
                    peak = max(history)
                    print(f"[AEGIS-ENTROPY] {ip} | samples={len(history)} | avg={avg:.2f} | peak={peak:.2f}")
            print()

if __name__ == "__main__":
    print("=" * 60)
    print("AEGIS PAYLOAD ENTROPY ANALYSIS ENGINE")
    print("Detects: C2 traffic, data exfiltration, encrypted tunnels")
    print(f"Thresholds: suspicious={SUSPICIOUS_THRESHOLD} | high={HIGH_ENTROPY_THRESHOLD}")
    print("=" * 60)

    iface = sys.argv[1] if len(sys.argv) > 1 else "s1-eth1"
    print(f"\n[AEGIS-ENTROPY] Analyzing payload entropy on {iface}")
    print("[AEGIS-ENTROPY] Monitoring for C2 and exfiltration patterns...\n")

    stats = threading.Thread(target=stats_loop, daemon=True)
    stats.start()

    sniff(filter="ip", promisc=True, prn=packet_callback,
          store=0, iface=iface)
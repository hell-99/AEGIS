import sys
import numpy as np
import os
import threading
import time
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scapy.all import sniff, IP, TCP, ICMP, UDP
from datetime import datetime
from collections import defaultdict
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import apply_block_rule, create_policy_entry

MODEL_PATH = "/home/twi/AEGIS/ids-ips/aegis_model.pkl"
SCALER_PATH = "/home/twi/AEGIS/ids-ips/aegis_scaler.pkl"
ALERT_LOG   = "/home/twi/AEGIS/ids-ips/ml_alerts.log"
WINDOW_SEC  = 5

traffic_windows = defaultdict(lambda: {
    "packets": [], "dst_ports": set(),
    "syn_count": 0, "icmp_count": 0,
    "udp_count": 0, "sizes": []
})

blocked_ips = set()
model = None
scaler = None

def extract_features(ip):
    w = traffic_windows[ip]
    total = max(len(w["packets"]), 1)
    return [total, len(w["dst_ports"]), w["syn_count"]/total,
            w["icmp_count"]/total, np.mean(w["sizes"]) if w["sizes"] else 0,
            w["udp_count"]/total]

def load_model():
    global model, scaler
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("[AEGIS-ML] Loaded existing model from disk")
        return True
    return False

def train_model():
    global model, scaler
    print("[AEGIS-ML] Training model...")
    X = np.array([[np.random.randint(1,15), np.random.randint(1,4),
                   np.random.uniform(0,.1), np.random.uniform(0,.05),
                   np.random.uniform(64,1500), np.random.uniform(0,.1)]
                  for _ in range(2000)])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X_scaled)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print("[AEGIS-ML] Model trained!")

def log_ml_alert(ip, features, score, action):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (f"[{ts}] ML-ALERT | SRC: {ip} | score={score:.4f} | "
           f"pkts={features[0]:.0f} | ports={features[1]:.0f} | "
           f"syn_ratio={features[2]:.2f} | action={action}")
    print(f"\033[95m{msg}\033[0m")
    with open(ALERT_LOG, "a") as f:
        f.write(msg + "\n")
    create_policy_entry("ML-DETECT", ip, "ISOLATION-FOREST", msg)

def analyze_ip(ip):
    if ip in blocked_ips:
        return
    features = extract_features(ip)
    X_scaled = scaler.transform([features])
    prediction = model.predict(X_scaled)[0]
    score = model.score_samples(X_scaled)[0]
    if prediction == -1:
        action = "BLOCKED" if features[0] > 20 else "ALERTED"
        log_ml_alert(ip, features, score, action)
        # if action == "BLOCKED" and ip not in blocked_ips:
        #     apply_block_rule(ip, f"ML anomaly score={score:.4f}")
        #     blocked_ips.add(ip)

def packet_callback(packet):
    if not packet.haslayer(IP):
        return
    ip = packet[IP].src
    now = time.time()
    w = traffic_windows[ip]
    w["packets"].append(now)
    w["sizes"].append(len(packet))
    if packet.haslayer(TCP):
        w["dst_ports"].add(packet[TCP].dport)
        if packet[TCP].flags == 'S':
            w["syn_count"] += 1
    if packet.haslayer(ICMP):
        w["icmp_count"] += 1
    if packet.haslayer(UDP):
        w["udp_count"] += 1
        w["dst_ports"].add(packet[UDP].dport)
    cutoff = now - WINDOW_SEC
    w["packets"] = [t for t in w["packets"] if t > cutoff]
    if len(w["packets"]) % 10 == 0:
        analyze_ip(ip)

if __name__ == "__main__":
    print("="*60)
    print("AEGIS ML-BASED ANOMALY DETECTION ENGINE")
    print("Algorithm: Isolation Forest (Unsupervised)")
    print("="*60)
    if not load_model():
        train_model()
    iface = sys.argv[1] if len(sys.argv) > 1 else "s1-eth1"
    print(f"\n[AEGIS-ML] Starting anomaly detection on {iface}")
    print("[AEGIS-ML] Monitoring traffic... (press Ctrl+C to stop)\n")
    sniff(filter="ip", promisc=True, prn=packet_callback, store=0, iface=iface)
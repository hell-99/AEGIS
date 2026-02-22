import numpy as np
import joblib
import sys
import time
from collections import defaultdict
from datetime import datetime
from ensemble import cast_vote
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import create_policy_entry, apply_block_rule

MODEL_PATH   = "/home/twi/AEGIS/ids-ips/cicids_model.pkl"
SCALER_PATH  = "/home/twi/AEGIS/ids-ips/cicids_scaler.pkl"
ENCODER_PATH = "/home/twi/AEGIS/ids-ips/cicids_encoder.pkl"
ALERT_LOG    = "/home/twi/AEGIS/ids-ips/cicids_live_alerts.log"

model   = joblib.load(MODEL_PATH)
scaler  = joblib.load(SCALER_PATH)
encoder = joblib.load(ENCODER_PATH)

print("[CICIDS-LIVE] Model loaded!")
print(f"[CICIDS-LIVE] Detecting: {list(encoder.classes_)}")

# Flow tracker — collects packets per (src,dst,port) tuple
flows = defaultdict(lambda: {
    "start": time.time(),
    "fwd_packets": [], "bwd_packets": [],
    "fwd_lengths": [], "bwd_lengths": [],
    "dst_port": 0, "syn": 0, "fin": 0,
    "psh": 0, "ack": 0,
    "fwd_iat": [], "bwd_iat": [],
    "last_fwd": None, "last_bwd": None,
    "init_win_fwd": 0, "init_win_bwd": 0,
})

blocked = set()
FLOW_TIMEOUT = 2  # seconds

def extract_flow_features(flow):
    """
    Extract the 52 CICIDS2017 features from a flow.
    We compute approximations for features we can derive from Scapy.
    """
    fwd = flow["fwd_lengths"] or [0]
    bwd = flow["bwd_lengths"] or [0]
    all_pkts = fwd + bwd or [0]
    fwd_iat = flow["fwd_iat"] or [0]
    bwd_iat = flow["bwd_iat"] or [0]
    duration = max(time.time() - flow["start"], 0.001)
    total_fwd = len(flow["fwd_packets"])
    total_bwd = len(flow["bwd_packets"])
    total_pkts = max(total_fwd + total_bwd, 1)

    features = [
        flow["dst_port"],                          # Destination Port
        duration * 1e6,                            # Flow Duration (microseconds)
        total_fwd,                                 # Total Fwd Packets
        sum(fwd),                                  # Total Length of Fwd Packets
        max(fwd),                                  # Fwd Packet Length Max
        min(fwd),                                  # Fwd Packet Length Min
        np.mean(fwd),                              # Fwd Packet Length Mean
        np.std(fwd),                               # Fwd Packet Length Std
        max(bwd),                                  # Bwd Packet Length Max
        min(bwd),                                  # Bwd Packet Length Min
        np.mean(bwd),                              # Bwd Packet Length Mean
        np.std(bwd),                               # Bwd Packet Length Std
        sum(all_pkts) / duration,                  # Flow Bytes/s
        total_pkts / duration,                     # Flow Packets/s
        np.mean(fwd_iat + bwd_iat),                # Flow IAT Mean
        np.std(fwd_iat + bwd_iat),                 # Flow IAT Std
        max(fwd_iat + bwd_iat),                    # Flow IAT Max
        min(fwd_iat + bwd_iat),                    # Flow IAT Min
        sum(fwd_iat),                              # Fwd IAT Total
        np.mean(fwd_iat),                          # Fwd IAT Mean
        np.std(fwd_iat),                           # Fwd IAT Std
        max(fwd_iat),                              # Fwd IAT Max
        min(fwd_iat),                              # Fwd IAT Min
        sum(bwd_iat),                              # Bwd IAT Total
        np.mean(bwd_iat),                          # Bwd IAT Mean
        np.std(bwd_iat),                           # Bwd IAT Std
        max(bwd_iat),                              # Bwd IAT Max
        min(bwd_iat),                              # Bwd IAT Min
        total_fwd * 20,                            # Fwd Header Length
        total_bwd * 20,                            # Bwd Header Length
        total_fwd / duration,                      # Fwd Packets/s
        total_bwd / duration,                      # Bwd Packets/s
        min(all_pkts),                             # Min Packet Length
        max(all_pkts),                             # Max Packet Length
        np.mean(all_pkts),                         # Packet Length Mean
        np.std(all_pkts),                          # Packet Length Std
        np.var(all_pkts),                          # Packet Length Variance
        flow["fin"],                               # FIN Flag Count
        flow["psh"],                               # PSH Flag Count
        flow["ack"],                               # ACK Flag Count
        np.mean(all_pkts),                         # Average Packet Size
        sum(fwd),                                  # Subflow Fwd Bytes
        flow["init_win_fwd"],                      # Init_Win_bytes_forward
        flow["init_win_bwd"],                      # Init_Win_bytes_backward
        total_fwd,                                 # act_data_pkt_fwd
        20,                                        # min_seg_size_forward
        duration * 1e6 / max(total_pkts, 1),       # Active Mean
        duration * 1e6,                            # Active Max
        0,                                         # Active Min
        duration * 1e6 / max(total_pkts, 1),       # Idle Mean
        duration * 1e6,                            # Idle Max
        0,                                         # Idle Min
    ]
    return features

def classify_flow(flow_key, flow):
    src_ip = flow_key[0]
    if src_ip in blocked:
        return

    features = extract_flow_features(flow)
    X = np.array([features])

    try:
        import pandas as pd
        feature_names = scaler.feature_names_in_
        X_df = pd.DataFrame(X, columns=feature_names)
        X_scaled = scaler.transform(X_df)
        prediction = model.predict(X_scaled)[0]
        label = encoder.inverse_transform([prediction])[0]
        proba = model.predict_proba(X_scaled)[0].max()

        # Always cast a vote — outside the if block
        vote = "BLOCK" if label != "Normal Traffic" else "ALERT"
        cast_vote("cicids", src_ip, vote, f"CICIDS: {label} ({proba:.2%})")

        if label != "Normal Traffic":
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            msg = (f"[{timestamp}] CICIDS-ALERT | "
                   f"SRC: {src_ip} | "
                   f"ATTACK: {label} | "
                   f"confidence={proba:.2%} | "
                   f"port={flow['dst_port']}")
            print(f"\033[95m{msg}\033[0m")
            with open("/home/twi/AEGIS/ids-ips/cicids_alerts.log", "a") as f:
                f.write(msg + "\n")
            create_policy_entry("CICIDS-DETECT", src_ip, label,
                              f"confidence={proba:.2%}")

            if proba > 0.85 and label in ("DDoS", "DoS", "Bots"):
                apply_block_rule(src_ip, f"CICIDS model: {label} ({proba:.2%})")
                blocked.add(src_ip)
                print(f"\033[91m[CICIDS-LIVE] AUTO-BLOCKED {src_ip} — {label}\033[0m")

    except Exception as e:
        print(f"[ERROR] {e}")

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    now = time.time()
    size = len(packet)
    dst_port = 0

    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        flow_key = (src, dst, dst_port, "TCP")
        flow = flows[flow_key]
        flow["dst_port"] = dst_port

        flags = packet[TCP].flags
        if "S" in str(flags): flow["syn"] += 1
        if "F" in str(flags): flow["fin"] += 1
        if "P" in str(flags): flow["psh"] += 1
        if "A" in str(flags): flow["ack"] += 1
        if flow["init_win_fwd"] == 0:
            flow["init_win_fwd"] = packet[TCP].window

        flow["fwd_packets"].append(now)
        flow["fwd_lengths"].append(size)
        if flow["last_fwd"]:
            flow["fwd_iat"].append(now - flow["last_fwd"])
        flow["last_fwd"] = now

    elif packet.haslayer(ICMP):
        flow_key = (src, dst, 0, "ICMP")
        flow = flows[flow_key]
        flow["fwd_packets"].append(now)
        flow["fwd_lengths"].append(size)
        if flow["last_fwd"]:
            flow["fwd_iat"].append(now - flow["last_fwd"])
        flow["last_fwd"] = now

    else:
        return

    # Classify flow every 20 packets
    if len(flow["fwd_packets"]) % 5 == 0:
        classify_flow(flow_key, flow)

    # Timeout old flows
    for key in list(flows.keys()):
        if time.time() - flows[key]["start"] > FLOW_TIMEOUT:
            classify_flow(key, flows[key])
            del flows[key]

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "s1-eth1"
    print(f"[CICIDS-LIVE] Starting live classification on {iface}")
    print("[CICIDS-LIVE] Monitoring all flows...\n")
    sniff(filter="ip", promisc=True, prn=packet_callback,
          store=0, iface=iface)
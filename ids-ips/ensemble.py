import json
import os
import re
import time
import threading
import requests
from datetime import datetime
from collections import defaultdict
import sys
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import apply_block_rule, create_policy_entry
sys.path.append('/home/twi/AEGIS/crypto')
from pqc_keys import sign_message, load_public_key

VOTES_FILE   = "/tmp/aegis_votes.json"
BLOCKED_FILE = "/tmp/aegis_blocked.json"
ALERT_LOG    = "/home/twi/AEGIS/ids-ips/ensemble_alerts.log"
IDS_LOG      = "/home/twi/AEGIS/ids-ips/alerts.log"
ML_LOG       = "/home/twi/AEGIS/ids-ips/ml_alerts.log"
VOTE_WINDOW  = 10
lock         = threading.Lock()

def load_votes():
    try:
        with open(VOTES_FILE) as f:
            return json.load(f)
    except:
        return {}

def save_votes(votes):
    with open(VOTES_FILE, "w") as f:
        json.dump(votes, f)

def load_blocked():
    try:
        with open(BLOCKED_FILE) as f:
            return json.load(f)
    except:
        return []

def save_blocked(blocked):
    with open(BLOCKED_FILE, "w") as f:
        json.dump(blocked, f)

def cast_vote(detector: str, src_ip: str, verdict: str, reason: str):
    with lock:
        votes = load_votes()
        now = time.time()

        if src_ip not in votes:
            votes[src_ip] = {}

        # Clean expired votes
        votes[src_ip] = {
            d: v for d, v in votes[src_ip].items()
            if now - v["time"] < VOTE_WINDOW
        }

        # Record vote
        votes[src_ip][detector] = {
            "verdict": verdict,
            "reason": reason,
            "time": now
        }
        save_votes(votes)

        # Evaluate
        current = votes[src_ip]
        blocked = load_blocked()

        if src_ip in blocked:
            return

        block_voters = [d for d, v in current.items() if v["verdict"] == "BLOCK"]
        block_count  = len(block_voters)
        total        = len(current)

        if block_count >= 2:
            time.sleep(8)
            votes = load_votes()
            if src_ip in votes:
                current = votes[src_ip]
                block_voters = [d for d, v in current.items() if v["verdict"] == "BLOCK"]
                block_count = len(block_voters)

            confidence = "HIGH" if block_count == 3 else "MEDIUM"
            reasons    = [current[d]["reason"] for d in block_voters]
            timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            msg = (f"[{timestamp}] ENSEMBLE-BLOCK | "
                   f"SRC: {src_ip} | "
                   f"confidence={confidence} | "
                   f"voters={block_voters} | "
                   f"reasons={' | '.join(reasons)}")

            print(f"\033[91m{'='*60}\033[0m")
            print(f"\033[91m{msg}\033[0m")
            print(f"\033[91m{'='*60}\033[0m")

            with open(ALERT_LOG, "a") as f:
                f.write(msg + "\n")

            create_policy_entry(
                "ENSEMBLE-BLOCK", src_ip,
                f"{confidence}-CONFIDENCE",
                f"voters={block_voters}"
            )
            apply_block_rule(src_ip, f"Ensemble: {confidence} confidence — {block_voters}")

            try:
                payload = json.dumps({
                    "src_ip": src_ip,
                    "action": "BLOCK",
                    "confidence": confidence,
                    "voters": block_voters,
                    "reasons": reasons,
                    "timestamp": timestamp
                }).encode()

                signature = sign_message(payload)

                requests.post("http://192.168.49.2:30080/receive-alert", json={
                    "payload": payload.decode(),
                    "signature": signature.hex(),
                    "public_key": load_public_key().hex(),
                    "pqc_verified": True,
                    "src_ip": src_ip,
                    "action": "BLOCK",
                    "confidence": confidence,
                    "voters": block_voters,
                    "reasons": reasons,
                    "timestamp": timestamp
                }, timeout=3)
                print(f"\033[92m[ENSEMBLE] Alert signed with Dilithium3 and forwarded to K8s ✓\033[0m")
            except Exception as e:
                print(f"[ENSEMBLE] K8s forward failed: {e}")

            blocked.append(src_ip)
            save_blocked(blocked)

            del votes[src_ip]
            save_votes(votes)

        elif block_count == 1 and total >= 2:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\033[93m[{timestamp}] ENSEMBLE-ALERT | SRC: {src_ip} | "
                  f"1/{total} voted BLOCK — monitoring\033[0m")


def watch_ids_alerts():
    """Watch rule-based IDS alert log"""
    print("[ENSEMBLE] Watching IDS alerts...")
    seen = 0
    while True:
        try:
            with open(IDS_LOG) as f:
                lines = f.readlines()
            for line in lines[seen:]:
                line = line.strip()
                if not line:
                    continue
                m = re.search(r'SRC:\s*([\d.]+)', line)
                if not m:
                    continue
                src_ip = m.group(1)
                if "ICMP FLOOD" in line:
                    detail = line.split("|")[-1].strip() if "|" in line else line
                    cast_vote("rule_based", src_ip, "BLOCK", f"ICMP FLOOD: {detail}")
                elif "SYN FLOOD" in line:
                    cast_vote("rule_based", src_ip, "BLOCK", "SYN FLOOD detected")
                elif "PORT SCAN" in line:
                    cast_vote("rule_based", src_ip, "ALERT", "PORT SCAN detected")
            seen = len(lines)
        except FileNotFoundError:
            pass
        time.sleep(2)


def watch_ml_alerts():
    """Watch ML anomaly detection log"""
    print("[ENSEMBLE] Watching ML alerts...")
    seen = 0
    while True:
        try:
            with open(ML_LOG) as f:
                lines = f.readlines()
            for line in lines[seen:]:
                line = line.strip()
                if not line:
                    continue
                m = re.search(r'SRC:\s*([\d.]+)', line)
                if not m:
                    continue
                src_ip = m.group(1)
                score_m = re.search(r'score=([-\d.]+)', line)
                score = float(score_m.group(1)) if score_m else -1.0
                if "BLOCKED" in line or score < -0.5:
                    cast_vote("isolation_forest", src_ip, "BLOCK",
                              f"ML anomaly score={score:.4f}")
                else:
                    cast_vote("isolation_forest", src_ip, "ALERT",
                              f"ML anomaly score={score:.4f}")
            seen = len(lines)
        except FileNotFoundError:
            pass
        time.sleep(2)


if __name__ == "__main__":
    print("[ENSEMBLE] Starting 3-layer consensus voting engine...")
    print(f"[ENSEMBLE] Watching: {IDS_LOG}")
    print(f"[ENSEMBLE] Watching: {ML_LOG}")
    print("[ENSEMBLE] Forwarding to K8s: http://192.168.49.2:30080")

    # Start ML watcher in background thread
    ml_thread = threading.Thread(target=watch_ml_alerts, daemon=True)
    ml_thread.start()

    # Run IDS watcher in main thread
    watch_ids_alerts()
import hashlib
import json
import os
import subprocess
from datetime import datetime

LEDGER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_ledger.json")

def load_ledger():
    try:
        with open(LEDGER_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def save_ledger(ledger):
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)

def get_last_hash(ledger):
    if not ledger:
        return "0" * 64
    return ledger[-1]["hash"]

def create_policy_entry(action, src_ip, rule, reason):
    ledger = load_ledger()
    prev_hash = get_last_hash(ledger)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_data = {
        "timestamp": timestamp,
        "action": action,
        "src_ip": src_ip,
        "rule": rule,
        "reason": reason,
        "prev_hash": prev_hash
    }
    entry_string = json.dumps(entry_data, sort_keys=True)
    entry_hash = hashlib.sha256(
        (prev_hash + entry_string).encode()
    ).hexdigest()
    entry_data["hash"] = entry_hash
    ledger.append(entry_data)
    save_ledger(ledger)
    print(f"\033[92m[AEGIS-POLICY] Entry #{len(ledger)} | {action} | {src_ip} | hash={entry_hash[:16]}...\033[0m")
    return entry_hash

def apply_block_rule(src_ip, reason):
    # Check if rule already exists — prevent duplicates
    check = subprocess.run(
        ['iptables', '-C', 'INPUT', '-s', src_ip, '-j', 'DROP'],
        capture_output=True
    )
    if check.returncode == 0:
        print(f"[AEGIS-POLICY] Rule already exists for {src_ip}, skipping")
        return

    # Apply iptables rule
    subprocess.run(
        ['iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'],
        capture_output=True
    )
    # Log to tamper-proof ledger
    create_policy_entry(
        action="BLOCK",
        src_ip=src_ip,
        rule=f"iptables -A INPUT -s {src_ip} -j DROP",
        reason=reason
    )

def apply_unblock_rule(src_ip, reason):
    subprocess.run(
        ['iptables', '-D', 'INPUT', '-s', src_ip, '-j', 'DROP'],
        capture_output=True
    )
    create_policy_entry(
        action="UNBLOCK",
        src_ip=src_ip,
        rule=f"iptables -D INPUT -s {src_ip} -j DROP",
        reason=reason
    )

def verify_ledger_integrity():
    ledger = load_ledger()
    print(f"\n[AEGIS-POLICY] Verifying audit chain integrity ({len(ledger)} entries)...")
    prev_hash = "0" * 64
    for i, entry in enumerate(ledger):
        check_entry = {k: v for k, v in entry.items() if k != "hash"}
        entry_string = json.dumps(check_entry, sort_keys=True)
        computed_hash = hashlib.sha256(
            (prev_hash + entry_string).encode()
        ).hexdigest()
        if computed_hash != entry["hash"]:
            print(f"\033[91m[AEGIS-POLICY] TAMPER DETECTED at entry #{i+1}!\033[0m")
            return False
        prev_hash = entry["hash"]
    print(f"\033[92m[AEGIS-POLICY] Audit chain VERIFIED — all {len(ledger)} entries intact!\033[0m")
    return True

if __name__ == "__main__":
    print("[AEGIS-POLICY] Testing policy mutation engine...")
    apply_block_rule("10.0.0.1", "ICMP FLOOD detected - 50 packets in 3s")
    apply_block_rule("10.0.0.2", "SYN FLOOD detected - 25 packets in 5s")
    apply_unblock_rule("10.0.0.1", "Manual review - false positive")
    verify_ledger_integrity()
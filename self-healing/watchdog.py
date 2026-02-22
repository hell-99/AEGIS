import subprocess
import time
import os
import signal
import sys
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import create_policy_entry
from datetime import datetime

COMPONENTS = {
    "flask-api": {
        "check_cmd": ["curl", "-s", "http://localhost:5000/status"],
        "restart_cmd": ["sudo", "python3", "/home/twi/AEGIS/flask_api.py"],
        "pid_file": "/tmp/aegis_api.pid",
        "process": None
    },
    "ids-engine": {
        "check_cmd": ["pgrep", "-f", "ids_engine.py"],
        "restart_cmd": ["sudo", "python3", "/home/twi/AEGIS/ids-ips/ids_engine.py", "s1-eth1"],
        "pid_file": "/tmp/aegis_ids.pid",
        "process": None
    }
}

heal_counts = {}

def log_heal(component, action, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] [AEGIS-WATCHDOG] {action} | {component} | {details}"
    print(f"\033[93m{msg}\033[0m")
    create_policy_entry("SELF-HEAL", component, action, details)

def check_component(name, config):
    try:
        result = subprocess.run(
            config["check_cmd"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0 and result.stdout
    except:
        return False

def restart_component(name, config):
    heal_counts[name] = heal_counts.get(name, 0) + 1
    log_heal(name, "RESTART", f"Attempt #{heal_counts[name]} — component down, restarting")

    try:
        # Kill any zombie processes
        subprocess.run(["pkill", "-f", name], capture_output=True)
        time.sleep(2)

        # Restart in background
        process = subprocess.Popen(
            config["restart_cmd"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        config["process"] = process
        time.sleep(3)

        # Verify restart worked
        if check_component(name, config):
            log_heal(name, "RECOVERED", f"Component back online after {heal_counts[name]} attempt(s)")
            return True
        else:
            log_heal(name, "FAILED", f"Restart failed — manual intervention may be needed")
            return False
    except Exception as e:
        log_heal(name, "ERROR", str(e))
        return False

def adaptive_escalation():
    """Level 2 — if same IP blocked multiple times, escalate to subnet block"""
    try:
        import json
        with open("/home/twi/AEGIS/policy-engine/audit_ledger.json") as f:
            ledger = json.load(f)

        # Count blocks per IP
        block_counts = {}
        for entry in ledger:
            if entry.get("action") == "BLOCK":
                ip = entry.get("src_ip", "")
                block_counts[ip] = block_counts.get(ip, 0) + 1

        # Escalate IPs blocked more than 5 times
        for ip, count in block_counts.items():
            if count > 5:
                subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                result = subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", subnet, "-j", "DROP"],
                    capture_output=True
                )
                if result.returncode != 0:  # Rule doesn't exist yet
                    subprocess.run(
                        ["sudo", "iptables", "-A", "INPUT", "-s", subnet, "-j", "DROP"],
                        capture_output=True
                    )
                    log_heal(ip, "ESCALATE", f"Blocked entire subnet {subnet} after {count} attacks")
    except Exception as e:
        pass

def watchdog_loop():
    print("\033[93m[AEGIS-WATCHDOG] Self-healing watchdog started...\033[0m")
    print("\033[93m[AEGIS-WATCHDOG] Monitoring: Flask API, IDS Engine\033[0m")
    print("\033[93m[AEGIS-WATCHDOG] Adaptive escalation: ACTIVE\033[0m\n")

    while True:
        for name, config in COMPONENTS.items():
            is_up = check_component(name, config)
            status = "UP" if is_up else "DOWN"

            if not is_up:
                print(f"\033[91m[AEGIS-WATCHDOG] {name} is {status} — initiating self-heal...\033[0m")
                restart_component(name, config)
            else:
                print(f"\033[92m[AEGIS-WATCHDOG] {name} is {status}\033[0m")

        # Run adaptive escalation every cycle
        adaptive_escalation()

        print(f"[AEGIS-WATCHDOG] Next check in 15s...\n")
        time.sleep(15)

if __name__ == "__main__":
    watchdog_loop()
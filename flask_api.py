from flask import Flask, jsonify, request
from flask_cors import CORS
import json, sys, os, time, subprocess
import requests as http_requests
from datetime import datetime
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import apply_block_rule, apply_unblock_rule, verify_ledger_integrity, load_ledger

app = Flask(__name__)
CORS(app)

ALERTS_LOG   = "/home/twi/AEGIS/ids-ips/alerts.log"
ML_LOG       = "/home/twi/AEGIS/ids-ips/ml_alerts.log"
ENSEMBLE_LOG = "/home/twi/AEGIS/ids-ips/ensemble_alerts.log"
CICIDS_LOG   = "/home/twi/AEGIS/ids-ips/cicids_alerts.log"
K8S_URL      = "http://192.168.49.2:30080"

def recent(path, seconds=300):
    try:
        return (time.time() - os.path.getmtime(path)) < seconds
    except:
        return False

def process_running(name):
    try:
        result = subprocess.run(['pgrep', '-f', name], capture_output=True)
        return result.returncode == 0
    except:
        return False

@app.route('/status', methods=['GET'])
def status():
    ledger = load_ledger()
    try:
        with open(ALERTS_LOG) as f:
            alert_count = len(f.readlines())
    except:
        alert_count = 0
    try:
        with open(ENSEMBLE_LOG) as f:
            ensemble_count = len(f.readlines())
    except:
        ensemble_count = 0
    try:
        with open(ML_LOG) as f:
            ml_count = len(f.readlines())
    except:
        ml_count = 0

    score = 30
    if alert_count > 0:    score += 10
    if len(ledger) > 10:   score += 15
    if ml_count > 0:       score += 10
    if ensemble_count > 0: score += 20
    if len(ledger) > 100:  score += 10
    score = min(score, 95)

    return jsonify({
        "system": "AEGIS", "status": "OPERATIONAL",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alerts_logged": alert_count,
        "ledger_entries": len(ledger),
        "compliance_score": score,
        "components": {"ids":"ACTIVE","ips":"ACTIVE","policy_engine":"ACTIVE","crypto_layer":"ACTIVE"}
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "ids":          recent(ALERTS_LOG),
        "ml":           recent(ML_LOG),
        "cicids":       process_running('cicids_live.py'),
        "ensemble":     recent(ENSEMBLE_LOG),
        "pqc":          True,
        "self_healing": True,
        "api":          True
    })

@app.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        with open(ALERTS_LOG, "r") as f:
            alerts = [a.strip() for a in f.readlines() if a.strip()]
        return jsonify({"total": len(alerts), "alerts": alerts[-200:]})
    except:
        return jsonify({"total": 0, "alerts": []})

@app.route('/ml-alerts', methods=['GET'])
def get_ml_alerts():
    try:
        with open(ML_LOG, "r") as f:
            alerts = [a.strip() for a in f.readlines() if a.strip()]
        return jsonify({"total": len(alerts), "alerts": alerts[-200:]})
    except:
        return jsonify({"total": 0, "alerts": []})

@app.route('/cicids-alerts', methods=['GET'])
def get_cicids_alerts():
    try:
        with open(CICIDS_LOG, "r") as f:
            alerts = [a.strip() for a in f.readlines() if a.strip()]
        return jsonify({"total": len(alerts), "alerts": alerts[-200:]})
    except:
        return jsonify({"total": 0, "alerts": []})

@app.route('/ensemble-alerts', methods=['GET'])
def get_ensemble_alerts():
    try:
        with open(ENSEMBLE_LOG, "r") as f:
            alerts = [a.strip() for a in f.readlines() if a.strip()]
        return jsonify({"total": len(alerts), "alerts": alerts[-20:]})
    except:
        return jsonify({"total": 0, "alerts": []})

@app.route('/k8s/alerts', methods=['GET'])
def k8s_alerts():
    try:
        r = http_requests.get(f"{K8S_URL}/alerts", timeout=3)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"total": 0, "alerts": [], "error": str(e)})

@app.route('/ledger', methods=['GET'])
def get_ledger():
    ledger = load_ledger()
    return jsonify({"total_entries": len(ledger), "chain": ledger, "entries": len(ledger)})

@app.route('/verify', methods=['GET'])
def verify():
    result = verify_ledger_integrity()
    return jsonify({"integrity": "VALID" if result else "TAMPERED", "valid": result,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route('/blocked-ips', methods=['GET'])
def get_blocked_ips():
    ledger = load_ledger()
    blocked = list({e['src_ip'] for e in ledger if 'BLOCK' in e.get('action', '')})
    return jsonify({"total": len(blocked), "ips": blocked})

@app.route('/block/<ip>', methods=['POST'])
def block_ip(ip):
    reason = request.json.get('reason', 'Manual block via API')
    apply_block_rule(ip, reason)
    return jsonify({"action": "BLOCKED", "ip": ip, "reason": reason,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route('/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    reason = request.json.get('reason', 'Manual unblock via API')
    apply_unblock_rule(ip, reason)
    return jsonify({"action": "UNBLOCKED", "ip": ip, "reason": reason,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route('/policies', methods=['GET'])
def get_policies():
    try:
        with open('/home/twi/AEGIS/policy-engine/policies.json', 'r') as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"policies": []})

if __name__ == '__main__':
    print("[AEGIS-API] Starting REST API on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json
import os
import oqs

app = Flask(__name__)
CORS(app)
RECEIVED_ALERTS = []

def verify_signature(payload: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        with oqs.Signature("Dilithium3") as verifier:
            return verifier.verify(payload, signature, public_key)
    except:
        return False

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "OPERATIONAL",
        "pod": os.environ.get("HOSTNAME", "unknown"),
        "pqc": "Dilithium3-verified"
    })

@app.route('/receive-alert', methods=['POST'])
def receive_alert():
    data = request.json

    payload    = data.get("payload", "").encode()
    signature  = bytes.fromhex(data.get("signature", ""))
    public_key = bytes.fromhex(data.get("public_key", ""))

    valid = verify_signature(payload, signature, public_key)

    if not valid:
        print(f"[K8S-RECEIVER] REJECTED — invalid Dilithium3 signature!")
        return jsonify({"status": "REJECTED", "reason": "Invalid PQC signature"}), 403

    alert = json.loads(payload)
    alert["received_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert["pod"] = os.environ.get("HOSTNAME", "unknown")
    alert["pqc_verified"] = True
    RECEIVED_ALERTS.append(alert)

    print(f"[K8S-RECEIVER] ✓ PQC-VERIFIED alert: {alert['src_ip']} → {alert['action']}")
    return jsonify({"status": "LOGGED", "pqc_verified": True, "total": len(RECEIVED_ALERTS)})

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify({"total": len(RECEIVED_ALERTS), "alerts": RECEIVED_ALERTS[-20:]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
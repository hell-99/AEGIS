from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
RECEIVED_ALERTS = []

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OPERATIONAL", "pod": os.environ.get("HOSTNAME", "unknown")})

@app.route('/receive-alert', methods=['POST', 'OPTIONS'])
def receive_alert():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    data = request.json
    data["received_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data["pod"] = os.environ.get("HOSTNAME", "unknown")
    RECEIVED_ALERTS.append(data)
    print(f"[K8S-RECEIVER] Alert received: {data}")
    return jsonify({"status": "LOGGED", "total": len(RECEIVED_ALERTS)})

@app.route('/alerts', methods=['GET', 'OPTIONS'])
def get_alerts():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    return jsonify({"total": len(RECEIVED_ALERTS), "alerts": RECEIVED_ALERTS[-20:]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

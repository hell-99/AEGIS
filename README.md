# AEGIS — Autonomous Edge-Native Guardian & Intelligence System

> A unified, self-healing cybersecurity fabric combining real-time intrusion detection, ensemble ML voting, autonomous threat response, cryptographically verifiable audit trails, post-quantum cryptography, and Kubernetes Zero Trust — all integrated into one system.

---

## Table of Contents

1. [The Problem AEGIS Solves](#the-problem-aegis-solves)
2. [Architecture](#architecture)
3. [How The Pipeline Works](#how-the-pipeline-works)
4. [Components](#components)
5. [Model Performance](#model-performance)
6. [Tech Stack](#tech-stack)
7. [Prerequisites](#prerequisites)
8. [Running AEGIS](#running-aegis)
9. [Demo Guide](#demo-guide)
10. [Threat Level Behavior](#threat-level-behavior)
11. [Self-Healing](#self-healing)
12. [Reset for Fresh Demo](#reset-for-fresh-demo)
13. [API Endpoints](#api-endpoints)
14. [What Makes AEGIS Different](#what-makes-aegis-different)
15. [Measured Performance](#measured-performance)
16. [NIST CSF Alignment](#nist-csf-alignment)
17. [Project Structure](#project-structure)
18. [Roadmap](#roadmap)

---

## The Problem AEGIS Solves

Modern organizations run 5–10 disconnected security tools. None talk to each other. A security analyst manually correlates alerts across multiple dashboards while attackers move in minutes. Audit logs can be tampered with. Detection systems use single-layer rule-based approaches that miss novel attacks. Most systems have zero protection against quantum computing threats.

**AEGIS unifies detection, ensemble voting, response, audit, compliance, and self-healing into a single pipeline — everything happens automatically in milliseconds.**

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      AEGIS SECURITY FABRIC                        │
├──────────────────┬────────────────┬─────────────────────────────┤
│   NETWORK LAYER  │  CLOUD LAYER   │     INTELLIGENCE LAYER      │
│                  │                │                             │
│  Mininet         │  Kubernetes    │  Rule-Based IDS/IPS         │
│  Topology        │  Deployment    │  Isolation Forest (ML)      │
│  OVS Switch      │  Zero Trust    │  CICIDS2017 Random Forest   │
│  Attack Sim      │  NetworkPolicy │  Entropy Analyzer           │
│                  │  NodePort      │  Cryptographic Ledger       │
│                  │  Bridge        │  PQC Layer (Dilithium3)     │
├──────────────────┴────────────────┴─────────────────────────────┤
│                    ENSEMBLE VOTING ENGINE                         │
│   3-Layer Consensus: Rule-Based + Isolation Forest + CICIDS      │
│   Majority (2/3) = MEDIUM confidence BLOCK                       │
│   Unanimous (3/3) = HIGH confidence BLOCK                        │
│   Signed with Dilithium3 → Verified in Kubernetes pod            │
├──────────────────────────────────────────────────────────────────┤
│                    SELF-HEALING WATCHDOG                          │
│         Component Recovery + Adaptive Threat Escalation          │
├──────────────────────────────────────────────────────────────────┤
│                      REST API (Flask)                             │
├──────────────────────────────────────────────────────────────────┤
│                     LIVE SOC DASHBOARD                            │
└──────────────────────────────────────────────────────────────────┘
```

## Few Visuals 
![Alert Logs](<Images/alert logs.png>)

![Audit Ledger showing Block](<Images/Audit Ledger Block.png>)

![Audit Ledger showing Detect](<Images/Audit Ledger Detect.png>)

![Audit Ledger](<Images/Audit Ledger.png>)

![Compliance](Images/Compliance.png)

![System Critical in Real Time](Images/Critical.png)

![System High in Real Time](Images/High.png)

![System Medium in Real Time](Images/Medium.png)

![System Low in Real Time](<Images/Low threat.png>)

![Iptable blocked](<Images/iptables block.png>)

![K8s](Images/k8s.png)

![pqc](Images/pqc.png)

![Watchdog Selfhealing](<Images/Watch dog self heal.png>)

![Zero Trust](<Images/Zero trust.png>)

---

## How The Pipeline Works

```
Attack occurs on Mininet network
→ Rule-based IDS flags known pattern (ICMP flood / SYN flood / Port scan)
→ Isolation Forest flags statistical anomaly (unsupervised ML)
→ CICIDS2017 Random Forest classifies attack type (supervised ML, 99% accuracy)
→ All three cast votes to Ensemble Engine
→ Ensemble waits for consensus — majority (2/3) required to BLOCK
→ Ensemble signs alert with Dilithium3 post-quantum signature
→ Signed alert POSTed to Kubernetes pod via NodePort
→ K8s pod verifies Dilithium3 signature — rejects if tampered
→ iptables block rule applied at kernel level (no duplicates)
→ SHA-256 hash chained into tamper-evident audit ledger
→ Watchdog monitors all components — restarts any that crash
→ Adaptive escalation blocks entire subnet after repeat attacks
→ Incident report auto-generated with NIST CSF mapping
→ Flask API exposes everything via REST
→ SOC Dashboard visualizes live — refreshes every 3 seconds
→ Threat level auto-resets to LOW after 30 seconds of no activity
```

Everything above is automatic. No human in the loop.

---

## Components

### 1. Network Topology (`network/topology.py`)
Simulates a real enterprise network using Mininet with Open vSwitch — single switch, 5 hosts, with realistic traffic simulation.

### 2. Rule-Based IDS/IPS (`ids-ips/ids_engine.py`)
Real-time packet inspection using Scapy at the raw socket level. Detects ICMP Flood (>10 packets/3s), SYN Flood (>20 half-open/5s), and Port Scans (>15 unique ports). 1-second alert cooldown prevents alert flooding. Casts vote to ensemble engine.

### 3. ML Anomaly Detection (`ids-ips/ml_detector.py`)
Isolation Forest — unsupervised machine learning trained on normal traffic profiles. Extracts 6 behavioral features per IP per window: packet count, unique ports, SYN ratio, ICMP ratio, average packet size, UDP ratio. Detects anomalies without being told what an attack looks like — catches zero-day threats.

### 4. CICIDS2017 Classifier (`ids-ips/cicids_trainer.py` + `ids-ips/cicids_live.py`)
Random Forest trained on 2,520,751 real labeled network flows from the CICIDS2017 dataset. Achieves 99% accuracy across 7 attack classes: Bots, Brute Force, DDoS, DoS, Normal Traffic, Port Scanning, Web Attacks.

### 5. Ensemble Voting Engine (`ids-ips/ensemble.py`)
The integration layer that makes AEGIS genuinely intelligent:
- All three detectors vote independently
- Majority vote (2/3) = MEDIUM confidence BLOCK
- Unanimous (3/3) = HIGH confidence BLOCK
- 1/3 = ALERT only, no block — prevents false positives
- Every decision signed with Dilithium3 before transmission
- Forwarded to Kubernetes pod with cryptographic proof

### 6. Payload Entropy Analyzer (`ids-ips/entropy_detector.py`)
Shannon entropy analysis on raw packet payloads. Normal traffic: 3.0–5.0 bits. Encrypted C2/exfiltration: 7.2–8.0 bits. Detects encrypted malware tunnels and slow data exfiltration.

### 7. Policy Engine (`policy-engine/policy_engine.py`)
Every security action hashed into a SHA-256 chained ledger. Duplicate iptables rule prevention — each IP blocked exactly once. Modifying any entry invalidates all subsequent hashes. Forensically verifiable.

```json
{
  "action": "ENSEMBLE-BLOCK",
  "src_ip": "10.0.0.1",
  "confidence": "HIGH",
  "voters": ["rule_based", "isolation_forest"],
  "prev_hash": "ce7263c817...",
  "hash": "dea8e54eb1..."
}
```

### 8. Post-Quantum Cryptography (`crypto/`)
NIST PQC Standard 2024 via liboqs — integrated into the actual data flow:
- CRYSTALS-Kyber768 (ML-KEM) — quantum-resistant key encapsulation
- CRYSTALS-Dilithium3 (ML-DSA) — signs every ensemble alert before transmission
- K8s receiver verifies Dilithium3 signature — rejects unsigned/tampered alerts

### 9. Self-Healing Watchdog (`self-healing/watchdog.py`)
Three layers of autonomous recovery:
- Level 1 — Health-checks components every 15s, auto-restarts, logs SELF-HEAL to audit chain
- Level 2 — Same IP blocked 5+ times → escalates to entire subnet block
- Level 3 — Kubernetes reconciliation loop auto-restarts crashed pods

### 10. Kubernetes + Zero Trust (`k8s/`)
- Deployment with replicas always running
- NetworkPolicy — default-deny all ingress/egress (Zero Trust)
- NodePort — exposes receiver at port 30080 for Mininet→K8s bridge
- Real communication — ensemble POSTs signed alerts to K8s pod, pod verifies and stores

### 11. Incident Response (`incident-response/incident_response.py`)
Automated 3-step response: Isolate → Audit → Map. Auto-generates JSON reports. Maps every incident to NIST CSF automatically.

### 12. REST API (`flask_api.py`)
Serves all system data to the dashboard and external tools.

### 13. SOC Dashboard (`soc-dashboard/dashboard.html`)
Live cyberpunk-aesthetic dashboard — intrusion feed, ensemble voting panel, Kubernetes bridge, audit ledger with SHA-256 hashes, component health monitor, chain integrity ring, dynamic threat level. Refreshes every 3 seconds.

---

## Model Performance (CICIDS2017)

```
              precision  recall  f1-score  support
Bots              0.99    0.99      0.99      389
Brute Force       1.00    0.99      1.00      389
DDoS              1.00    1.00      1.00      390
DoS               0.98    0.99      0.99      390
Normal Traffic    0.98    0.99      0.98      390
Port Scanning     1.00    0.99      1.00      390
Web Attacks       0.99    0.98      0.99      390

Overall accuracy: 99% on 2,728 held-out test samples
Training data: 2,520,751 real network flows
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Network simulation | Mininet, Open vSwitch | Enterprise network emulation |
| Packet inspection | Scapy | Raw socket IDS |
| Firewall | Linux iptables | Kernel-level IPS |
| ML Unsupervised | Isolation Forest | Anomaly detection |
| ML Supervised | Random Forest | Attack classification |
| Training data | CICIDS2017 | 2.5M real labeled flows |
| Post-quantum crypto | liboqs (Kyber768 + Dilithium3) | NIST PQC Standard 2024 |
| Audit chain | SHA-256 chaining | Tamper-evident ledger |
| Containers | Docker, Kubernetes | Cloud-native deployment |
| Zero Trust | K8s NetworkPolicy | Default-deny networking |
| Self-healing | Python subprocess + K8s | Process + pod recovery |
| API | Flask, Flask-CORS | REST interface |
| Frontend | HTML5, CSS3, JavaScript | SOC dashboard |
| Compliance | NIST CSF | Regulatory mapping |

---

## Prerequisites

- Ubuntu 22.04/24.04, Python 3.12+, Docker, 8GB RAM

```bash
# System dependencies
sudo apt install -y python3-pip mininet openvswitch-switch \
  cmake ninja-build libssl-dev python3-dev git curl

# Python packages
pip install scapy flask flask-cors scikit-learn numpy pandas \
  requests joblib --break-system-packages

# Post-quantum cryptography
git clone --recursive https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python && sudo pip3 install . --break-system-packages && cd ..

# Kubernetes
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
sudo snap install kubectl --classic
minikube start --cpus=3 --memory=4096 --driver=docker

# Generate PQC keypair
sudo python3 crypto/pqc_keys.py

# Train CICIDS model
python3 ids-ips/cicids_trainer.py
```

---

## Running AEGIS

**Step 1 — Reset to clean state:**
```bash
sudo ~/AEGIS/reset.sh
```

**Step 2 — Start Minikube:**
```bash
minikube start
kubectl rollout restart deployment/aegis-receiver -n aegis
```

**Step 3 — Start each component in a separate terminal:**

```bash
# Terminal 1 — Mininet network
sudo mn --topo single,5

# Terminal 2 — IDS Engine
sudo python3 ~/AEGIS/ids-ips/ids_engine.py s1-eth1

# Terminal 3 — ML Detector
sudo python3 ~/AEGIS/ids-ips/ml_detector.py s1-eth1

# Terminal 4 — CICIDS Classifier
sudo python3 ~/AEGIS/ids-ips/cicids_live.py s1-eth1

# Terminal 5 — Ensemble Engine
sudo python3 ~/AEGIS/ids-ips/ensemble.py

# Terminal 6 — Self-Healing Watchdog
sudo python3 ~/AEGIS/self-healing/watchdog.py

# Terminal 7 — Flask API
python3 ~/AEGIS/flask_api.py
```

**Step 4 — Open Dashboard:**
```
Open ~/AEGIS/soc-dashboard/dashboard.html in Firefox
```

---

## Demo Guide

### Simulating Attacks in Mininet

**MEDIUM threat:**
```
mininet> h1 ping -f -c 55 h2
```

**HIGH threat (run twice quickly):**
```
mininet> h1 ping -f -c 55 h2
mininet> h1 ping -f -c 55 h2
```

**CRITICAL threat (run three times quickly):**
```
mininet> h1 ping -f -c 55 h2
mininet> h1 ping -f -c 55 h2
mininet> h1 ping -f -c 55 h2
```

After each attack, AEGIS automatically detects → votes → blocks → recovers. Threat level returns to LOW within 30 seconds.

### Verify Ensemble + K8s Integration
```bash
curl http://192.168.49.2:30080/alerts
```

### Verify Audit Chain Integrity
```bash
curl http://localhost:5000/verify
# Returns: {"integrity": "VERIFIED"}
```

### Demonstrate Self-Healing
```bash
sudo pkill -f ids_engine.py
# Wait 15 seconds — watchdog detects and auto-restarts
```

---

## Threat Level Behavior

Threat level is driven by alerts in the **last 30 seconds** (sliding window):

| Recent Alerts (30s window) | Threat Level | Color |
|---------------------------|--------------|-------|
| 0 | LOW | Green |
| 1–2 | MEDIUM | Yellow |
| 3–4 | HIGH | Orange |
| 5+ | CRITICAL | Red |

**Autonomous reset:** After an attack ends and the IP is blocked, no new alerts are generated. After 30 seconds the sliding window expires and the threat level automatically drops back to LOW — demonstrating the full autonomous detect → respond → recover lifecycle.

---

## Self-Healing

**Level 1 — Component Recovery:**
- Monitors Flask API and IDS Engine every 15 seconds
- Auto-restarts any failed component
- Logs all heal events to the Merkle audit ledger as `SELF-HEAL` entries

**Level 2 — Adaptive Escalation:**
- If the same IP attacks more than 5 times → automatically blocks entire `/24` subnet
- Logged as `ESCALATE` events in the audit ledger

---

## Reset for Fresh Demo

```bash
sudo ~/AEGIS/reset.sh
```

Clears: iptables rules, blocked IPs, all alert logs, ensemble votes.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | System health and compliance score |
| `/alerts` | GET | IDS alert feed |
| `/ml-alerts` | GET | ML anomaly alert feed |
| `/cicids-alerts` | GET | CICIDS classifier alert feed |
| `/ledger` | GET | Audit ledger entries |
| `/verify` | GET | Cryptographic integrity check |
| `/health` | GET | Component health status |
| `/blocked-ips` | GET | Currently blocked IPs |
| `/k8s/alerts` | GET | Kubernetes bridge alerts |

---

## What Makes AEGIS Different

**Ensemble Voting — Not Single-Layer Detection:**
Most IDS tools make blocking decisions from a single signal. AEGIS requires consensus across 3 independent detection layers before blocking. This eliminates false positives while maintaining high recall.

**PQC in the Actual Data Flow:**
The Dilithium3 signature is embedded in the real communication channel between Mininet and Kubernetes. Every ensemble alert is signed before transmission and verified on receipt. Tampered or unsigned alerts are rejected.

**Cryptographic Audit Chain:**
Every action — alert, block, self-heal, escalate — is SHA-256 hashed and chained. Modifying any historical entry breaks the entire chain. Tamper-evident and forensically verifiable.

**Real Cross-Environment Integration:**
Mininet and Kubernetes are genuinely connected. The ensemble engine POSTs signed alerts to a K8s NodePort, and the receiving pod verifies the PQC signature before storing.

**Fully Autonomous Lifecycle:**
Detect → Escalate → Block → Recover — no human in the loop at any stage.

---

## Measured Performance

| Metric | Value |
|--------|-------|
| Alert detection latency | < 1ms |
| IPS block application | < 5ms |
| Audit chain entry + hash | < 5ms |
| Ledger verification (500 entries) | < 100ms |
| Watchdog recovery time | < 20 seconds |
| Threat level auto-reset | 30 seconds |
| CICIDS2017 model accuracy | 99% |
| Training dataset size | 2,520,751 flows |
| PQC key generation (Kyber768) | ~0.3ms |

---

## NIST CSF Alignment

| Function | Implementation |
|----------|---------------|
| **Identify** | Network topology mapping, asset discovery via Mininet |
| **Protect** | iptables firewall, PQC encryption (Dilithium3 + Kyber768), policy enforcement |
| **Detect** | IDS + Isolation Forest + CICIDS + Entropy Detector — 4-layer detection |
| **Respond** | Ensemble auto-blocking, incident response playbooks, K8s alert forwarding |
| **Recover** | Self-healing watchdog, adaptive subnet escalation, automatic threat reset |

---

## Project Structure

```
AEGIS/
├── ids-ips/
│   ├── ids_engine.py          # Rule-based IDS — ICMP/SYN/port scan detection
│   ├── ml_detector.py         # Isolation Forest anomaly detection
│   ├── cicids_live.py         # CICIDS Random Forest live classifier
│   ├── cicids_trainer.py      # Offline model training script
│   ├── entropy_detector.py    # Shannon entropy traffic analysis
│   ├── ensemble.py            # 3-layer consensus voting engine
│   ├── aegis_model.pkl        # Trained Isolation Forest model
│   ├── cicids_model.pkl       # Trained CICIDS Random Forest model
│   └── cicids/
│       └── cicids2017_cleaned.csv  # CICIDS2017 training dataset
├── policy-engine/
│   └── policy_engine.py       # iptables management + SHA-256 audit ledger
├── crypto/
│   ├── pqc_keys.py            # Dilithium3 key generation and signing
│   ├── pqc_layer.py           # PQC operations wrapper
│   └── keys/                  # Generated key files
├── self-healing/
│   └── watchdog.py            # Self-healing watchdog + adaptive escalation
├── incident-response/
│   └── incident_response.py   # Automated incident response playbooks
├── network/
│   └── topology.py            # Mininet topology definition
├── k8s/
│   ├── receiver_app.py        # K8s Flask receiver for PQC-signed alerts
│   ├── receiver-deployment.yaml
│   └── Dockerfile
├── compliance/                # NIST CSF compliance scoring and reports
├── soc-dashboard/
│   └── dashboard.html         # Live SOC dashboard
├── flask_api.py               # REST API (localhost:5000)
├── reset.sh                   # One-command demo reset
└── README.md
```

---

## Roadmap

- [ ] LSTM temporal detection for slow-burn attacks spread over hours
- [ ] Istio service mesh with mTLS between all microservices
- [ ] HashiCorp Vault for secrets and certificate management
- [ ] Multi-node Kubernetes cluster with real load distribution
- [ ] ELK Stack for enterprise-grade log aggregation
- [ ] GAN-based adversarial attack simulation for model hardening
- [ ] OpenCTI integration for threat intelligence feeds

---

## Disclaimer

Built entirely in a sandboxed virtual environment for research and educational purposes. All simulated attacks target locally controlled hosts inside a VM. No external systems, networks, or devices were involved.

---

## License

MIT License — see LICENSE for details.


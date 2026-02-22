import json
import subprocess
from datetime import datetime
import sys
sys.path.append('/home/twi/AEGIS/policy-engine')
from policy_engine import load_ledger, create_policy_entry

# NIST CSF mapping
NIST_MAP = {
    "ICMP FLOOD":  {"function": "DETECT",   "category": "DE.AE-1", "description": "Network anomaly detected"},
    "SYN FLOOD":   {"function": "RESPOND",  "category": "RS.RP-1", "description": "Response plan executed"},
    "PORT SCAN":   {"function": "IDENTIFY", "category": "ID.RA-1", "description": "Asset vulnerability identified"},
    "IPS BLOCK":   {"function": "PROTECT",  "category": "PR.AC-4", "description": "Access permissions enforced"},
}

def generate_incident_report(alert_type, src_ip, details):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    nist = NIST_MAP.get(alert_type, {"function": "DETECT", "category": "DE.AE-1", "description": "Security event"})

    report = {
        "incident_id": incident_id,
        "timestamp": timestamp,
        "severity": "HIGH" if "FLOOD" in alert_type else "MEDIUM",
        "alert_type": alert_type,
        "source_ip": src_ip,
        "details": details,
        "nist_csf": nist,
        "response_actions": [],
        "status": "OPEN"
    }

    # Auto-response steps
    actions = []

    # Step 1 — Isolate
    print(f"[AEGIS-IR] Step 1: Isolating threat from {src_ip}...")
    subprocess.run(['iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'], capture_output=True)
    actions.append({"step": 1, "action": "ISOLATE", "detail": f"iptables block applied to {src_ip}", "status": "DONE"})

    # Step 2 — Log to ledger
    print(f"[AEGIS-IR] Step 2: Logging to cryptographic audit ledger...")
    create_policy_entry("INCIDENT", src_ip, incident_id, f"{alert_type}: {details}")
    actions.append({"step": 2, "action": "AUDIT_LOG", "detail": f"Ledger entry created: {incident_id}", "status": "DONE"})

    # Step 3 — NIST mapping
    print(f"[AEGIS-IR] Step 3: Mapping to NIST CSF {nist['category']}...")
    actions.append({"step": 3, "action": "NIST_MAP", "detail": f"{nist['function']} - {nist['category']}", "status": "DONE"})

    # Step 4 — Save report
    report["response_actions"] = actions
    report["status"] = "CONTAINED"
    report_path = f"/home/twi/AEGIS/incident-response/{incident_id}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[AEGIS-IR] {'='*50}")
    print(f"[AEGIS-IR] INCIDENT REPORT GENERATED")
    print(f"[AEGIS-IR] ID:       {incident_id}")
    print(f"[AEGIS-IR] Type:     {alert_type}")
    print(f"[AEGIS-IR] Source:   {src_ip}")
    print(f"[AEGIS-IR] Severity: {report['severity']}")
    print(f"[AEGIS-IR] NIST CSF: {nist['function']} / {nist['category']}")
    print(f"[AEGIS-IR] Status:   {report['status']}")
    print(f"[AEGIS-IR] Saved:    {report_path}")
    print(f"[AEGIS-IR] {'='*50}\n")

    return report

def generate_compliance_summary():
    ledger = load_ledger()
    summary = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events": len(ledger),
        "nist_csf_coverage": {
            "IDENTIFY": 0,
            "PROTECT": 0,
            "DETECT": 0,
            "RESPOND": 0,
            "RECOVER": 0
        },
        "compliance_score": 0
    }

    for entry in ledger:
        reason = entry.get("reason", "")
        for alert_type, nist in NIST_MAP.items():
            if alert_type in reason:
                summary["nist_csf_coverage"][nist["function"]] += 1

    total = sum(summary["nist_csf_coverage"].values()) or 1
    covered = sum(1 for v in summary["nist_csf_coverage"].values() if v > 0)
    summary["compliance_score"] = round((covered / 5) * 100)

    print(f"\n[AEGIS-COMPLIANCE] NIST CSF COMPLIANCE REPORT")
    print(f"[AEGIS-COMPLIANCE] Generated: {summary['generated']}")
    print(f"[AEGIS-COMPLIANCE] Total Events Analyzed: {summary['total_events']}")
    print(f"[AEGIS-COMPLIANCE] Coverage Score: {summary['compliance_score']}%")
    for func, count in summary["nist_csf_coverage"].items():
        bar = "█" * min(count, 20)
        print(f"[AEGIS-COMPLIANCE]   {func:<10} {bar} ({count})")

    report_path = "/home/twi/AEGIS/compliance/nist_report.json"
    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[AEGIS-COMPLIANCE] Report saved: {report_path}")
    return summary

if __name__ == "__main__":
    print("[AEGIS-IR] Testing incident response automation...")
    generate_incident_report("ICMP FLOOD", "10.0.0.1", "75 packets in 3s")
    generate_incident_report("PORT SCAN", "10.0.0.2", "unique_ports=18")
    generate_compliance_summary()
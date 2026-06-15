import json
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, "policy-engine"))

from soar import playbook_engine
from soar import case_manager
from policy_engine import load_ledger


def generate_incident_report(alert_type, src_ip, details):
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    print(f"\n\033[96m[AEGIS-IR] Incident triggered: {incident_id} | {alert_type} | {src_ip}\033[0m")
    report = playbook_engine.execute(alert_type, src_ip, details, incident_id)
    return report


def generate_compliance_summary():
    ledger = load_ledger()
    summary = {
        "generated":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_events":    len(ledger),
        "nist_csf_coverage": {
            "IDENTIFY": 0, "PROTECT": 0, "DETECT": 0, "RESPOND": 0, "RECOVER": 0
        },
        "compliance_score": 0,
    }

    nist_map = {
        "ICMP FLOOD":     "RESPOND",
        "SYN FLOOD":      "RESPOND",
        "PORT SCAN":      "IDENTIFY",
        "IPS BLOCK":      "PROTECT",
        "ENSEMBLE-BLOCK": "RESPOND",
    }
    for entry in ledger:
        reason = entry.get("reason", "")
        for threat, func in nist_map.items():
            if threat in reason:
                summary["nist_csf_coverage"][func] += 1

    covered = sum(1 for v in summary["nist_csf_coverage"].values() if v > 0)
    summary["compliance_score"] = round((covered / 5) * 100)

    print(f"\n[AEGIS-COMPLIANCE] NIST CSF COMPLIANCE REPORT")
    print(f"[AEGIS-COMPLIANCE] Generated: {summary['generated']}")
    print(f"[AEGIS-COMPLIANCE] Total Events: {summary['total_events']}")
    print(f"[AEGIS-COMPLIANCE] Coverage Score: {summary['compliance_score']}%")
    for func, count in summary["nist_csf_coverage"].items():
        bar = "█" * min(count, 20)
        print(f"[AEGIS-COMPLIANCE]   {func:<10} {bar} ({count})")

    case_manager.print_summary()

    report_path = os.path.join(BASE_DIR, "compliance", "nist_report.json")
    with open(report_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[AEGIS-COMPLIANCE] Report saved: {report_path}")
    return summary


if __name__ == "__main__":
    print("[AEGIS-IR] Testing SOAR playbook execution...\n")
    generate_incident_report("ICMP FLOOD",    "10.0.0.1", "75 packets in 3s")
    generate_incident_report("PORT SCAN",     "10.0.0.2", "unique_ports=18")
    generate_incident_report("ENSEMBLE-BLOCK","10.0.0.3", "voters=[rule_based, isolation_forest, ml_detector]")
    generate_compliance_summary()

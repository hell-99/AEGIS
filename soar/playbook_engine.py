import json
import os
import subprocess
from datetime import datetime

from soar.config import PLAYBOOKS_DIR, INCIDENT_DIR, BASE_DIR
from soar import case_manager, enrichment, notifier
from soar.kill_chain import get_stage_for_aegis

import sys
sys.path.append(os.path.join(BASE_DIR, "policy-engine"))
from policy_engine import apply_block_rule, create_policy_entry

NIST_MAP = {
    "ICMP FLOOD":     {"function": "RESPOND",  "category": "RS.RP-1", "description": "Response plan executed"},
    "SYN FLOOD":      {"function": "RESPOND",  "category": "RS.MI-1", "description": "Incident mitigated"},
    "UDP FLOOD":      {"function": "RESPOND",  "category": "RS.RP-1", "description": "Response plan executed"},
    "PORT SCAN":      {"function": "IDENTIFY", "category": "ID.RA-1", "description": "Asset vulnerability identified"},
    "IPS BLOCK":      {"function": "PROTECT",  "category": "PR.AC-4", "description": "Access permissions enforced"},
    "ENSEMBLE-BLOCK": {"function": "RESPOND",  "category": "RS.MI-2", "description": "Incident containment executed"},
    "ML ANOMALY":     {"function": "DETECT",   "category": "DE.AE-5", "description": "Incident alert threshold established"},
}


def load_playbook(alert_type):
    for fname in os.listdir(PLAYBOOKS_DIR):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(PLAYBOOKS_DIR, fname)) as f:
            pb = json.load(f)
        if alert_type in pb.get("triggers", []):
            return pb

    with open(os.path.join(PLAYBOOKS_DIR, "generic.json")) as f:
        return json.load(f)


def execute(alert_type, src_ip, details, incident_id):
    playbook = load_playbook(alert_type)
    severity = playbook.get("severity", "MEDIUM")

    print(f"\n\033[96m[AEGIS-SOAR] ── Playbook: {playbook['name']} ───────────────\033[0m")
    print(f"\033[96m[AEGIS-SOAR] Incident : {incident_id}\033[0m")
    kc = get_stage_for_aegis(alert_type)
    print(f"\033[96m[AEGIS-SOAR] Threat   : {alert_type} | SRC: {src_ip} | Severity: {severity}\033[0m")
    print(f"\033[96m[AEGIS-SOAR] Kill Chain: Stage {kc['stage']} — {kc['name']} | Next: {kc.get('next', {}).get('prediction', 'N/A')}\033[0m")
    print(f"\033[96m[AEGIS-SOAR] Steps    : {len(playbook['steps'])}\033[0m\n")

    case_id = case_manager.create_case(incident_id, alert_type, src_ip, severity, playbook["name"], kill_chain=kc)

    ctx = {
        "incident_id": incident_id,
        "case_id":     case_id,
        "alert_type":  alert_type,
        "src_ip":      src_ip,
        "details":     details,
        "severity":    severity,
        "playbook":    playbook,
        "kill_chain":  kc,
        "enrichment":  None,
        "steps_done":  [],
        "report":      {},
    }

    for i, step in enumerate(playbook["steps"], 1):
        step_id = step["id"]
        action  = step["action"]
        print(f"\033[96m[AEGIS-SOAR] Step {i}/{len(playbook['steps'])}: {step_id} — {step['description']}\033[0m")
        try:
            result = _run_step(step, ctx)
            case_manager.log_step(case_id, step_id, action, result, success=True)
            ctx["steps_done"].append(step_id)
        except Exception as e:
            err = str(e)
            print(f"\033[91m[AEGIS-SOAR] Step {step_id} failed: {err}\033[0m")
            case_manager.log_step(case_id, step_id, action, err, success=False)

    print(f"\033[96m[AEGIS-SOAR] ── Playbook complete ── {len(ctx['steps_done'])}/{len(playbook['steps'])} steps OK\033[0m\n")
    return ctx["report"]


def _run_step(step, ctx):
    action = step["action"]

    if action == "enrich_ip":
        result = enrichment.enrich_ip(ctx["src_ip"])
        ctx["enrichment"] = result
        case_manager.set_enrichment(ctx["case_id"], result)
        return result

    elif action == "block_ip":
        apply_block_rule(ctx["src_ip"], f"{ctx['alert_type']}: {ctx['details']}")
        return f"iptables DROP applied to {ctx['src_ip']}"

    elif action == "audit_log":
        h = create_policy_entry(
            action="SOAR-IR",
            src_ip=ctx["src_ip"],
            rule=ctx["incident_id"],
            reason=f"{ctx['alert_type']}: {ctx['details']}"
        )
        return f"Ledger entry hash={h[:16]}..."

    elif action == "notify":
        notifier.send_alert(
            ctx["incident_id"], ctx["alert_type"], ctx["src_ip"],
            ctx["severity"], ctx["steps_done"], ctx["enrichment"]
        )
        return "Alert dispatched"

    elif action == "nist_map":
        nist = ctx["playbook"].get("nist") or NIST_MAP.get(ctx["alert_type"],
               {"function": "DETECT", "category": "DE.AE-1", "description": "Security event"})
        print(f"\033[96m[AEGIS-SOAR]   NIST CSF: {nist['function']} / {nist['category']} — {nist['description']}\033[0m")
        ctx["report"]["nist_csf"] = nist
        return nist

    elif action == "generate_report":
        report = _build_report(ctx)
        path = os.path.join(INCIDENT_DIR, f"{ctx['incident_id']}.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        ctx["report"] = report
        print(f"\033[96m[AEGIS-SOAR]   Report saved: {path}\033[0m")
        return path

    elif action == "update_case":
        new_status = step.get("status", "INVESTIGATING")
        case_manager.update_status(ctx["case_id"], new_status, step.get("description"))
        return f"Case status → {new_status}"

    elif action == "escalate":
        return _escalate(ctx)

    return f"Unknown action: {action}"


def _escalate(ctx):
    src_ip = ctx["src_ip"]
    parts = src_ip.split(".")
    if len(parts) != 4:
        return "Escalation skipped — invalid IP"
    subnet = ".".join(parts[:3]) + ".0/24"
    check = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", subnet, "-j", "DROP"],
        capture_output=True
    )
    if check.returncode != 0:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", subnet, "-j", "DROP"], capture_output=True)
        create_policy_entry("SOAR-ESCALATE", src_ip, f"subnet-block:{subnet}", "Escalation: repeat attacker")
        print(f"\033[91m[AEGIS-SOAR]   ESCALATED: subnet {subnet} blocked\033[0m")
        return f"Subnet {subnet} blocked"
    return f"Subnet {subnet} already blocked"


def _build_report(ctx):
    kc = ctx["kill_chain"]
    return {
        "incident_id":    ctx["incident_id"],
        "case_id":        ctx["case_id"],
        "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type":     ctx["alert_type"],
        "source_ip":      ctx["src_ip"],
        "details":        ctx["details"],
        "severity":       ctx["severity"],
        "playbook":       ctx["playbook"]["name"],
        "kill_chain": {
            "stage":      kc.get("stage"),
            "phase":      kc.get("name"),
            "rationale":  kc.get("rationale"),
            "next_stage": kc.get("next", {}).get("prediction"),
        },
        "nist_csf":       ctx["report"].get("nist_csf", {}),
        "enrichment":     ctx["enrichment"],
        "steps_executed": ctx["steps_done"],
        "status":         "CONTAINED",
    }

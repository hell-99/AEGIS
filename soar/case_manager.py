import json
import os
from datetime import datetime
from soar.config import CASES_DIR

VALID_TRANSITIONS = {
    "OPEN":          ["INVESTIGATING", "CONTAINED", "RESOLVED"],
    "INVESTIGATING": ["CONTAINED", "RESOLVED", "ESCALATED"],
    "ESCALATED":     ["CONTAINED", "RESOLVED"],
    "CONTAINED":     ["RESOLVED"],
    "RESOLVED":      [],
}

SEVERITY_SLA = {
    "CRITICAL": {"contain": 5,  "resolve": 30},
    "HIGH":     {"contain": 15, "resolve": 60},
    "MEDIUM":   {"contain": 60, "resolve": 240},
    "LOW":      {"contain": 240,"resolve": 1440},
}


def _case_path(case_id):
    return os.path.join(CASES_DIR, f"{case_id}.json")


def create_case(incident_id, alert_type, src_ip, severity, playbook_name):
    case_id = f"CASE-{incident_id}"
    sla = SEVERITY_SLA.get(severity, SEVERITY_SLA["MEDIUM"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    case = {
        "case_id":      case_id,
        "incident_id":  incident_id,
        "alert_type":   alert_type,
        "src_ip":       src_ip,
        "severity":     severity,
        "playbook":     playbook_name,
        "status":       "OPEN",
        "created_at":   now,
        "updated_at":   now,
        "sla_minutes":  sla,
        "timeline": [
            {"timestamp": now, "status": "OPEN", "note": f"Case created — playbook: {playbook_name}"}
        ],
        "steps_executed": [],
        "enrichment":   None,
        "resolved_at":  None,
        "contained_at": None,
    }

    with open(_case_path(case_id), "w") as f:
        json.dump(case, f, indent=2)

    print(f"\033[96m[AEGIS-SOAR] Case created: {case_id} | {alert_type} | {severity} | SLA contain={sla['contain']}min\033[0m")
    return case_id


def update_status(case_id, new_status, note=None):
    path = _case_path(case_id)
    if not os.path.exists(path):
        return False

    with open(path) as f:
        case = json.load(f)

    current = case["status"]
    if new_status not in VALID_TRANSITIONS.get(current, []):
        print(f"\033[93m[AEGIS-SOAR] Invalid transition {current} -> {new_status} for {case_id}\033[0m")
        return False

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case["status"]     = new_status
    case["updated_at"] = now
    case["timeline"].append({
        "timestamp": now,
        "status":    new_status,
        "note":      note or f"Status updated to {new_status}"
    })

    if new_status == "CONTAINED":
        case["contained_at"] = now
    if new_status == "RESOLVED":
        case["resolved_at"] = now

    with open(path, "w") as f:
        json.dump(case, f, indent=2)

    color = "\033[92m" if new_status in ("CONTAINED", "RESOLVED") else "\033[93m"
    print(f"{color}[AEGIS-SOAR] {case_id} → {new_status}\033[0m")
    return True


def log_step(case_id, step_id, action, result, success=True):
    path = _case_path(case_id)
    if not os.path.exists(path):
        return

    with open(path) as f:
        case = json.load(f)

    case["steps_executed"].append({
        "step_id":   step_id,
        "action":    action,
        "result":    result,
        "success":   success,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    with open(path, "w") as f:
        json.dump(case, f, indent=2)


def set_enrichment(case_id, enrichment):
    path = _case_path(case_id)
    if not os.path.exists(path):
        return
    with open(path) as f:
        case = json.load(f)
    case["enrichment"] = enrichment
    with open(path, "w") as f:
        json.dump(case, f, indent=2)


def get_case(case_id):
    path = _case_path(case_id)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def list_cases(status=None):
    cases = []
    for fname in os.listdir(CASES_DIR):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(CASES_DIR, fname)) as f:
            case = json.load(f)
        if status is None or case["status"] == status:
            cases.append(case)
    return sorted(cases, key=lambda c: c["created_at"], reverse=True)


def print_summary():
    cases = list_cases()
    counts = {}
    for c in cases:
        counts[c["status"]] = counts.get(c["status"], 0) + 1

    print(f"\n\033[96m[AEGIS-SOAR] ── Case Summary ──────────────────────────\033[0m")
    print(f"\033[96m[AEGIS-SOAR] Total cases: {len(cases)}\033[0m")
    for status, count in counts.items():
        bar = "█" * count
        print(f"\033[96m[AEGIS-SOAR]   {status:<15} {bar} ({count})\033[0m")
    print(f"\033[96m[AEGIS-SOAR] ─────────────────────────────────────────────\033[0m\n")

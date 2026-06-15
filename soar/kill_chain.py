"""
Cyber Kill Chain mapping for AEGIS + IRIS detections.

Lockheed Martin Kill Chain (7 stages):
  1 - Reconnaissance        attacker maps the target
  2 - Weaponization         exploit crafted
  3 - Delivery              exploit delivered to target
  4 - Exploitation          vulnerability triggered
  5 - Installation          foothold established
  6 - Command & Control     attacker takes remote control
  7 - Actions on Objectives data theft / ransomware / destruction
"""

STAGES = {
    1: "Reconnaissance",
    2: "Weaponization",
    3: "Delivery",
    4: "Exploitation",
    5: "Installation",
    6: "Command & Control",
    7: "Actions on Objectives",
}

# AEGIS network threat → kill chain stage
AEGIS_THREAT_MAP = {
    "PORT SCAN":         {"stage": 1, "name": "Reconnaissance",        "rationale": "Attacker probing open ports and services"},
    "ICMP FLOOD":        {"stage": 3, "name": "Delivery",               "rationale": "Volumetric payload delivery attempt"},
    "SYN FLOOD":         {"stage": 3, "name": "Delivery",               "rationale": "TCP handshake exploit delivery"},
    "UDP FLOOD":         {"stage": 3, "name": "Delivery",               "rationale": "UDP-based DDoS delivery"},
    "ML ANOMALY":        {"stage": 4, "name": "Exploitation",           "rationale": "Anomalous behavior pattern — exploit in progress"},
    "ENSEMBLE-BLOCK":    {"stage": 4, "name": "Exploitation",           "rationale": "Multi-detector consensus — active exploitation"},
    "IPS BLOCK":         {"stage": 4, "name": "Exploitation",           "rationale": "IPS intervention during exploitation attempt"},
    "ENTROPY HIGH":      {"stage": 6, "name": "Command & Control",      "rationale": "High-entropy traffic indicating encrypted C2 tunnel"},
    "SOAR-ESCALATE":     {"stage": 7, "name": "Actions on Objectives",  "rationale": "Repeat attacker escalated to subnet — persistent threat"},
    "CORRELATED-ATTACK": {"stage": 6, "name": "Command & Control",      "rationale": "Multi-vector simultaneous attack — coordinated C2 campaign"},
}

# IRIS MITRE ATLAS TTP → kill chain stage
IRIS_TTP_MAP = {
    "privilege_escalation": {"stage": 3, "name": "Delivery",              "rationale": "Prompt injection delivers malicious instruction to LLM"},
    "lateral_movement":     {"stage": 4, "name": "Exploitation",          "rationale": "Adversarial data exploits model trust boundaries"},
    "permission_violation": {"stage": 5, "name": "Installation",          "rationale": "Unauthorized access establishes persistent foothold"},
    "tool_misuse":          {"stage": 6, "name": "Command & Control",     "rationale": "LLM plugin compromised as C2 channel"},
    "data_exfiltration":    {"stage": 7, "name": "Actions on Objectives", "rationale": "ML inference used to exfiltrate sensitive data"},
    "agent_collusion":      {"stage": 6, "name": "Command & Control",     "rationale": "Cross-agent collusion mirrors botnet C2 coordination"},
}

# Collusion detection type → kill chain stage
IRIS_COLLUSION_MAP = {
    "PROMPT_INJECTION":     {"stage": 3, "name": "Delivery"},
    "AGENT_COLLUSION":      {"stage": 6, "name": "Command & Control"},
    "HIGH_RISK_TOOL_CALL":  {"stage": 5, "name": "Installation"},
}

# Next predicted stage (for threat intel)
NEXT_STAGE = {
    1: {"next": 3, "prediction": "Expect Delivery attempt (SYN/ICMP flood or prompt injection)"},
    3: {"next": 4, "prediction": "Expect Exploitation (ensemble block or divergence detection)"},
    4: {"next": 5, "prediction": "Expect Installation (foothold via tool misuse or persistence)"},
    5: {"next": 6, "prediction": "Expect C2 (encrypted tunnel or cross-agent coordination)"},
    6: {"next": 7, "prediction": "Expect Actions on Objectives (data exfiltration or destruction)"},
    7: {"next": None, "prediction": "Attacker at final stage — immediate containment required"},
}


def get_stage_for_aegis(alert_type):
    """Return kill chain info for an AEGIS threat type."""
    info = AEGIS_THREAT_MAP.get(alert_type)
    if not info:
        return {"stage": 0, "name": "Unknown", "rationale": "Unclassified threat"}
    return {**info, "next": NEXT_STAGE.get(info["stage"], {})}


def get_stage_for_iris_ttp(ttp_key):
    """Return kill chain info for an IRIS TTP key."""
    info = IRIS_TTP_MAP.get(ttp_key)
    if not info:
        return {"stage": 0, "name": "Unknown", "rationale": "Unclassified TTP"}
    return {**info, "next": NEXT_STAGE.get(info["stage"], {})}


def get_stage_for_iris_signal(signal_type):
    """Return kill chain info for an IRIS XDR signal type."""
    info = IRIS_COLLUSION_MAP.get(signal_type)
    if not info:
        return {"stage": 0, "name": "Unknown"}
    return {**info, "next": NEXT_STAGE.get(info["stage"], {})}


def get_highest_stage(signals):
    """Given a list of signal dicts with 'stage', return the most advanced."""
    stages = [s.get("kill_chain", {}).get("stage", 0) for s in signals if s.get("kill_chain")]
    return max(stages) if stages else 0


def progression_summary(stages_seen):
    """
    Given a list of observed stages (e.g. [1, 3, 4]),
    return a human-readable campaign progression string.
    """
    if not stages_seen:
        return "No stages observed"
    stages_seen = sorted(set(stages_seen))
    labels = [f"Stage {s} ({STAGES.get(s, '?')})" for s in stages_seen]
    highest = stages_seen[-1]
    skipped = [s for s in range(stages_seen[0], highest + 1) if s not in stages_seen]
    summary = " → ".join(labels)
    if skipped:
        summary += f"  [skipped stages: {skipped} — sophisticated attacker]"
    return summary

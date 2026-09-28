"""
Context-Aware Risk Scoring & Evidence Fusion Engine — CloudIntelliGuard.

Combines multi-dimensional behavioral, graph, and security telemetry into an
explainable composite risk score (0–100).

Risk Policy Matrix:
  0–24  : LOW      ➔ Monitor
  25–49 : MEDIUM   ➔ Alert + Monitor
  50–74 : HIGH     ➔ Automatically Restrict (Privilege Quarantine)
  75+   : CRITICAL ➔ Automatically Block (Session Revocation & Access Block)
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

FACTOR_MAX_CONTRIBUTIONS: Dict[str, float] = {
    "gnn_graph_evidence":        25.0,
    "behavioral_deviation":      15.0,
    "ip_anomaly":                15.0,
    "login_anomaly":             10.0,
    "api_anomaly":               12.0,
    "privilege_escalation":      20.0,
    "sensitive_resource_access": 15.0,
    "temporal_anomaly":           8.0,
    "attack_path_correlation":   12.0,
}

RISK_LEVELS = [
    ("CRITICAL", 75.0, "Automatically Block"),
    ("HIGH",     50.0, "Automatically Restrict"),
    ("MEDIUM",   25.0, "Alert + Monitor"),
    ("LOW",       0.0, "Monitor"),
]


@dataclass
class RiskFactorResult:
    factor: str
    contribution: float
    description: str
    raw_value: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "factor": self.factor,
            "contribution": round(self.contribution, 2),
            "description": self.description,
            "raw_value": round(self.raw_value, 4) if self.raw_value is not None else None,
        }


def compute_risk_score(
    anomaly_score: float = 0.0,
    is_anomaly: bool = False,
    event_count: int = 0,
    failed_request_count: int = 0,
    unique_services: Optional[List[str]] = None,
    unusual_services: Optional[List[str]] = None,
    sensitive_resources: Optional[List[str]] = None,
    historical_avg_requests: Optional[float] = None,
    recent_intensity: Optional[float] = None,
    is_coordinated: bool = False,
    temporal_anomaly_score: Optional[float] = None,
    # Explicit evidence fusion dimensions:
    has_new_ip: bool = False,
    has_login_anomaly: bool = False,
    has_privilege_escalation: bool = False,
    has_attack_path: bool = False,
    attack_path_score: Optional[float] = None,
    new_ips_count: int = 0,
    privilege_actions_count: int = 0,
    is_off_hours: bool = False,
) -> Tuple[float, str, List[RiskFactorResult]]:
    """
    Compute explainable, context-aware risk score through evidence fusion.

    All inputs are derived from real observed event telemetry or ML/GNN outputs.
    No random numbers are used. The function is strictly deterministic.

    Returns:
        (risk_score: float 0–100, risk_level: str, factors: List[RiskFactorResult])
    """
    factors: List[RiskFactorResult] = []
    total = 0.0

    unique_services = unique_services or []
    unusual_services = unusual_services or []
    sensitive_resources = sensitive_resources or []

    # 1. GNN / Graph Relational Evidence (0–25)
    gnn_contrib = float(anomaly_score) * FACTOR_MAX_CONTRIBUTIONS["gnn_graph_evidence"]
    if is_anomaly:
        gnn_contrib = min(FACTOR_MAX_CONTRIBUTIONS["gnn_graph_evidence"], gnn_contrib * 1.25)
    if gnn_contrib > 0.5:
        factors.append(RiskFactorResult(
            factor="GNN Graph Evidence",
            contribution=gnn_contrib,
            description=f"GNN relational anomaly score: {anomaly_score:.3f}" + (" (anomalous pattern flagged)" if is_anomaly else ""),
            raw_value=anomaly_score,
        ))
        total += gnn_contrib

    # 2. Behavioral Deviation (0–15)
    if historical_avg_requests is not None and historical_avg_requests > 0:
        dev = max(0.0, (event_count - historical_avg_requests) / historical_avg_requests)
        dev_contrib = min(FACTOR_MAX_CONTRIBUTIONS["behavioral_deviation"], dev * 10.0)
        if dev_contrib > 0.5:
            factors.append(RiskFactorResult(
                factor="Behavioral Deviation",
                contribution=dev_contrib,
                description=f"Observed volume ({event_count} events) exceeds historical baseline avg ({historical_avg_requests:.0f}) by {dev * 100:.0f}%",
                raw_value=dev,
            ))
            total += dev_contrib

    # 3. IP Anomaly / Location Shift (0–15)
    if has_new_ip or new_ips_count > 0:
        count = max(1, new_ips_count)
        ip_contrib = min(FACTOR_MAX_CONTRIBUTIONS["ip_anomaly"], 10.0 + (count - 1) * 2.5)
        factors.append(RiskFactorResult(
            factor="New IP / Location Anomaly",
            contribution=ip_contrib,
            description=f"Activity originated from {count} newly observed external IP address(es) not seen in user baseline",
            raw_value=float(count),
        ))
        total += ip_contrib

    # 4. Login Anomaly (0–10)
    if has_login_anomaly:
        login_contrib = FACTOR_MAX_CONTRIBUTIONS["login_anomaly"]
        factors.append(RiskFactorResult(
            factor="Login Anomaly",
            contribution=login_contrib,
            description="Abnormal login timing or atypical authentication velocity detected",
            raw_value=1.0,
        ))
        total += login_contrib

    # 5. API Anomaly / Unusual Services & Failure Rate (0–12)
    api_score = 0.0
    desc_parts = []
    if unusual_services:
        ratio = len(unusual_services) / max(1, len(unique_services))
        svc_part = ratio * 7.0
        api_score += svc_part
        desc_parts.append(f"{len(unusual_services)} unusual service(s) ({', '.join(unusual_services[:3])})")

    if event_count > 0 and failed_request_count > 0:
        fail_ratio = failed_request_count / event_count
        fail_part = min(5.0, fail_ratio * 10.0)
        api_score += fail_part
        desc_parts.append(f"{failed_request_count}/{event_count} failed requests ({fail_ratio:.0%})")

    if api_score > 0.5:
        api_contrib = min(FACTOR_MAX_CONTRIBUTIONS["api_anomaly"], api_score)
        factors.append(RiskFactorResult(
            factor="Unusual API Activity",
            contribution=api_contrib,
            description="; ".join(desc_parts),
            raw_value=api_score,
        ))
        total += api_contrib

    # 6. Privilege Escalation (0–20)
    has_pe = has_privilege_escalation or privilege_actions_count > 0 or any(
        s.lower() in ("iam", "sts", "organizations") for s in unusual_services
    )
    if has_pe:
        pe_count = max(1, privilege_actions_count)
        pe_contrib = min(FACTOR_MAX_CONTRIBUTIONS["privilege_escalation"], 14.0 + pe_count * 2.0)
        factors.append(RiskFactorResult(
            factor="Privilege Escalation",
            contribution=pe_contrib,
            description=f"Detected {pe_count} IAM credential creation, policy attachment, or role escalation operation(s)",
            raw_value=float(pe_count),
        ))
        total += pe_contrib

    # 7. Sensitive Resource Access (0–15)
    if sensitive_resources:
        sens_contrib = min(FACTOR_MAX_CONTRIBUTIONS["sensitive_resource_access"], 6.0 + len(sensitive_resources) * 3.0)
        factors.append(RiskFactorResult(
            factor="Sensitive Resource Access",
            contribution=sens_contrib,
            description=f"Accessed {len(sensitive_resources)} sensitive cloud resource(s) (KMS keys, Secrets, DB backups)",
            raw_value=float(len(sensitive_resources)),
        ))
        total += sens_contrib

    # 8. Temporal Anomaly (0–8)
    if is_off_hours or (temporal_anomaly_score and temporal_anomaly_score > 0.3):
        t_score = temporal_anomaly_score if temporal_anomaly_score else 0.8
        temp_contrib = min(FACTOR_MAX_CONTRIBUTIONS["temporal_anomaly"], t_score * 8.0)
        factors.append(RiskFactorResult(
            factor="Temporal Anomaly",
            contribution=temp_contrib,
            description="Activity occurred during abnormal off-hours window (01:00–05:00 UTC)",
            raw_value=t_score,
        ))
        total += temp_contrib

    # 9. Attack-Path Correlation (0–12)
    if has_attack_path or (attack_path_score and attack_path_score > 0):
        ap_val = attack_path_score or 1.0
        ap_contrib = min(FACTOR_MAX_CONTRIBUTIONS["attack_path_correlation"], 8.0 + ap_val * 4.0)
        factors.append(RiskFactorResult(
            factor="Attack-Path Correlation",
            contribution=ap_contrib,
            description="Correlated multi-hop traversal from initial identity through intermediate services to target resource",
            raw_value=ap_val,
        ))
        total += ap_contrib

    # Clamp composite score to 0–100
    total = round(min(100.0, max(0.0, total)), 1)

    # Determine risk level from exact policy
    risk_level = "LOW"
    for level, threshold, _ in RISK_LEVELS:
        if total >= threshold:
            risk_level = level
            break

    return total, risk_level, factors


def get_policy_action_for_level(risk_level: str) -> str:
    """Return the exact policy action name for a risk level."""
    for level, _, action in RISK_LEVELS:
        if level == risk_level.upper():
            return action
    return "Monitor"

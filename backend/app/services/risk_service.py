"""
Risk scoring service — CloudIntelliGuard.

Orchestrates context computation and persists RiskScore records to the database.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.models.database_models import Anomaly, CloudEvent, GraphWindow, RiskScore
from app.ml.risk.scorer import compute_risk_score, RiskFactorResult
from app.services.feature_engineering import (
    extract_raw_features, extract_derived_features,
    SENSITIVE_SERVICES,
)
from app.services.preprocessing import load_processed_dataframe

# Services we consider "unusual" if not seen before in historical data
_COMMON_SERVICES = {"s3", "ec2", "cloudwatch", "elb", "lambda"}


async def compute_and_store_risk(
    db: AsyncSession,
    anomaly: Anomaly,
    graph_window: GraphWindow,
    is_coordinated: bool = False,
) -> RiskScore:
    """
    Compute context-aware risk score for a user and persist it.

    Args:
        db: Async database session
        anomaly: The Anomaly record for this user/window
        graph_window: The GraphWindow containing the events
        is_coordinated: Whether user is part of a coordinated event

    Returns:
        Persisted RiskScore ORM object.
    """
    # Load events for this window
    events_result = await db.execute(
        select(CloudEvent).where(
            CloudEvent.dataset_id == graph_window.dataset_id,
            CloudEvent.timestamp >= graph_window.start_time,
            CloudEvent.timestamp < graph_window.end_time,
        )
    )
    events = events_result.scalars().all()
    df = load_processed_dataframe(events)

    uid = anomaly.cloud_user_id
    raw = extract_raw_features(df, uid)
    derived = extract_derived_features(
        df, uid,
        window_start=graph_window.start_time,
        window_end=graph_window.end_time,
    )

    unique_services: List[str] = raw.get("services", [])
    user_services_lower = set(s.lower() for s in unique_services)
    unusual_services = [
        s for s in unique_services
        if s.lower() not in _COMMON_SERVICES
    ]
    sensitive_resources: List[str] = derived.get("sensitive_resources", [])

    # Check for specific evidence dimensions
    user_evs = [ev for ev in events if ev.cloud_user_id == uid]
    ip_list = list(set(ev.source_ip for ev in user_evs if ev.source_ip))
    user_actions = [str(ev.action).lower() for ev in user_evs if ev.action]
    
    privilege_keywords = ("createaccesskey", "attachuserpolicy", "putuserpolicy", "createuser", "createrole", "assumerole", "addusertogroup", "admin", "updatelogin")
    privilege_actions = [a for a in user_actions if any(pk in a for pk in privilege_keywords)]
    
    # Check off-hours (00:00 - 05:00 UTC)
    has_off_hours = any(ev.timestamp and ev.timestamp.hour < 6 for ev in user_evs)

    # Check login actions
    has_login = any("login" in a or "signin" in a for a in user_actions)
    has_external_ip = any(not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.") for ip in ip_list)
    has_login_anomaly = has_login and (has_off_hours or has_external_ip)

    # Extract sensitive resources directly from events
    all_sens = list(derived.get("sensitive_resources", []))
    for ev in user_evs:
        svc_lower = str(ev.service or "").lower()
        res_lower = str(ev.resource or "").lower()
        if svc_lower in ("secretsmanager", "kms", "rds") or any(sk in res_lower for sk in ("secret", "key", "backup", "vault", "password", "cred")):
            all_sens.append(ev.resource or ev.service)
    sensitive_resources = list(set(all_sens))

    # Attack path check
    from app.services.attack_path_service import get_attack_paths
    paths = await get_attack_paths(db, cloud_user_id=uid)
    has_attack_path = len(paths) > 0 and len(sensitive_resources) > 0 and len(privilege_actions) > 0
    attack_path_score = paths[0].get("path_risk_score", 0) / 100.0 if (paths and has_attack_path) else 0.0

    risk_score, risk_level, factors = compute_risk_score(
        anomaly_score=anomaly.anomaly_score,
        is_anomaly=anomaly.is_anomaly,
        event_count=raw.get("event_count", 0),
        failed_request_count=derived.get("failed_count", 0) or 0,
        unique_services=unique_services,
        unusual_services=unusual_services,
        sensitive_resources=sensitive_resources,
        historical_avg_requests=derived.get("historical_avg_daily_requests"),
        recent_intensity=derived.get("recent_intensity"),
        is_coordinated=is_coordinated,
        temporal_anomaly_score=0.8 if has_off_hours else None,
        has_new_ip=has_external_ip,
        new_ips_count=len(ip_list),
        has_login_anomaly=has_login_anomaly,
        has_privilege_escalation=len(privilege_actions) > 0,
        privilege_actions_count=len(privilege_actions),
        has_attack_path=has_attack_path,
        attack_path_score=attack_path_score if has_attack_path else None,
        is_off_hours=has_off_hours,
    )

    rs = RiskScore(
        cloud_user_id=uid,
        graph_window_id=graph_window.id,
        anomaly_id=anomaly.id,
        risk_score=risk_score,
        risk_level=risk_level,
        factors=[f.to_dict() for f in factors],
    )
    db.add(rs)
    await db.commit()
    await db.refresh(rs)

    # Autonomous Security Response Policy Trigger
    from app.services.response_service import evaluate_and_enforce_user_risk
    reason_desc = f"{risk_level} risk score ({risk_score:.1f}) in Window #{graph_window.id}"
    await evaluate_and_enforce_user_risk(
        db=db,
        cloud_user_id=uid,
        risk_score=risk_score,
        risk_level=risk_level,
        reason=reason_desc,
        trigger_anomaly_id=anomaly.id,
    )

    logger.info(f"Risk scored for {uid}: {risk_score} ({risk_level})")
    return rs


async def compute_continuous_risk_evolution(
    db: AsyncSession,
    cloud_user_id: str,
) -> List[Dict[str, Any]]:

    normalized_user_id = cloud_user_id.strip().lower()

    stmt = (
        select(CloudEvent)
        .where(
            func.lower(
                func.trim(CloudEvent.cloud_user_id)
            ) == normalized_user_id
        )
        .order_by(CloudEvent.timestamp.asc())
    )

    res = await db.execute(stmt)
    events = res.scalars().all()

    if not events:
        return []
    # Partition events into sequential checkpoints (up to 8 chronological steps)
    n_events = len(events)
    if n_events <= 4:
        step_indices = list(range(n_events))
    else:
        # Pick progressive checkpoints from start to finish
        step_indices = sorted(list(set([
            0,
            int(n_events * 0.25),
            int(n_events * 0.50),
            int(n_events * 0.70),
            int(n_events * 0.85),
            n_events - 1,
        ])))

    evolution_points = []
    seen_ips = set()
    seen_services = set()
    privilege_seen = 0
    sensitive_seen = 0

    privilege_keywords = ("createaccesskey", "attachuserpolicy", "putuserpolicy", "createuser", "createrole", "assumerole", "addusertogroup", "admin")

    for idx in step_indices:
        sub_events = events[: idx + 1]
        last_ev = sub_events[-1]
        ts = last_ev.timestamp
        ts_str = ts.strftime("%H:%M:%S") if ts else "N/A"
        date_str = ts.strftime("%Y-%m-%d %H:%M:%SZ") if ts else "N/A"

        # Tally cumulative telemetry up to this step
        sub_ips = set(ev.source_ip for ev in sub_events if ev.source_ip)
        sub_services = set(ev.service.lower() for ev in sub_events if ev.service)
        sub_actions = [str(ev.action or "").lower() for ev in sub_events]
        sub_failures = sum(1 for ev in sub_events if ev.status and "fail" in str(ev.status).lower())

        sub_privilege = sum(1 for a in sub_actions if any(pk in a for pk in privilege_keywords))
        sub_sensitive = sum(
            1 for ev in sub_events 
            if (ev.service and ev.service.lower() in ("secretsmanager", "kms", "rds"))
            or (ev.resource and any(sk in str(ev.resource).lower() for sk in ("secret", "key", "backup", "password", "cred")))
        )

        has_new_external_ip = any(
            not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.")
            for ip in sub_ips
        )
        is_off_hours = ts.hour < 6 if ts else False

        # Estimated progressive anomaly score based on suspicious behaviors
        base_anomaly = 0.05
        if has_new_external_ip:
            base_anomaly += 0.20
        if sub_privilege > 0:
            base_anomaly += 0.35
        if sub_sensitive > 0:
            base_anomaly += 0.25
        if sub_failures >= 3:
            base_anomaly += 0.15
        base_anomaly = min(0.95, base_anomaly)

        score, level, factors = compute_risk_score(
            anomaly_score=base_anomaly,
            is_anomaly=base_anomaly > 0.45,
            event_count=len(sub_events),
            failed_request_count=sub_failures,
            unique_services=list(sub_services),
            unusual_services=[s for s in sub_services if s not in ("s3", "ec2", "cloudwatch", "lambda")],
            sensitive_resources=[f"sensitive_resource_{i+1}" for i in range(min(5, sub_sensitive))],
            historical_avg_requests=10.0,
            has_new_ip=has_new_external_ip,
            new_ips_count=len(sub_ips),
            has_privilege_escalation=sub_privilege > 0,
            privilege_actions_count=sub_privilege,
            has_attack_path=sub_sensitive > 0 and sub_privilege > 0,
            attack_path_score=0.85 if (sub_sensitive > 0 and sub_privilege > 0) else 0.0,
            is_off_hours=is_off_hours,
        )

        from app.ml.risk.scorer import get_policy_action_for_level
        action_name = get_policy_action_for_level(level)

        trigger_desc = f"{last_ev.action or 'Event'} on {last_ev.service or 'service'}"
        if sub_privilege > privilege_seen:
            trigger_desc = f"Privilege Escalation ({last_ev.action})"
        elif sub_sensitive > sensitive_seen:
            trigger_desc = f"Sensitive Resource Access ({last_ev.resource or last_ev.service})"
        elif len(sub_ips) > len(seen_ips) and has_new_external_ip:
            trigger_desc = f"New External IP Observed ({last_ev.source_ip})"
        elif sub_failures > 0 and "fail" in str(last_ev.status or "").lower():
            trigger_desc = f"Authorization Failure on {last_ev.action}"

        privilege_seen = sub_privilege
        sensitive_seen = sub_sensitive
        seen_ips = sub_ips

        evolution_points.append({
            "step": len(evolution_points) + 1,
            "timestamp": date_str,
            "time_label": ts_str,
            "risk_score": score,
            "risk_level": level,
            "policy_action": action_name,
            "trigger_event": trigger_desc,
            "event_action": last_ev.action,
            "service": last_ev.service,
            "source_ip": last_ev.source_ip,
            "status": last_ev.status,
            "cumulative_events": len(sub_events),
            "factors": [f.to_dict() for f in factors],
        })

    return evolution_points


async def get_user_risk_history(
    db: AsyncSession,
    cloud_user_id: str,
    limit: int = 20,
) -> List[RiskScore]:
    """Return recent risk scores for a cloud user (newest first)."""
    result = await db.execute(
        select(RiskScore)
        .where(RiskScore.cloud_user_id == cloud_user_id)
        .order_by(RiskScore.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()

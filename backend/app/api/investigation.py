"""
Investigation Workspace API — CloudIntelliGuard.

Central endpoint serving unified investigation workspace payload:
- User Summary
- Current Risk & Level
- Continuous Risk Evolution Trajectory
- Normal vs Current Behavior Analytics
- Evidence Timeline
- "Why Suspicious?" Explanation
- Multi-Hop Attack Path
- Risk Evidence Fusion Breakdown
- Automated Response State & Policy
- Audit Trail
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database.connection import get_db
from app.models.database_models import (
    Anomaly, AuditLog, CloudEvent, CloudUserEnforcement, RiskScore, User,
)
from app.services.attack_path_service import get_attack_paths
from app.services.risk_service import compute_continuous_risk_evolution
from app.services.uba_service import compute_user_uba_profile, get_all_uba_users
from app.ml.risk.scorer import get_policy_action_for_level

router = APIRouter()


@router.get("/users", summary="List all monitored identities for investigation")
async def list_investigation_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return all monitored cloud identities with risk summary and threat category."""
    users = await get_all_uba_users(db)
    
    # Enrich with latest anomaly category if available
    for u in users:
        uid = u["cloud_user_id"]
        stmt = select(Anomaly).where(Anomaly.cloud_user_id == uid).order_by(Anomaly.created_at.desc())
        res = await db.execute(stmt)
        anom = res.scalars().first()
        if anom and anom.explanation:
            summary = anom.explanation.get("summary", "")
            if "privilege" in summary.lower():
                u["threat_category"] = "Privilege Escalation"
            elif "exfiltration" in summary.lower() or "secret" in summary.lower():
                u["threat_category"] = "Data Exfiltration"
            elif "reconnaissance" in summary.lower() or "service" in summary.lower():
                u["threat_category"] = "Cloud Reconnaissance"
            else:
                u["threat_category"] = "Behavioral Anomaly"
        else:
            u["threat_category"] = "Standard Activity"

    return users


@router.get("/{cloud_user_id}", summary="Get unified investigation payload for identity")
async def get_investigation_details(
    cloud_user_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Consolidated investigation workspace data:
    1. User Summary & Status
    2. Current Risk Score & Level
    3. Continuous User Risk Evolution Timeline
    4. Normal vs Current Behavior Analytics
    5. Evidence Timeline
    6. "Why Suspicious?" Explanation
    7. Attack Path Steps
    8. Risk Evidence Fusion Factor Breakdown
    9. Current Automated Response Enforcement
    10. Audit History
    """
    uid = cloud_user_id.strip().lower()

    # 1. Fetch & synchronize Enforcement with latest calculated risk
    from app.services.response_service import synchronize_user_enforcement
    enforcement = await synchronize_user_enforcement(db, uid)
    if enforcement is None:
        from sqlalchemy import func
        enf_stmt = select(CloudUserEnforcement).where(func.lower(func.trim(CloudUserEnforcement.cloud_user_id)) == uid)
        enf_res = await db.execute(enf_stmt)
        enforcement = enf_res.scalar_one_or_none()

    # 2. Fetch UBA profile (baseline vs current, behavior diffs, why suspicious)
    uba = await compute_user_uba_profile(db, uid)

    # 3. Fetch Continuous Risk Evolution
    evolution = await compute_continuous_risk_evolution(db, uid)

    # 4. Fetch Attack Paths
    attack_paths = await get_attack_paths(db, cloud_user_id=uid)
    primary_attack_path = attack_paths[0] if attack_paths else None

    # 5. Fetch Recent RiskScore record for factor contributions
    rs_stmt = select(RiskScore).where(RiskScore.cloud_user_id == uid).order_by(RiskScore.created_at.desc())
    rs_res = await db.execute(rs_stmt)
    latest_rs = rs_res.scalars().first()

    factors = latest_rs.factors if (latest_rs and latest_rs.factors) else []
    if not factors and evolution:
        factors = evolution[-1].get("factors", [])

    # 6. Fetch Audit Logs for this identity
    audit_stmt = (
        select(AuditLog)
        .where(AuditLog.resource.like(f"%{uid}%"))
        .order_by(AuditLog.timestamp.desc())
        .limit(20)
    )
    audit_res = await db.execute(audit_stmt)
    audit_records = [
        {
            "id": a.id,
            "action": a.action,
            "resource": a.resource,
            "detail": a.detail,
            "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%SZ"),
            "time": a.timestamp.strftime("%H:%M:%S"),
        }
        for a in audit_res.scalars().all()
    ]

    current_risk_score = enforcement.risk_score if enforcement else (latest_rs.risk_score if latest_rs else uba.get("current_risk_score", 0.0))
    current_risk_level = enforcement.risk_level if enforcement else (latest_rs.risk_level if latest_rs else uba.get("current_risk_level", "LOW"))
    current_status = enforcement.status if enforcement else "ACTIVE"

    policy_action = get_policy_action_for_level(current_risk_level)

    return {
        "cloud_user_id": uid,
        "summary": {
            "identity": uid,
            "status": current_status,
            "risk_score": current_risk_score,
            "risk_level": current_risk_level,
            "policy_action": policy_action,
            "session_revoked": enforcement.session_revoked if enforcement else False,
            "restriction_reason": enforcement.restriction_reason if enforcement else None,
            "blocking_reason": enforcement.blocking_reason if enforcement else None,
            "first_seen": uba.get("activity_tracking", {}).get("first_seen", "N/A"),
            "last_seen": uba.get("activity_tracking", {}).get("last_seen", "N/A"),
            "total_events": uba.get("activity_tracking", {}).get("total_events", 0),
        },
        "current_risk": {
            "score": current_risk_score,
            "level": current_risk_level,
            "policy_action": policy_action,
            "status": current_status,
            "session_revoked": enforcement.session_revoked if enforcement else False,
        },
        "risk_evolution": evolution,
        "uba_profile": {
            "deviation_score": uba.get("deviation_score", 0.0),
            "baseline": uba.get("baseline", {}),
            "current_behavior": uba.get("current_behavior", {}),
            "behavior_diffs": uba.get("behavior_diffs", []),
            "suspicious_indicators": uba.get("suspicious_indicators", []),
        },
        "why_suspicious": uba.get("why_suspicious", "No suspicious anomalies detected."),
        "evidence_timeline": uba.get("recent_events", []),
        "suspicious_events": uba.get("suspicious_events", []),
        "attack_path": primary_attack_path,
        "risk_contributors": factors,
        "automated_response": {
            "status": current_status,
            "policy_action": policy_action,
            "session_revoked": enforcement.session_revoked if enforcement else False,
            "restriction_reason": enforcement.restriction_reason if enforcement else None,
            "blocking_reason": enforcement.blocking_reason if enforcement else None,
            "history": enforcement.history if (enforcement and enforcement.history) else [],
        },
        "audit_trail": audit_records,
    }
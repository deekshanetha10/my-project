"""
Automated Security Response Service — CloudIntelliGuard.

Autonomous, risk-based policy execution engine:
  - LOW      (0–24) : Monitor only
  - MEDIUM  (25–49) : Alert + Continue Monitoring
  - HIGH    (50–74) : Automatically RESTRICT user (quarantine sensitive APIs) + Audit Log
  - CRITICAL (75+)  : Automatically BLOCK user + Revoke Sessions + Critical Incident + Audit Log

Ensures safety: all enforcement actions are recorded with reasons and audit trails.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger, log_audit
from app.models.database_models import AuditLog, CloudUserEnforcement, Incident


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


AUTOMATED_POLICIES = [
    {
        "level": "CRITICAL",
        "threshold": "Risk Score ≥ 75",
        "action": "Automatically Block",
        "effect": "Application-level enforcement: Revoke active credentials & sessions, block further API access, create critical incident.",
        "auto_trigger": True,
    },
    {
        "level": "HIGH",
        "threshold": "Risk Score 50–74",
        "action": "Automatically Restrict",
        "effect": "Application-level enforcement: Restrict sensitive resource/IAM access, quarantine privilege, increase audit logging.",
        "auto_trigger": True,
    },
    {
        "level": "MEDIUM",
        "threshold": "Risk Score 25–49",
        "action": "Alert + Monitor",
        "effect": "Generate operational alert, continue continuous baseline anomaly tracking.",
        "auto_trigger": True,
    },
    {
        "level": "LOW",
        "threshold": "Risk Score 0–24",
        "action": "Monitor",
        "effect": "Standard continuous user behavior monitoring.",
        "auto_trigger": False,
    },
]


async def evaluate_and_enforce_user_risk(
    db: AsyncSession,
    cloud_user_id: str,
    risk_score: float,
    risk_level: str,
    reason: Optional[str] = None,
    trigger_anomaly_id: Optional[int] = None,
) -> Tuple[str, Optional[str]]:
    """
    Evaluate calculated risk score and apply automated response policy.
    
    Returns:
        (new_status: 'ACTIVE' | 'RESTRICTED' | 'BLOCKED', action_taken_description: str)
    """
    now = _utcnow()
    stmt = select(CloudUserEnforcement).where(CloudUserEnforcement.cloud_user_id == cloud_user_id)
    result = await db.execute(stmt)
    enforcement = result.scalar_one_or_none()

    if enforcement is None:
        enforcement = CloudUserEnforcement(
            cloud_user_id=cloud_user_id,
            status="ACTIVE",
            risk_score=risk_score,
            risk_level=risk_level,
            last_evaluated_at=now,
            history=[],
        )
        db.add(enforcement)
        await db.flush()

    enforcement.risk_score = risk_score
    enforcement.risk_level = risk_level
    enforcement.last_evaluated_at = now

    old_status = enforcement.status
    action_taken: Optional[str] = None

    if risk_level == "CRITICAL" or risk_score >= 75.0:
        # CRITICAL -> BLOCK
        enforcement.status = "BLOCKED"
        enforcement.blocking_reason = reason or f"Automated block triggered by CRITICAL risk score ({risk_score:.1f})"
        enforcement.blocked_at = now
        enforcement.session_revoked = True
        action_taken = f"AUTOMATED_BLOCK applied to {cloud_user_id} (Session Revoked)"

        _record_history(enforcement, "BLOCK", enforcement.blocking_reason, now)

        # Audit log
        audit = AuditLog(
            action="AUTOMATED_BLOCK",
            resource=f"cloud_user/{cloud_user_id}",
            detail={
                "risk_score": risk_score,
                "risk_level": risk_level,
                "session_revoked": True,
                "reason": enforcement.blocking_reason,
                "trigger_anomaly_id": trigger_anomaly_id,
            },
            timestamp=now,
        )
        db.add(audit)
        logger.warning(f"🚨 [AUTOMATED ENFORCEMENT] BLOCKED user '{cloud_user_id}' — Risk: {risk_score:.1f}")

    elif risk_level == "HIGH" or risk_score >= 50.0:
        # HIGH -> RESTRICT
        enforcement.status = "RESTRICTED"
        enforcement.restriction_reason = reason or f"Automated restriction triggered by HIGH risk score ({risk_score:.1f})"
        enforcement.restricted_at = now
        enforcement.session_revoked = False
        enforcement.blocking_reason = None
        action_taken = f"AUTOMATED_RESTRICTION applied to {cloud_user_id} (Privilege Quarantine)"

        _record_history(enforcement, "RESTRICT", enforcement.restriction_reason, now)

        # Audit log
        audit = AuditLog(
            action="AUTOMATED_RESTRICTION",
            resource=f"cloud_user/{cloud_user_id}",
            detail={
                "risk_score": risk_score,
                "risk_level": risk_level,
                "reason": enforcement.restriction_reason,
                "trigger_anomaly_id": trigger_anomaly_id,
            },
            timestamp=now,
        )
        db.add(audit)
        logger.warning(f"⚠️ [AUTOMATED ENFORCEMENT] RESTRICTED user '{cloud_user_id}' — Risk: {risk_score:.1f}")

    elif risk_level in ("LOW", "MEDIUM"):
        enforcement.status = "ACTIVE"
        enforcement.session_revoked = False
        enforcement.blocking_reason = None
        enforcement.restriction_reason = None
        action_taken = f"NORMAL_MONITORING for {cloud_user_id}"

        if old_status in ("RESTRICTED", "BLOCKED"):
            restore_desc = reason or f"Risk reduced to {risk_level} ({risk_score:.1f}) — Returned to baseline monitoring"
            _record_history(enforcement, "RESTORE", restore_desc, now)
            audit = AuditLog(
                action="AUTOMATED_RESTORE",
                resource=f"cloud_user/{cloud_user_id}",
                detail={
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "old_status": old_status,
                    "new_status": "ACTIVE",
                    "reason": restore_desc,
                    "trigger_anomaly_id": trigger_anomaly_id,
                },
                timestamp=now,
            )
            db.add(audit)
            logger.info(f"✅ [AUTOMATED ENFORCEMENT] Restored user '{cloud_user_id}' to ACTIVE — Risk: {risk_score:.1f}")
    await db.commit()
    await db.refresh(enforcement)
    return enforcement.status, action_taken


async def manual_override_enforcement(
    db: AsyncSession,
    cloud_user_id: str,
    action: str,  # "RESTORE" | "RESTRICT" | "BLOCK"
    reason: str,
    analyst_user_id: Optional[int] = None,
) -> CloudUserEnforcement:
    """Manually override enforcement state by security analyst."""
    now = _utcnow()
    stmt = select(CloudUserEnforcement).where(CloudUserEnforcement.cloud_user_id == cloud_user_id)
    result = await db.execute(stmt)
    enforcement = result.scalar_one_or_none()

    if enforcement is None:
        enforcement = CloudUserEnforcement(
            cloud_user_id=cloud_user_id,
            status="ACTIVE",
            risk_score=0.0,
            risk_level="LOW",
            last_evaluated_at=now,
            history=[],
        )
        db.add(enforcement)
        await db.flush()

    old_status = enforcement.status
    if action.upper() == "RESTORE":
        enforcement.status = "ACTIVE"
        enforcement.session_revoked = False
        enforcement.blocking_reason = None
        enforcement.restriction_reason = None
        log_action = "MANUAL_RESTORE"
    elif action.upper() == "RESTRICT":
        enforcement.status = "RESTRICTED"
        enforcement.restriction_reason = reason
        enforcement.restricted_at = now
        log_action = "MANUAL_RESTRICT"
    elif action.upper() == "BLOCK":
        enforcement.status = "BLOCKED"
        enforcement.blocking_reason = reason
        enforcement.blocked_at = now
        enforcement.session_revoked = True
        log_action = "MANUAL_BLOCK"
    else:
        raise ValueError(f"Invalid override action: {action}")

    _record_history(enforcement, f"MANUAL_{action.upper()}", reason, now)

    audit = AuditLog(
        user_id=analyst_user_id,
        action=log_action,
        resource=f"cloud_user/{cloud_user_id}",
        detail={"old_status": old_status, "new_status": enforcement.status, "reason": reason},
        timestamp=now,
    )
    db.add(audit)

    await db.commit()
    await db.refresh(enforcement)
    logger.info(f"Analyst manually updated enforcement for {cloud_user_id} -> {enforcement.status}")
    return enforcement


async def synchronize_user_enforcement(
    db: AsyncSession,
    cloud_user_id: str,
) -> Optional[CloudUserEnforcement]:
    """
    Ensure a single user's enforcement status is synchronized with their latest calculated risk level.
    Policy:
      LOW (0–24)      -> Monitor / ACTIVE
      MEDIUM (25–49)  -> Alert + Monitor / ACTIVE
      HIGH (50–74)    -> Automatically Restrict / RESTRICTED
      CRITICAL (75+)  -> Automatically Block / BLOCKED
    """
    from app.models.database_models import RiskScore
    now = _utcnow()
    normalized_uid = cloud_user_id.strip().lower()

    # Fetch latest risk score for this identity
    stmt = (
        select(RiskScore)
        .where(func.lower(func.trim(RiskScore.cloud_user_id)) == normalized_uid)
        .order_by(RiskScore.created_at.desc())
    )
    res = await db.execute(stmt)
    latest_rs = res.scalars().first()
    if not latest_rs:
        return None

    # Fetch enforcement record
    enf_stmt = select(CloudUserEnforcement).where(
        func.lower(func.trim(CloudUserEnforcement.cloud_user_id)) == normalized_uid
    )
    enf_res = await db.execute(enf_stmt)
    enforcement = enf_res.scalar_one_or_none()

    score = latest_rs.risk_score
    level = latest_rs.risk_level

    # Final policy mapping
    if score >= 75.0 or level == "CRITICAL":
        target_status = "BLOCKED"
        target_session_revoked = True
        target_blocking = (enforcement.blocking_reason if enforcement else None) or f"Automated block triggered by CRITICAL risk score ({score:.1f})"
        target_restriction = None
        action_name = "BLOCK"
    elif score >= 50.0 or level == "HIGH":
        target_status = "RESTRICTED"
        target_session_revoked = False
        target_restriction = (enforcement.restriction_reason if enforcement else None) or f"Automated restriction triggered by HIGH risk score ({score:.1f})"
        target_blocking = None
        action_name = "RESTRICT"
    else:  # LOW or MEDIUM
        target_status = "ACTIVE"
        target_session_revoked = False
        target_restriction = None
        target_blocking = None
        action_name = "RESTORE"

    if enforcement is None:
        enforcement = CloudUserEnforcement(
            cloud_user_id=latest_rs.cloud_user_id,
            status=target_status,
            risk_score=score,
            risk_level=level,
            session_revoked=target_session_revoked,
            restriction_reason=target_restriction,
            blocking_reason=target_blocking,
            last_evaluated_at=now,
            history=[],
        )
        if target_status != "ACTIVE":
            _record_history(enforcement, action_name, f"Initial policy enforcement: {level} ({score:.1f})", now)
        db.add(enforcement)
        await db.commit()
        await db.refresh(enforcement)
        return enforcement

    # Check if synchronization is needed
    needs_update = (
        enforcement.status != target_status
        or abs(enforcement.risk_score - score) > 0.01
        or enforcement.risk_level != level
        or enforcement.session_revoked != target_session_revoked
    )

    if needs_update:
        old_status = enforcement.status
        enforcement.status = target_status
        enforcement.risk_score = score
        enforcement.risk_level = level
        enforcement.session_revoked = target_session_revoked
        enforcement.restriction_reason = target_restriction
        enforcement.blocking_reason = target_blocking
        enforcement.last_evaluated_at = now

        if old_status != target_status:
            desc = f"Synchronized with latest {level} risk score ({score:.1f}) — Realigned to {target_status}"
            _record_history(enforcement, action_name, desc, now)
            audit = AuditLog(
                action=f"AUTOMATED_{target_status}",
                resource=f"cloud_user/{enforcement.cloud_user_id}",
                detail={
                    "risk_score": score,
                    "risk_level": level,
                    "old_status": old_status,
                    "new_status": target_status,
                    "reason": desc,
                },
                timestamp=now,
            )
            db.add(audit)

        await db.commit()
        await db.refresh(enforcement)

    return enforcement


async def get_all_enforcements(db: AsyncSession) -> List[CloudUserEnforcement]:
    """Return all active enforcements, ensuring synchronization with latest calculated risk."""
    from app.models.database_models import RiskScore
    
    # 1. Collect all distinct users who have risk scores or enforcements
    enf_users_res = await db.execute(select(CloudUserEnforcement.cloud_user_id))
    enf_users = {u.strip().lower(): u for u in enf_users_res.scalars().all() if u}

    risk_users_res = await db.execute(select(RiskScore.cloud_user_id).distinct())
    risk_users = {u.strip().lower(): u for u in risk_users_res.scalars().all() if u}

    all_users = set(enf_users.values()) | set(risk_users.values())

    # 2. Synchronize each user with their latest risk
    for uid in all_users:
        await synchronize_user_enforcement(db, uid)

    # 3. Return sorted enforcements
    result = await db.execute(
        select(CloudUserEnforcement).order_by(CloudUserEnforcement.risk_score.desc())
    )
    return list(result.scalars().all())


def _record_history(enforcement: CloudUserEnforcement, action: str, reason: Optional[str], ts: datetime):
    hist = list(enforcement.history or [])
    hist.append({
        "action": action,
        "reason": reason,
        "timestamp": ts.isoformat(),
    })
    enforcement.history = hist[-20:]  # Keep last 20

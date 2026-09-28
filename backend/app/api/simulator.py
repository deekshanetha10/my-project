"""What-If Risk Simulator API endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database.connection import get_db
from app.models.database_models import CloudEvent, CloudUserEnforcement, RiskScore, User
from app.models.schemas import SimulateRiskRequest, SimulateRiskResponse
from app.ml.risk.scorer import compute_risk_score
from app.services.feature_engineering import extract_raw_features, extract_derived_features
from app.services.preprocessing import load_processed_dataframe

router = APIRouter()


@router.post("/simulate", response_model=SimulateRiskResponse, summary="Simulate behavior changes on risk score")
async def simulate_risk(
    req: SimulateRiskRequest,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    """
    Simulate what happens to a user's risk score when hypothetical behaviors occur.
    Uses the project's native risk scoring function.
    """
    uid = req.cloud_user_id.strip().lower()

    # 1. Fetch user real current enforcement or risk score from DB
    enf_stmt = select(CloudUserEnforcement).where(
        func.lower(func.trim(CloudUserEnforcement.cloud_user_id)) == uid
    )
    enf_res = await db.execute(enf_stmt)
    enforcement = enf_res.scalar_one_or_none()

    # 2. Fetch user events to extract baseline telemetry
    stmt = (
        select(CloudEvent)
        .where(func.lower(func.trim(CloudEvent.cloud_user_id)) == uid)
        .order_by(CloudEvent.timestamp.asc())
    )
    res = await db.execute(stmt)
    events = res.scalars().all()

    if enforcement is not None:
        current_score = enforcement.risk_score
        current_level = enforcement.risk_level
    else:
        # If not evaluated yet, check recent risk score record
        rs_stmt = (
            select(RiskScore)
            .where(func.lower(func.trim(RiskScore.cloud_user_id)) == uid)
            .order_by(RiskScore.created_at.desc())
        )
        rs_res = await db.execute(rs_stmt)
        rs = rs_res.scalars().first()
        if rs is not None:
            current_score = rs.risk_score
            current_level = rs.risk_level
        else:
            current_score = 15.0
            current_level = "LOW"

    # Base values from events
    if events:
        df = load_processed_dataframe(events)
        raw = extract_raw_features(df, uid)
        derived = extract_derived_features(df, uid)
        event_count = raw.get("event_count", 10)
        unique_services = raw.get("services", ["s3", "ec2"])
        failed_count = raw.get("failure_count", 0) or 0
    else:
        event_count = 15
        unique_services = ["s3", "ec2"]
        failed_count = 0

    # Base anomaly score
    sim_anomaly_score = 0.10
    sim_event_count = event_count
    sim_failed_count = failed_count
    sim_unusual_services = []
    sim_sensitive_resources = []
    sim_recent_intensity = 0.1

    # Apply hypothetical toggles
    has_new_ip = req.new_ip_location or req.unusual_login
    has_pe = req.privilege_escalation
    has_sensitive = req.sensitive_resource_access
    is_off_hours = req.temporal_anomaly
    has_attack_chain = False

    if req.abnormal_api_activity:
        sim_event_count = max(event_count * 3, 60)
        sim_recent_intensity = 0.90
        sim_anomaly_score = max(sim_anomaly_score, 0.55)

    if req.privilege_escalation:
        sim_anomaly_score = max(sim_anomaly_score, 0.75)
        sim_sensitive_resources.extend(["arn:aws:iam:::role/AdminAccess", "arn:aws:iam:::policy/AdministratorAccess"])
        sim_unusual_services.append("iam")

    if req.sensitive_resource_access:
        sim_sensitive_resources.extend(["arn:aws:secretsmanager:::secret/production_db_creds", "arn:aws:kms:::key/master-key"])
        sim_unusual_services.append("secretsmanager")

    if req.multiple_failed_logins:
        sim_failed_count = max(failed_count + 8, 8)
        sim_event_count = max(sim_event_count, sim_failed_count + 5)
        sim_anomaly_score = max(sim_anomaly_score, 0.45)

    if req.unusual_login or req.new_ip_location:
        sim_anomaly_score = max(sim_anomaly_score, 0.50)
        sim_unusual_services.append("sts")

    if (req.privilege_escalation or req.sensitive_resource_access) and (req.new_ip_location or req.unusual_login):
        has_attack_chain = True

    # 1. Compute Base Simulated Risk Score (WITHOUT hypothetical toggles)
    from app.ml.risk.scorer import compute_risk_score, get_policy_action_for_level, RISK_LEVELS
    base_score, _, _ = compute_risk_score(
        anomaly_score=0.10,
        is_anomaly=False,
        event_count=event_count,
        failed_request_count=failed_count,
        unique_services=unique_services,
        unusual_services=[],
        sensitive_resources=[],
        historical_avg_requests=float(event_count),
        recent_intensity=0.1,
        is_coordinated=False,
        temporal_anomaly_score=None,
        has_new_ip=False,
        new_ips_count=0,
        has_login_anomaly=False,
        has_privilege_escalation=False,
        privilege_actions_count=0,
        has_attack_path=False,
        attack_path_score=None,
        is_off_hours=False,
    )

    # 2. Compute Simulated Risk Score WITH hypothetical toggles
    raw_sim_score, _, sim_factors = compute_risk_score(
        anomaly_score=sim_anomaly_score,
        is_anomaly=sim_anomaly_score >= 0.5,
        event_count=sim_event_count,
        failed_request_count=sim_failed_count,
        unique_services=list(set(unique_services + sim_unusual_services)),
        unusual_services=sim_unusual_services,
        sensitive_resources=sim_sensitive_resources,
        historical_avg_requests=float(event_count),
        recent_intensity=sim_recent_intensity,
        is_coordinated=req.coordinated_behavior,
        temporal_anomaly_score=0.85 if req.temporal_anomaly else None,
        has_new_ip=has_new_ip,
        new_ips_count=2 if has_new_ip else 0,
        has_login_anomaly=req.unusual_login,
        has_privilege_escalation=has_pe,
        privilege_actions_count=3 if has_pe else 0,
        has_attack_path=has_attack_chain,
        attack_path_score=0.90 if has_attack_chain else None,
        is_off_hours=is_off_hours,
    )

    # 3. Apply engine delta to the REAL current user risk
    delta = round(raw_sim_score - base_score, 1)
    
    # Delta should never be negative from toggles (hypothetical behaviors add risk)
    # If the toggle adds nothing, delta is 0
    delta = max(0.0, delta)

    final_sim_score = min(100.0, current_score + delta)
    final_sim_score = round(final_sim_score, 1)
    
    # Strictly enforce delta matches final score difference
    delta = round(final_sim_score - current_score, 1)

    final_sim_level = "LOW"
    for level, threshold, _ in RISK_LEVELS:
        if final_sim_score >= threshold:
            final_sim_level = level
            break

    predicted_action = get_policy_action_for_level(final_sim_level)

    # Top contributor
    top_factor = max(sim_factors, key=lambda f: f.contribution) if sim_factors else None
    top_contributor_name = top_factor.factor if top_factor else "Normal Baseline"

    action_desc = {
        "Monitor": "Continue continuous baseline user monitoring.",
        "Alert + Monitor": "Generate SOC priority alert and continue elevated surveillance.",
        "Automatically Restrict": "Application-level enforcement: Restrict sensitive operations and quarantine elevated privileges.",
        "Automatically Block": "Application-level enforcement: Revoke active session tokens, block API actions, and generate critical incident.",
    }.get(predicted_action, "Monitor")

    explanation = (
        f"Hypothetical simulation for '{uid}' moves risk from {current_score:.1f} ({current_level}) "
        f"➔ {final_sim_score:.1f} ({final_sim_level}) [Δ: {'+' if delta >= 0 else ''}{delta:.1f}]. "
        f"Under policy, this triggers: {predicted_action}. Primary driver: {top_contributor_name}."
    )

    return SimulateRiskResponse(
        cloud_user_id=uid,
        current_risk_score=current_score,
        current_risk_level=current_level,
        simulated_risk_score=final_sim_score,
        simulated_risk_level=final_sim_level,
        predicted_action=predicted_action,
        predicted_action_description=action_desc,
        delta=delta,
        risk_level_changed=current_level != final_sim_level,
        top_contributor=top_contributor_name,
        explanation=explanation,
        factor_contributions=[f.to_dict() for f in sim_factors],
    )

"""
User Behavior Analytics (UBA) Service — CloudIntelliGuard.

Establishes behavioral baselines and computes deviation profiles:
  - Normal behavioral baseline vs Current observed behavior
  - Login / API frequency deviation
  - Service and resource access breadth
  - IP / Location shifts
  - Deviation score (0–100) & suspicious behavioral indicators
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database_models import CloudEvent, CloudUserEnforcement, RiskScore
from app.services.feature_engineering import SENSITIVE_SERVICES, SENSITIVE_RESOURCES_PATTERNS
from app.services.preprocessing import load_processed_dataframe


async def get_all_uba_users(db: AsyncSession) -> List[Dict[str, Any]]:
    """Return all unique monitored cloud IAM identities with quick risk summaries."""
    # Fetch enforcements and risk scores
    enf_stmt = select(CloudUserEnforcement)
    enf_res = await db.execute(enf_stmt)
    enforcements = {e.cloud_user_id.strip().lower(): e for e in enf_res.scalars().all() if e.cloud_user_id}

    # Also fetch distinct cloud_user_ids from events
    events_stmt = select(CloudEvent.cloud_user_id).distinct()
    events_res = await db.execute(events_stmt)
    all_uids = [u for u in events_res.scalars().all() if u and u.strip()]

    # Combine with case-insensitive deduplication
    users = []
    seen = set()
    # First add identities with existing enforcement records
    for enf in sorted(enforcements.values(), key=lambda e: e.risk_score, reverse=True):
        uid_key = enf.cloud_user_id.strip().lower()
        if uid_key in seen:
            continue
        seen.add(uid_key)
        users.append({
            "cloud_user_id": enf.cloud_user_id,
            "status": enf.status,
            "risk_score": enf.risk_score,
            "risk_level": enf.risk_level,
            "last_evaluated": enf.last_evaluated_at.isoformat() if enf.last_evaluated_at else None,
        })

    # Then include any identities from events that don't yet have enforcement records
    for uid in all_uids:
        uid_key = uid.strip().lower()
        if uid_key in seen:
            continue
        seen.add(uid_key)
        enf = enforcements.get(uid_key)
        users.append({
            "cloud_user_id": uid,
            "status": enf.status if enf else "ACTIVE",
            "risk_score": enf.risk_score if enf else 0.0,
            "risk_level": enf.risk_level if enf else "LOW",
            "last_evaluated": enf.last_evaluated_at.isoformat() if enf and enf.last_evaluated_at else None,
        })

    return sorted(users, key=lambda x: x["risk_score"], reverse=True)


async def compute_user_uba_profile(db: AsyncSession, cloud_user_id: str) -> Dict[str, Any]:
    """
    Build a comprehensive UBA Profile comparing historical baseline vs current behavior.
    """
    # 1. Fetch all events for this user
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
    result = await db.execute(stmt)
    events = result.scalars().all()

    # Fetch enforcement status
    enf_stmt = select(CloudUserEnforcement).where(CloudUserEnforcement.cloud_user_id == cloud_user_id)
    enf_res = await db.execute(enf_stmt)
    enforcement = enf_res.scalar_one_or_none()

    if not events:
        return {
            "cloud_user_id": cloud_user_id,
            "current_status": enforcement.status if enforcement else "ACTIVE",
            "current_risk_score": enforcement.risk_score if enforcement else 0.0,
            "current_risk_level": enforcement.risk_level if enforcement else "LOW",
            "deviation_score": 0.0,
            "baseline": {
                "avg_daily_api_calls": 0,
                "common_services": [],
                "known_ips": [],
                "failure_rate": 0.0,
                "active_hours": "N/A",
            },
            "current_behavior": {
                "current_api_calls": 0,
                "active_services": [],
                "current_ips": [],
                "current_failure_rate": 0.0,
                "sensitive_resource_accesses": 0,
            },
            "suspicious_indicators": [],
            "recent_events": [],
        }

    df = load_processed_dataframe(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)

    # Split into historical baseline (first 70% or all except last window) vs current behavior (recent 30% / last 24h)
    n_events = len(df)
    if n_events >= 10:
        split_idx = int(n_events * 0.65)
        base_df = df.iloc[:split_idx]
        curr_df = df.iloc[split_idx:]
    else:
        base_df = df
        curr_df = df

    # Baseline calculations
    base_services = list(base_df["service"].dropna().unique())
    base_ips = list(base_df["source_ip"].dropna().unique())
    base_events_count = len(base_df)
    
    # Calculate active observation duration in days (excluding dormant gaps > 24h between distinct sessions/datasets)
    base_time_diffs = base_df["timestamp"].diff().dt.total_seconds().fillna(0)
    base_session_ids = (base_time_diffs > 86400).cumsum()
    base_active_seconds = 0.0
    for _, sess in base_df.groupby(base_session_ids):
        span_s = (sess["timestamp"].max() - sess["timestamp"].min()).total_seconds()
        base_active_seconds += max(3600.0, span_s)
    base_days = max(1.0, base_active_seconds / 86400.0)
    avg_daily_calls = round(base_events_count / base_days, 1)

    base_failures = (base_df["status"].str.lower().str.contains("fail|denied|unauth", na=False)).sum()
    base_failure_rate = round((base_failures / max(1, base_events_count)) * 100, 1)

    # Current behavior calculations
    curr_services = list(curr_df["service"].dropna().unique())
    curr_ips = list(curr_df["source_ip"].dropna().unique())
    curr_events_count = len(curr_df)
    
    # Calculate active observation duration in days for current window (excluding dormant gaps > 24h between distinct sessions/datasets)
    curr_time_diffs = curr_df["timestamp"].diff().dt.total_seconds().fillna(0)
    curr_session_ids = (curr_time_diffs > 86400).cumsum()
    curr_active_seconds = 0.0
    for _, sess in curr_df.groupby(curr_session_ids):
        span_s = (sess["timestamp"].max() - sess["timestamp"].min()).total_seconds()
        curr_active_seconds += max(3600.0, span_s)
    curr_days = max(0.1, curr_active_seconds / 86400.0)
    curr_daily_calls = round(curr_events_count / curr_days, 1)

    curr_failures = (curr_df["status"].str.lower().str.contains("fail|denied|unauth", na=False)).sum()
    curr_failure_rate = round((curr_failures / max(1, curr_events_count)) * 100, 1)

    # Sensitive resource checks
    sensitive_accesses = 0
    sensitive_list = []
    for _, row in curr_df.iterrows():
        svc = str(row.get("service", "")).lower()
        res = str(row.get("resource", "")).lower()
        act = str(row.get("action", "")).lower()
        if svc in SENSITIVE_SERVICES or any(p in res for p in SENSITIVE_RESOURCES_PATTERNS) or "admin" in act or "role" in act:
            sensitive_accesses += 1
            sensitive_list.append(f"{svc}::{row.get('action', 'action')}")

    # Identify novel / suspicious differences
    novel_services = [s for s in curr_services if s not in base_services]
    novel_ips = [ip for ip in curr_ips if ip not in base_ips]

    # Compute Behavioral Deviation Score (0–100)
    deviation_score = 0.0
    indicators = []

    # Indicator 1: API Volume Spike
    if curr_daily_calls > avg_daily_calls * 1.5 and curr_events_count > 5:
        spike_ratio = round(curr_daily_calls / max(1.0, avg_daily_calls), 1)
        contrib = min(35.0, (spike_ratio - 1.0) * 12.0)
        deviation_score += contrib
        indicators.append({
            "name": "Abnormal API Velocity",
            "severity": "HIGH" if spike_ratio > 3.0 else "MEDIUM",
            "description": f"Current rate ({curr_daily_calls} calls/day) is {spike_ratio}x historical baseline ({avg_daily_calls} calls/day)",
        })

    # Indicator 2: Novel Service Exploration
    if novel_services:
        contrib = min(30.0, len(novel_services) * 10.0)
        deviation_score += contrib
        indicators.append({
            "name": "Unusual Service Exploration",
            "severity": "HIGH" if any(s.lower() in SENSITIVE_SERVICES for s in novel_services) else "MEDIUM",
            "description": f"Accessed {len(novel_services)} service(s) never seen in baseline: {', '.join(novel_services[:3])}",
        })

    # Indicator 3: Novel IP Address
    if novel_ips and len(base_ips) > 0:
        deviation_score += 15.0
        indicators.append({
            "name": "New Source IP / Location Shift",
            "severity": "MEDIUM",
            "description": f"Activity originated from unseen source IP(s): {', '.join(novel_ips[:3])}",
        })

    # Indicator 4: High Failure Rate
    if curr_failure_rate > base_failure_rate + 15.0 and curr_failures >= 3:
        deviation_score += 20.0
        indicators.append({
            "name": "Spike in Authorization / API Failures",
            "severity": "HIGH",
            "description": f"Failure rate surged to {curr_failure_rate}% (baseline: {base_failure_rate}%) across {curr_failures} failed attempts",
        })

    # Indicator 5: Sensitive Resource Access
    if sensitive_accesses > 0:
        contrib = min(20.0, sensitive_accesses * 4.0)
        deviation_score += contrib
        indicators.append({
            "name": "Sensitive Resource / IAM Operations",
            "severity": "HIGH" if sensitive_accesses > 3 else "MEDIUM",
            "description": f"{sensitive_accesses} high-privilege IAM/KMS/Secrets operations detected",
        })

    deviation_score = round(min(100.0, max(0.0, deviation_score)), 1)

    # Determine privilege levels
    privilege_keywords = ("createaccesskey", "attachuserpolicy", "putuserpolicy", "createuser", "createrole", "assumerole", "addusertogroup", "admin", "updatelogin")
    has_priv_changes = any(any(pk in str(a).lower() for pk in privilege_keywords) for a in curr_df["action"].dropna())
    normal_privilege = "Standard IAM User"
    current_privilege = "Elevated Privileges / Admin Attempt" if has_priv_changes else "Standard IAM User"

    # Behavior Diff
    behavior_diffs = []
    # 1. IP comparison
    normal_ip_str = ", ".join(base_ips[:2]) if base_ips else "No historical IP data"
    current_ip_str = ", ".join(curr_ips[:2]) if curr_ips else "N/A"
    behavior_diffs.append({
        "attribute": "Source IP Address",
        "normal": normal_ip_str,
        "current": current_ip_str,
        "is_suspicious": len(novel_ips) > 0,
        "explanation": f"Accessed from new IP address: {', '.join(novel_ips)}" if novel_ips else "Originates from known historical IP range",
    })

    # 2. Service comparison
    normal_svc_str = ", ".join(base_services[:3]) if base_services else "No historical service data"
    current_svc_str = ", ".join(curr_services[:3]) if curr_services else "N/A"
    behavior_diffs.append({
        "attribute": "Target Cloud Services",
        "normal": normal_svc_str,
        "current": current_svc_str,
        "is_suspicious": len(novel_services) > 0,
        "explanation": f"Explored novel service(s): {', '.join(novel_services)}" if novel_services else "Matches baseline services",
    })

    # 3. Privilege Level
    behavior_diffs.append({
        "attribute": "Privilege Level",
        "normal": normal_privilege,
        "current": current_privilege,
        "is_suspicious": has_priv_changes,
        "explanation": "Attempted privilege escalation via IAM credential / policy modification" if has_priv_changes else "Operating within assigned standard permissions",
    })

    # 4. Activity Velocity
    behavior_diffs.append({
        "attribute": "API Request Velocity",
        "normal": f"{avg_daily_calls} calls/day",
        "current": f"{curr_daily_calls} calls/day",
        "is_suspicious": curr_daily_calls > avg_daily_calls * 2.0,
        "explanation": f"Request rate is {round(curr_daily_calls / max(1.0, avg_daily_calls), 1)}x baseline velocity" if curr_daily_calls > avg_daily_calls * 2.0 else "Within normal frequency band",
    })

    # Generate "Why Suspicious?" Explanation based on actual data
    explanation_sentences = []
    if len(novel_ips) > 0:
        explanation_sentences.append(f"A new external IP address ({', '.join(novel_ips[:2])}) was detected that differs from historical login IPs ({', '.join(base_ips[:2])}).")
    if has_priv_changes:
        explanation_sentences.append("The identity attempted unauthorized privilege escalation and IAM credential manipulation.")
    if sensitive_accesses > 0:
        explanation_sentences.append(f"Unusual access to {sensitive_accesses} high-value sensitive resources (KMS keys, Secrets Manager secrets) was observed.")
    if curr_failures >= 2:
        explanation_sentences.append(f"A high frequency of authorization failures ({curr_failures} failures, {curr_failure_rate}%) indicates probable brute-force or privilege probing.")
    if curr_daily_calls > avg_daily_calls * 2.5:
        explanation_sentences.append(f"API request velocity surged to {curr_daily_calls} calls/day ({round(curr_daily_calls / max(1.0, avg_daily_calls), 1)}x normal baseline).")

    if not explanation_sentences:
        why_suspicious = f"User {cloud_user_id} activity conforms to established historical baseline patterns. No anomalous behavioral deviations detected."
    else:
        why_suspicious = f"The activity of identity '{cloud_user_id}' deviates from the user's normal behavioral baseline. " + " ".join(explanation_sentences)

    # Format user activity tracking breakdown
    all_events_list = []
    for _, row in df.iterrows():
        act_str = str(row.get("action", ""))
        svc_str = str(row.get("service", ""))
        res_str = str(row.get("resource", ""))
        stat_str = str(row.get("status", "success"))
        is_susp_ev = (
            any(pk in act_str.lower() for pk in privilege_keywords)
            or svc_str.lower() in SENSITIVE_SERVICES
            or "fail" in stat_str.lower()
            or str(row.get("source_ip", "")) in novel_ips
        )
        all_events_list.append({
            "timestamp": row["timestamp"].strftime("%Y-%m-%d %H:%M:%SZ"),
            "time": row["timestamp"].strftime("%H:%M:%S"),
            "action": act_str,
            "service": svc_str,
            "resource": res_str,
            "source_ip": str(row.get("source_ip", "")),
            "status": stat_str,
            "is_suspicious": is_susp_ev,
        })

    suspicious_events = [ev for ev in all_events_list if ev["is_suspicious"]]

    # Format recent events sample
    recent_events = all_events_list[-20:][::-1]

    return {
        "cloud_user_id": cloud_user_id,
        "current_status": enforcement.status if enforcement else "ACTIVE",
        "current_risk_score": enforcement.risk_score if enforcement else 0.0,
        "current_risk_level": enforcement.risk_level if enforcement else "LOW",
        "deviation_score": deviation_score,
        "why_suspicious": why_suspicious,
        "behavior_diffs": behavior_diffs,
        "baseline": {
            "avg_daily_api_calls": avg_daily_calls,
            "common_services": base_services[:8],
            "known_ips": base_ips[:6],
            "failure_rate": base_failure_rate,
            "privilege_level": normal_privilege,
            "active_hours": "08:00 - 18:00 UTC" if len(base_df) > 5 else "Variable",
        },
        "current_behavior": {
            "current_api_calls": curr_daily_calls,
            "active_services": curr_services[:8],
            "current_ips": curr_ips[:6],
            "current_failure_rate": curr_failure_rate,
            "privilege_level": current_privilege,
            "sensitive_resource_accesses": sensitive_accesses,
        },
        "activity_tracking": {
            "total_events": n_events,
            "total_ips": len(set(curr_ips + base_ips)),
            "novel_ips": novel_ips,
            "novel_services": novel_services,
            "privilege_changes_count": sum(1 for ev in all_events_list if any(pk in ev["action"].lower() for pk in privilege_keywords)),
            "sensitive_operations_count": sensitive_accesses,
            "failure_count": int(curr_failures + base_failures),
            "first_seen": df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%SZ"),
            "last_seen": df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%SZ"),
            "active_hours_distribution": "Standard Business Hours (08:00-18:00 UTC)" if not any(ev.get("timestamp", "").endswith("02:") or "03:" in ev.get("timestamp", "") for ev in all_events_list) else "Anomalous Off-Hours (02:00-05:00 UTC)",
        },
        "suspicious_indicators": indicators,
        "suspicious_events": suspicious_events,
        "recent_events": recent_events,
    }

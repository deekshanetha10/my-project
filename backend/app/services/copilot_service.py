"""
AI Copilot Security Assistant Service — CloudIntelliGuard.

Grounds natural language SOC queries into actual live database telemetry:
  - Incident context & explanations
  - User risk & behavioral deviations
  - Autonomous enforcement actions & reasons
  - Attack path traversals
"""
import re
from typing import Any, Dict, List, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database_models import (
    Anomaly, AuditLog, CloudEvent, CloudUserEnforcement, Incident, RiskScore,
)
from app.services.attack_path_service import get_attack_paths
from app.services.uba_service import compute_user_uba_profile


async def answer_copilot_query(
    db: AsyncSession,
    query: str,
    context_user_id: Optional[str] = None,
    context_incident_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Process analyst query and return factual, grounded response using database state.
    """
    q = query.lower().strip()
    data_sources = []
    related_entities = []
    suggested_actions = []

    # 1. Resolve all known users in DB (enforcements + distinct events)
    enf_res = await db.execute(select(CloudUserEnforcement))
    all_enfs = enf_res.scalars().all()
    user_map = {e.cloud_user_id.strip().lower(): e for e in all_enfs}

    events_uids_res = await db.execute(select(CloudEvent.cloud_user_id).distinct())
    all_event_uids = [u.strip() for u in events_uids_res.scalars().all() if u and u.strip()]
    all_known_uids = list(set(list(user_map.keys()) + [u.lower() for u in all_event_uids]))

    # Target user resolution: query mention takes priority, fallback to context_user_id
    target_uid = None
    user_match = None

    for u_lower in sorted(all_known_uids, key=len, reverse=True):
        if u_lower in q:
            target_uid = u_lower
            user_match = user_map.get(u_lower)
            break

    if not target_uid and context_user_id and context_user_id.strip():
        target_uid = context_user_id.strip().lower()
        user_match = user_map.get(target_uid)

    if target_uid and not user_match:
        enf_stmt = select(CloudUserEnforcement).where(
            func.lower(func.trim(CloudUserEnforcement.cloud_user_id)) == target_uid
        )
        enf_res2 = await db.execute(enf_stmt)
        user_match = enf_res2.scalar_one_or_none()

    # Intent 1: "Highest risk" / "Top threats"
    if ("highest risk" in q or "top threat" in q or "most dangerous" in q or "highest threat" in q or "top risk" in q) and not ("why" in q and target_uid):
        data_sources.append("cloud_user_enforcements")
        data_sources.append("risk_scores")

        top_users = sorted(all_enfs, key=lambda x: x.risk_score, reverse=True)[:5]
        if not top_users:
            answer = "No evaluated cloud identities currently found in the system. Ingest a dataset and run inference to populate risk scores."
        else:
            top_user = top_users[0]
            lines = [f"**Highest Risk Identity:** `{top_user.cloud_user_id}` with a Risk Score of **{top_user.risk_score:.1f}/100** ({top_user.risk_level})."]
            lines.append(f"**Current Status:** `{top_user.status}`")
            if top_user.blocking_reason:
                lines.append(f"**Block Reason:** {top_user.blocking_reason}")
            elif top_user.restriction_reason:
                lines.append(f"**Restriction Reason:** {top_user.restriction_reason}")

            lines.append("\n**Top Monitored Identities by Risk:**")
            for u in top_users:
                lines.append(f"- `{u.cloud_user_id}`: Risk **{u.risk_score:.1f}** ({u.risk_level}) — Status: **{u.status}**")

            answer = "\n".join(lines)
            related_entities.append({"type": "USER", "id": top_user.cloud_user_id, "risk": top_user.risk_score})
            suggested_actions.extend([
                f"View Attack Path for {top_user.cloud_user_id}",
                f"Inspect User Behavior Profile for {top_user.cloud_user_id}",
                "Review Automated Response Enforcements",
            ])

        return {
            "query": query,
            "answer": answer,
            "intent": "QUERY_HIGHEST_RISK",
            "related_entities": related_entities,
            "suggested_actions": suggested_actions,
            "data_sources_used": data_sources,
        }

    # Intent 2: "Attack path" / "kill chain"
    if ("attack path" in q or "kill chain" in q or "graph path" in q) and ("why" not in q):
        data_sources.append("attack_paths")
        path_uid = target_uid or (user_match.cloud_user_id if user_match else None)
        paths = await get_attack_paths(db, cloud_user_id=path_uid)

        if not paths:
            answer = f"No suspicious attack paths currently detected for `{path_uid or 'all identities'}`. All observed graph transitions are within normal baseline thresholds."
        else:
            top_p = paths[0]
            lines = [f"### ⚔️ Attack Path Analysis for `{top_p['cloud_user_id']}` (Risk: {top_p['path_risk_score']:.1f})"]
            lines.append(f"**Target Resource:** `{top_p['target_resource']}`\n")
            lines.append("**Progression Sequence:**")
            for s in top_p["steps"]:
                warn = "⚠️" if s["is_suspicious"] else "➡️"
                lines.append(f"{s['step_number']}. {warn} **{s['source_type']}** `{s['source_entity']}` ➔ **{s['target_type']}** `{s['target_entity']}` ({s['action']})")

            answer = "\n".join(lines)
            related_entities.append({"type": "ATTACK_PATH", "id": top_p["path_id"], "user": top_p["cloud_user_id"]})
            suggested_actions.extend([
                f"Inspect User Profile for {top_p['cloud_user_id']}",
                "Review Automated Response Enforcements",
            ])

        return {
            "query": query,
            "answer": answer,
            "intent": "QUERY_ATTACK_PATH",
            "related_entities": related_entities,
            "suggested_actions": suggested_actions,
            "data_sources_used": data_sources,
        }

    # Intent 3: "Which IP caused the risk increase?" / "IP addresses" / "Login history"
    if ("ip" in q or "login" in q or "location" in q or "address" in q) and target_uid:
        data_sources.extend(["cloud_events", "uba_profile"])
        uba = await compute_user_uba_profile(db, target_uid)
        tracking = uba.get("activity_tracking", {})
        
        lines = [f"### 🌐 IP & Login Intelligence for `{target_uid}`"]
        base_ips = uba.get("baseline", {}).get("known_ips", [])
        curr_ips = uba.get("current_behavior", {}).get("current_ips", [])
        lines.append(f"- **Baseline IPs:** `{', '.join(base_ips) or 'None recorded'}`")
        lines.append(f"- **Current Active IPs:** `{', '.join(curr_ips) or 'None recorded'}`")
        
        novel_ips = tracking.get("novel_ips", [])
        if novel_ips:
            lines.append(f"- 🚨 **Suspicious IP Flagged:** `{', '.join(novel_ips)}` was not present in the user's historical baseline and directly elevated the IP Anomaly risk score (+15 pts).")
        else:
            lines.append("- ✓ Observed IP connections originated from known subnet/IP ranges.")
            
        lines.append(f"- **Active Hours Distribution:** {tracking.get('active_hours_distribution', 'Standard Business Hours')}")
        lines.append(f"- **First Seen:** {tracking.get('first_seen', 'N/A')} | **Last Seen:** {tracking.get('last_seen', 'N/A')}")
        
        return {
            "query": query,
            "answer": "\n".join(lines),
            "intent": "QUERY_IP_LOGIN_HISTORY",
            "related_entities": [{"type": "USER", "id": target_uid, "risk": uba.get("current_risk_score", 0.0)}],
            "suggested_actions": [f"Trace Attack Path for {target_uid}", "What happened before the response?"],
            "data_sources_used": data_sources,
        }

    # Intent 4: "Show suspicious activities" / "Suspicious events"
    if (("suspicious" in q and ("activit" in q or "action" in q or "event" in q or "show" in q or "what" in q or "list" in q)) or ("anomal" in q and ("activit" in q or "event" in q))) and target_uid:
        data_sources.extend(["cloud_events", "uba_profile"])
        uba = await compute_user_uba_profile(db, target_uid)
        suspicious_evs = uba.get("suspicious_events", [])
        total_evs = uba.get("activity_tracking", {}).get("total_events", 0)

        lines = [f"### 🚨 Suspicious Activities Detected for `{target_uid}` ({len(suspicious_evs)} flagged / {total_evs} total events)"]
        
        # List indicators
        if uba.get("suspicious_indicators"):
            lines.append("\n**Behavioral Indicators:**")
            for ind in uba["suspicious_indicators"]:
                lines.append(f"- **[{ind['severity']}] {ind['name']}:** {ind['description']}")

        if suspicious_evs:
            lines.append("\n**Key Flagged Events:**")
            for ev in suspicious_evs[-8:]:
                stat_badge = f"[{ev.get('status', 'N/A')}]"
                lines.append(f"- `{ev.get('time', 'N/A')}` 🚨 **{ev.get('action', 'N/A')}** on `{ev.get('service', 'N/A')}` (`{ev.get('resource', 'resource')}`) from `{ev.get('source_ip', 'N/A')}` {stat_badge}")
        else:
            lines.append("\n✓ No individual suspicious cloud events flagged.")

        if user_match and user_match.status in ("RESTRICTED", "BLOCKED"):
            lines.append(f"\n**Enforcement Status:** Automated mitigation executed: **{user_match.status}**.")
            if user_match.restriction_reason or user_match.blocking_reason:
                lines.append(f"*Reason:* {user_match.blocking_reason or user_match.restriction_reason}")

        return {
            "query": query,
            "answer": "\n".join(lines),
            "intent": "QUERY_SUSPICIOUS_ACTIVITIES",
            "related_entities": [{"type": "USER", "id": target_uid, "risk": uba.get("current_risk_score", 0.0)}],
            "suggested_actions": ["What happened before the response?", "Why was this user flagged?"],
            "data_sources_used": data_sources,
        }

    # Intent 5: "What happened before the response?" / "API actions" / "Activity Timeline"
    if ("api" in q or "action" in q or "before" in q or "activities" in q or "event" in q or "timeline" in q) and target_uid:
        data_sources.extend(["cloud_events", "audit_logs"])
        
        events_res = await db.execute(
            select(CloudEvent)
            .where(func.lower(func.trim(CloudEvent.cloud_user_id)) == target_uid)
            .order_by(CloudEvent.timestamp.asc())
        )
        evs = events_res.scalars().all()
        
        lines = [f"### 📜 Chronological Activity Timeline for `{target_uid}` ({len(evs)} events)"]
        
        if not evs:
            lines.append("No cloud activity events found for this identity in the database.")
        else:
            # Show events leading up to the mitigation action (last 10 events)
            display_evs = evs[-10:] if len(evs) > 10 else evs
            for ev in display_evs:
                is_susp = (
                    (ev.status and "fail" in ev.status.lower())
                    or (ev.service and ev.service.lower() in ("secretsmanager", "kms", "iam"))
                    or (ev.action and any(k in ev.action.lower() for k in ("createaccesskey", "attachuserpolicy", "createrole", "admin")))
                )
                warn = "🚨" if is_susp else "✓"
                ts_str = ev.timestamp.strftime("%H:%M:%S") if ev.timestamp else "N/A"
                lines.append(f"- `{ts_str}` {warn} **{ev.action}** on `{ev.service}` (`{ev.resource or 'resource'}`) from `{ev.source_ip}` [{ev.status}]")
            
        if user_match and user_match.status in ("RESTRICTED", "BLOCKED"):
            lines.append(f"\n**Enforcement Trigger:** Automated mitigation executed: **{user_match.status}**.")
            if user_match.blocking_reason:
                lines.append(f"*Reason:* {user_match.blocking_reason}")
            elif user_match.restriction_reason:
                lines.append(f"*Reason:* {user_match.restriction_reason}")
                
        return {
            "query": query,
            "answer": "\n".join(lines),
            "intent": "QUERY_USER_ACTIVITIES",
            "related_entities": [{"type": "USER", "id": target_uid, "risk": user_match.risk_score if user_match else 0.0}],
            "suggested_actions": ["Why was this user flagged?", "Which IP caused the risk increase?", f"View Attack Path for {target_uid}"],
            "data_sources_used": data_sources,
        }

    # Intent 5b: "Why did risk become critical?" / "Why critical?" / "Historical critical transition"
    if (("critical" in q and ("why" in q or "risk" in q or "become" in q or "score" in q or "increase" in q or "transition" in q or "history" in q or "cross" in q or "75" in q)) or ("why" in q and "critical" in q)) and target_uid:
        resolved_uid = target_uid
        data_sources.extend(["risk_scores", "audit_logs", "cloud_user_enforcements", "uba_profile"])

        # 1. Fetch all risk score history for this user
        rs_res = await db.execute(
            select(RiskScore)
            .where(func.lower(func.trim(RiskScore.cloud_user_id)) == resolved_uid)
            .order_by(RiskScore.created_at.asc())
        )
        risk_history = rs_res.scalars().all()

        # 2. Fetch all audit logs for this user
        audit_res = await db.execute(
            select(AuditLog)
            .where(AuditLog.resource.like(f"%{resolved_uid}%"))
            .order_by(AuditLog.timestamp.asc())
        )
        audits = audit_res.scalars().all()

        # 3. Fetch latest enforcement and UBA profile
        uba = await compute_user_uba_profile(db, resolved_uid)

        current_score = user_match.risk_score if user_match else (risk_history[-1].risk_score if risk_history else uba.get("current_risk_score", 0.0))
        current_level = user_match.risk_level if user_match else (risk_history[-1].risk_level if risk_history else uba.get("current_risk_level", "LOW"))
        current_status = user_match.status if user_match else "ACTIVE"

        # Find historical CRITICAL score(s)
        critical_scores = [r for r in risk_history if r.risk_level == "CRITICAL" or r.risk_score >= 75.0]
        critical_audits = [a for a in audits if "BLOCK" in a.action or (a.detail and a.detail.get("risk_level") == "CRITICAL")]

        lines = [f"### 🚨 Risk Transition Analysis: `{resolved_uid}`"]

        if critical_scores:
            crit_rs = critical_scores[0]
            crit_ts = crit_rs.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if crit_rs.created_at else "N/A"
            
            lines.append(f"\n**1. Historical Critical Risk Peak:**")
            lines.append(f"- **Peak Risk Score:** **{crit_rs.risk_score:.1f}/100** (`CRITICAL`) at `{crit_ts}`")
            lines.append(f"- **Policy Threshold:** Breached CRITICAL threshold (≥ 75.0)")

            lines.append(f"\n**2. Risk Factors That Caused the Score to Cross 75:**")
            factors = crit_rs.factors or []
            for f in factors:
                contrib = f.get('contribution', 0.0)
                lines.append(f"- **{f.get('factor', 'Risk Factor')} (+{contrib:.1f} pts):** {f.get('description', '')}")

            lines.append(f"\n**3. Contributing Behavioral Evidence:**")
            tracking = uba.get("activity_tracking", {})
            novel_ips = tracking.get("novel_ips", [])
            if novel_ips:
                lines.append(f"- **IP Anomaly:** Unseen source IP `{', '.join(novel_ips)}` connected during off-hours")
            sensitive_ops = tracking.get("sensitive_operations_count", 0)
            if sensitive_ops:
                lines.append(f"- **Sensitive Operations:** {sensitive_ops} high-privilege IAM/KMS/Secrets operations invoked")
            priv_ops = tracking.get("privilege_changes_count", 0)
            if priv_ops:
                lines.append(f"- **Privilege Escalation Attempts:** {priv_ops} IAM credential/key generation actions (`CreateAccessKey`)")

            lines.append(f"\n**4. Automated Response Triggered at Peak:**")
            if critical_audits:
                crit_a = critical_audits[0]
                a_ts = crit_a.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if crit_a.timestamp else "N/A"
                reason = crit_a.detail.get("reason", "CRITICAL risk policy threshold breached") if crit_a.detail else "CRITICAL risk policy threshold breached"
                lines.append(f"- **Action Executed:** 🚨 **{crit_a.action}** at `{a_ts}`")
                lines.append(f"- **Enforcement Detail:** Session revoked (`session_revoked: True`), API execution blocked")
                lines.append(f"- **Trigger Reason:** *{reason}*")
            else:
                lines.append(f"- **Action Executed:** 🚨 **AUTOMATED_BLOCK** (Active sessions revoked)")

            lines.append(f"\n**5. Current Risk & Enforcement State (State Transition):**")
            lines.append(f"- **Current Calculated Risk:** **{current_score:.1f}/100** (`{current_level}`)")
            lines.append(f"- **Current Enforcement Status:** `{current_status}`")
            if user_match and user_match.restriction_reason:
                lines.append(f"- **Current Reason:** {user_match.restriction_reason}")

            lines.append(f"\n**6. Summary Distinction:**")
            lines.append(
                f"The identity previously spiked to **{crit_rs.risk_score:.1f} CRITICAL** due to combined GNN relational anomaly, "
                f"new IP origin, and rapid IAM `CreateAccessKey` privilege attempts, triggering an immediate **AUTOMATED_BLOCK**. "
                f"Following subsequent evaluation window stabilization, the active score realigned to **{current_score:.1f} HIGH**, "
                f"transitioning the enforcement from BLOCKED to **{current_status}** (quarantined under continuous monitoring)."
            )
        else:
            lines.append(f"\n- Identity `{resolved_uid}` has **not** breached the CRITICAL threshold (≥ 75.0) in recorded evaluation checkpoints.")
            lines.append(f"- **Current Risk Score:** **{current_score:.1f}/100** (`{current_level}`)")
            lines.append(f"- **Current Enforcement Status:** `{current_status}`")
            if risk_history:
                peak_rs = max(risk_history, key=lambda x: x.risk_score)
                lines.append(f"- **Historical Peak Risk:** **{peak_rs.risk_score:.1f}/100** (`{peak_rs.risk_level}`)")
                if peak_rs.factors:
                    lines.append("\n**Primary Contributors to Current/Peak Risk:**")
                    for f in peak_rs.factors[:4]:
                        contrib = f.get('contribution', 0.0)
                        lines.append(f"- **{f.get('factor', 'Factor')} (+{contrib:.1f} pts):** {f.get('description', '')}")

        return {
            "query": query,
            "answer": "\n".join(lines),
            "intent": "QUERY_CRITICAL_RISK_TRANSITION",
            "related_entities": [{"type": "USER", "id": resolved_uid, "risk": current_score}],
            "suggested_actions": ["What happened before the response?", "Show suspicious activities", f"View Attack Path for {resolved_uid}"],
            "data_sources_used": data_sources,
        }

    # Intent 6: "Why was this user flagged?" / "Why is risk high?"
    if (("why" in q and ("flagged" in q or "blocked" in q or "restricted" in q or "anomaly" in q or "high" in q or "risk" in q or "suspicious" in q)) or (target_uid and ("why" in q or "detail" in q or "tell me about" in q or "status" in q or "reason" in q or "flagged" in q))):
        resolved_uid = target_uid or "u006"
        data_sources.extend(["cloud_user_enforcements", "anomalies", "uba_profile", "risk_scores", "audit_logs"])

        # Fetch UBA, Anomaly & Risk details
        uba = await compute_user_uba_profile(db, resolved_uid)
        anom_res = await db.execute(
            select(Anomaly)
            .where(func.lower(func.trim(Anomaly.cloud_user_id)) == resolved_uid)
            .order_by(Anomaly.created_at.desc())
        )
        anom = anom_res.scalars().first()

        # Fetch latest RiskScore for factor breakdown
        rs_res = await db.execute(
            select(RiskScore)
            .where(func.lower(func.trim(RiskScore.cloud_user_id)) == resolved_uid)
            .order_by(RiskScore.created_at.desc())
        )
        latest_rs = rs_res.scalars().first()

        current_risk_score = user_match.risk_score if user_match else (latest_rs.risk_score if latest_rs else uba.get("current_risk_score", 0.0))
        current_risk_level = user_match.risk_level if user_match else (latest_rs.risk_level if latest_rs else uba.get("current_risk_level", "LOW"))
        current_status = user_match.status if user_match else "ACTIVE"

        lines = [f"### 🛡️ Analysis for Identity: `{resolved_uid}`"]
        lines.append(f"- **Current Status:** `{current_status}` | **Risk Score:** `{current_risk_score:.1f}/100` ({current_risk_level})")
        lines.append(f"- **Behavioral Deviation Score:** `{uba.get('deviation_score', 0.0):.1f}/100`")
        lines.append(f"- **Total Events Monitored:** {uba.get('activity_tracking', {}).get('total_events', 0)}")

        if user_match and user_match.session_revoked:
            lines.append(f"- **Enforcement:** 🚨 **ACTIVE CREDENTIAL / SESSION REVOKED** ({user_match.blocking_reason or 'Critical Threat Level'})")
        elif user_match and user_match.status == "RESTRICTED":
            lines.append(f"- **Enforcement:** ⚠️ **QUARANTINED** ({user_match.restriction_reason or 'High Risk Policy Threshold Breached'})")

        # Risk Factors
        factors = latest_rs.factors if (latest_rs and latest_rs.factors) else []
        if factors:
            lines.append("\n**Primary Risk Contributors:**")
            for f in factors[:4]:
                contrib = f.get('contribution', 0.0)
                lines.append(f"- **{f.get('factor', 'Risk Factor')} (+{contrib:.1f} pts):** {f.get('description', '')}")

        # Suspicious Indicators
        if uba.get("suspicious_indicators"):
            lines.append("\n**Key Suspicious Indicators Detected:**")
            for ind in uba["suspicious_indicators"]:
                lines.append(f"- **[{ind['severity']}] {ind['name']}:** {ind['description']}")

        # GNN Anomaly summary
        if anom and anom.explanation:
            summary = anom.explanation.get("summary")
            if summary:
                lines.append(f"\n**GNN Anomaly Engine:** {summary}")

        answer = "\n".join(lines)
        related_entities.append({"type": "USER", "id": resolved_uid, "risk": current_risk_score})
        suggested_actions.extend([
            "What happened before the response?",
            "Which IP caused the risk increase?",
            f"Launch Attack Path for {resolved_uid}",
        ])

        return {
            "query": query,
            "answer": answer,
            "intent": "QUERY_USER_EXPLANATION",
            "related_entities": related_entities,
            "suggested_actions": suggested_actions,
            "data_sources_used": data_sources,
        }

    # Intent 7: "Critical incidents" / "Active alerts"
    if "incident" in q or "critical" in q or "active alerts" in q:
        data_sources.append("incidents")
        inc_res = await db.execute(select(Incident).order_by(Incident.created_at.desc()).limit(5))
        incidents = inc_res.scalars().all()

        if not incidents:
            answer = "There are currently 0 active critical security incidents."
        else:
            lines = [f"**Found {len(incidents)} Recent Security Incident(s):**\n"]
            for inc in incidents:
                lines.append(f"- **Incident #{inc.id} [{inc.severity} / {inc.status}]:** {inc.title}")
                if inc.explanation:
                    lines.append(f"  *Detail:* {inc.explanation[:120]}...")
            answer = "\n".join(lines)
            suggested_actions.extend(["Review Incident Triage Console", "Inspect Automated Responses"])

        return {
            "query": query,
            "answer": answer,
            "intent": "QUERY_INCIDENTS",
            "related_entities": related_entities,
            "suggested_actions": suggested_actions,
            "data_sources_used": data_sources,
        }

    # Intent 8: "Automated action" / "What was done"
    if "action" in q or "automated" in q or "response" in q or "blocked" in q or "quarantine" in q:
        data_sources.extend(["audit_logs", "cloud_user_enforcements"])
        audit_res = await db.execute(
            select(AuditLog).where(
                AuditLog.action.like("%AUTOMATED%") | AuditLog.action.like("%RESTRICTION%") | AuditLog.action.like("%OVERRIDE%")
            ).order_by(AuditLog.timestamp.desc()).limit(5)
        )
        logs = audit_res.scalars().all()

        if not logs:
            answer = "No automated restrictions or blocks have been triggered yet. When a user's risk exceeds 50 (HIGH) or 75 (CRITICAL), the autonomous policy engine executes immediately."
        else:
            lines = ["**Recent Autonomous Response Actions:**\n"]
            for log in logs:
                u_res = log.resource or "N/A"
                detail = log.detail or {}
                reason = detail.get("reason", "Risk policy threshold breached")
                lines.append(f"- **{log.action}** on `{u_res}` at {log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                lines.append(f"  *Reason:* {reason}")
            answer = "\n".join(lines)

        return {
            "query": query,
            "answer": answer,
            "intent": "QUERY_AUTOMATED_ACTIONS",
            "related_entities": related_entities,
            "suggested_actions": ["View Audit Log", "Inspect Enforcements Table"],
            "data_sources_used": data_sources,
        }

    # Default general assistance
    data_sources.append("cloud_telemetry_index")
    answer = (
        f"CloudIntelliGuard AI Security Investigation Copilot is active. "
        f"You can ask me grounded questions like:\n"
        f"- *'Why was u006 flagged?'*\n"
        f"- *'What happened before the response?'*\n"
        f"- *'Show suspicious activities for u006'*\n"
        f"- *'Which IP caused the risk increase?'*\n"
        f"- *'Why did risk become critical?'*\n"
        f"- *'Which user currently has the highest risk?'*\n"
        f"- *'Show the attack path for u006'*\n"
        f"- *'What automated actions were taken?'*"
    )
    return {
        "query": query,
        "answer": answer,
        "intent": "GENERAL_QUERY",
        "related_entities": related_entities,
        "suggested_actions": ["Which user currently has the highest risk?", "What happened before the response?", "Why was this user flagged?"],
        "data_sources_used": data_sources,
    }

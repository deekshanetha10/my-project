"""
Attack Path Analysis Service — CloudIntelliGuard.

Traces multi-hop suspicious event sequences across cloud entities:
  User → IP → Action (Privilege Escalation / Recon) → Service → Sensitive Resource
"""
from typing import Any, Dict, List, Optional
import networkx as nx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database_models import CloudEvent, GraphWindow, Incident
from app.services.feature_engineering import SENSITIVE_SERVICES, SENSITIVE_RESOURCES_PATTERNS
from app.services.graph_builder import deserialize_graph, NODE_USER, NODE_IP, NODE_ACTION, NODE_SERVICE, NODE_RESOURCE

SUSPICIOUS_ACTIONS = {
    "assumerole", "getsessiontoken", "createrole", "putuserpolicy",
    "attachuserpolicy", "createaccesskey", "getsecretvalue", "decrypt",
    "listbuckets", "getcalleridentity", "describekey", "getpassworddata",
    "authorizesecuritygroupingress", "createuser", "updatelogingenerated",
}


async def get_attack_paths(
    db: AsyncSession,
    cloud_user_id: Optional[str] = None,
    target_resource: Optional[str] = None,
    graph_window_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Extract and structure attack paths from graph windows and event sequences.
    """
    norm_uid = cloud_user_id.strip().lower() if cloud_user_id else None

    # 1. Fetch events
    stmt = select(CloudEvent).order_by(CloudEvent.timestamp.asc())
    if norm_uid:
        stmt = stmt.where(func.lower(func.trim(CloudEvent.cloud_user_id)) == norm_uid)
    if graph_window_id:
        gw_res = await db.execute(select(GraphWindow).where(GraphWindow.id == graph_window_id))
        gw = gw_res.scalar_one_or_none()
        if gw:
            stmt = stmt.where(CloudEvent.dataset_id == gw.dataset_id)
            stmt = stmt.where(CloudEvent.timestamp >= gw.start_time, CloudEvent.timestamp <= gw.end_time)

    events_res = await db.execute(stmt.limit(1000))
    events = events_res.scalars().all()

    if not events:
        return []

    # Group events by user (normalized)
    user_events: Dict[str, List[CloudEvent]] = {}
    for ev in events:
        raw_uid = (ev.cloud_user_id or "unknown").strip()
        u = raw_uid.lower()
        if u not in user_events:
            user_events[u] = []
        user_events[u].append(ev)

    attack_paths: List[Dict[str, Any]] = []

    for uid, ev_list in user_events.items():
        if norm_uid and uid != norm_uid:
            continue

        if target_resource:
            res_matches = any(target_resource.lower() in str(e.resource or "").lower() for e in ev_list)
            if not res_matches:
                continue

        # Look for sequences that touch sensitive APIs or errors
        suspicious_events = []
        for ev in ev_list:
            act = str(ev.action or "").lower()
            svc = str(ev.service or "").lower()
            res = str(ev.resource or "").lower()
            status = str(ev.status or "").lower()

            is_suspicious = (
                act in SUSPICIOUS_ACTIONS or
                svc in SENSITIVE_SERVICES or
                any(p in res for p in SENSITIVE_RESOURCES_PATTERNS) or
                "fail" in status or "denied" in status or "unauth" in status
            )

            if is_suspicious or len(suspicious_events) < 4:
                suspicious_events.append((ev, is_suspicious))

        if not suspicious_events:
            continue

        # Build chronological multi-hop steps
        steps = []
        step_num = 1
        path_score = 15.0

        for ev, is_susp in suspicious_events[-6:]:  # Focus on key steps
            ip_val = ev.source_ip or "127.0.0.1"
            act_val = ev.action or "APIRequest"
            svc_val = ev.service or "AWS"
            res_val = ev.resource or f"arn:aws:{svc_val}:::default"
            ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%SZ") if ev.timestamp else "N/A"

            # Step 1: User -> IP
            if step_num == 1:
                steps.append({
                    "step_number": step_num,
                    "source_entity": uid,
                    "source_type": "USER",
                    "target_entity": ip_val,
                    "target_type": "IP_ADDRESS",
                    "action": "Authenticate / Session Origination",
                    "timestamp": ts_str,
                    "status": "Success",
                    "is_suspicious": False,
                    "details": f"User initialized session from {ip_val}",
                })
                step_num += 1

            # Step 2: IP -> Action
            steps.append({
                "step_number": step_num,
                "source_entity": ip_val,
                "source_type": "IP_ADDRESS",
                "target_entity": act_val,
                "target_type": "ACTION",
                "action": f"Invoke {act_val}",
                "timestamp": ts_str,
                "status": ev.status or "Success",
                "is_suspicious": is_susp,
                "details": f"API call '{act_val}' executed via {svc_val}",
            })
            step_num += 1

            # Step 3: Action -> Service
            steps.append({
                "step_number": step_num,
                "source_entity": act_val,
                "source_type": "ACTION",
                "target_entity": svc_val,
                "target_type": "SERVICE",
                "action": f"Target Service {svc_val}",
                "timestamp": ts_str,
                "status": ev.status or "Success",
                "is_suspicious": svc_val.lower() in SENSITIVE_SERVICES,
                "details": f"Targeted service endpoint {svc_val}",
            })
            step_num += 1

            # Step 4: Service -> Target Resource
            steps.append({
                "step_number": step_num,
                "source_entity": svc_val,
                "source_type": "SERVICE",
                "target_entity": res_val,
                "target_type": "RESOURCE",
                "action": "Resource Mutation / Read",
                "timestamp": ts_str,
                "status": ev.status or "Success",
                "is_suspicious": any(p in res_val.lower() for p in SENSITIVE_RESOURCES_PATTERNS),
                "details": f"Access attempted on resource: {res_val}",
            })
            step_num += 1

            if is_susp:
                path_score += 15.0

        path_score = round(min(100.0, path_score), 1)
        severity = "CRITICAL" if path_score >= 75 else "HIGH" if path_score >= 50 else "MEDIUM" if path_score >= 25 else "LOW"

        target_res_label = steps[-1]["target_entity"] if steps else "N/A"
        summary = (
            f"Multi-hop attack path for identity '{uid}': originated from IP {steps[0]['target_entity'] if steps else 'N/A'}, "
            f"progressed through {len(steps)} entity interactions, reaching target resource {target_res_label}."
        )

        # Primary 5-entity multi-hop chain: User -> IP -> Action -> Service -> Resource
        key_event = None
        for ev, is_susp in reversed(suspicious_events):
            if is_susp:
                key_event = ev
                break
        if key_event is None and ev_list:
            key_event = ev_list[-1]

        primary_ip = key_event.source_ip if (key_event and key_event.source_ip) else (steps[0]["target_entity"] if steps else "127.0.0.1")
        primary_action = key_event.action if (key_event and key_event.action) else (steps[1]["target_entity"] if len(steps) > 1 else "APIRequest")
        primary_service = key_event.service if (key_event and key_event.service) else (steps[2]["target_entity"] if len(steps) > 2 else "CloudService")
        primary_resource = key_event.resource if (key_event and key_event.resource) else target_res_label

        chain = [
            {"type": "USER", "label": uid},
            {"type": "IP_ADDRESS", "label": primary_ip},
            {"type": "ACTION", "label": primary_action},
            {"type": "SERVICE", "label": primary_service},
            {"type": "RESOURCE", "label": primary_resource},
        ]

        attack_paths.append({
            "path_id": f"ap_{uid}_{len(steps)}",
            "cloud_user_id": uid,
            "target_resource": target_res_label,
            "path_risk_score": path_score,
            "severity": severity,
            "chain": chain,
            "primary_chain": f"{uid} → {primary_ip} → {primary_action} → {primary_service} → {primary_resource}",
            "steps": steps,
            "summary": summary,
        })

    return sorted(attack_paths, key=lambda x: x["path_risk_score"], reverse=True)

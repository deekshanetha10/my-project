import copy
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database.connection import get_db
from app.models.database_models import GraphWindow, RiskScore, User
from app.models.schemas import GraphWindowRead, GraphWindowWithData
from app.services.graph_builder import deserialize_graph, get_user_subgraph, serialize_graph

router = APIRouter()


@router.get("", response_model=List[GraphWindowRead], summary="List graph windows")
async def list_graph_windows(
    dataset_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(GraphWindow)
    if dataset_id is not None:
        stmt = stmt.where(GraphWindow.dataset_id == dataset_id)
    stmt = stmt.order_by(GraphWindow.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{window_id}", response_model=GraphWindowWithData,
            summary="Get graph window with full graph data")
async def get_graph_window(
    window_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    include_graph: bool = True,
):
    result = await db.execute(select(GraphWindow).where(GraphWindow.id == window_id))
    gw = result.scalar_one_or_none()
    if gw is None:
        raise HTTPException(status_code=404, detail="GraphWindow not found.")
    if not include_graph:
        gw.graph_json = None
    elif gw.graph_json and "nodes" in gw.graph_json:
        # Enrich nodes with risk_level and is_anomaly from RiskScore
        rs_result = await db.execute(
            select(RiskScore).where(RiskScore.graph_window_id == window_id)
        )
        risk_map = {r.cloud_user_id: r for r in rs_result.scalars().all()}
        if not risk_map:
            latest_rs = await db.execute(select(RiskScore).order_by(RiskScore.created_at.desc()))
            for r in latest_rs.scalars().all():
                if r.cloud_user_id not in risk_map:
                    risk_map[r.cloud_user_id] = r

        graph_dict = copy.deepcopy(gw.graph_json)
        threat_user_ids = {u for u, r in risk_map.items() if r.risk_level in ("HIGH", "CRITICAL")}
        threat_node_ids = set()
        for u in threat_user_ids:
            threat_node_ids.add(f"user::{u}")
            threat_node_ids.add(u)

        for link in graph_dict.get("links", []):
            src = link.get("source")
            dst = link.get("target")
            if src in threat_node_ids:
                threat_node_ids.add(dst)

        for node in graph_dict.get("nodes", []):
            node_id = node.get("id", "")
            raw_user = node_id.replace("user::", "") if node_id.startswith("user::") else node.get("label")
            if raw_user in risk_map:
                r = risk_map[raw_user]
                node["risk_level"] = r.risk_level
                node["risk_score"] = r.risk_score
                node["is_anomaly"] = r.risk_level in ("HIGH", "CRITICAL")
            elif node_id in threat_node_ids:
                node["is_anomaly"] = True
                node["risk_level"] = "HIGH"

        gw.graph_json = graph_dict
    return gw


@router.get("/user/{cloud_user_id}", summary="Get user ego subgraph from latest window")
async def get_user_subgraph_api(
    cloud_user_id: str,
    dataset_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return the 2-hop ego subgraph centred on a cloud user from the most recent window."""
    result = await db.execute(
        select(GraphWindow)
        .where(GraphWindow.dataset_id == dataset_id)
        .order_by(GraphWindow.created_at.desc())
        .limit(1)
    )
    gw = result.scalar_one_or_none()
    if gw is None or gw.graph_json is None:
        raise HTTPException(status_code=404, detail="No graph data found for this dataset.")

    G = deserialize_graph(gw.graph_json)
    subgraph = get_user_subgraph(G, cloud_user_id)
    return {
        "cloud_user_id": cloud_user_id,
        "window_id": gw.id,
        "node_count": subgraph.number_of_nodes(),
        "edge_count": subgraph.number_of_edges(),
        "graph": serialize_graph(subgraph),
    }

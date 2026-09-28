"""Dataset upload and processing API routes."""
import os
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.core.config import settings
from app.core.logging import log_audit
from app.database.connection import get_db
from app.models.database_models import CloudEvent, Dataset, GraphWindow, User
from app.models.schemas import DatasetProcessRequest, DatasetRead, MessageResponse
from app.services.data_ingestion import IngestionError, ingest_file
from app.services.preprocessing import preprocess_dataset
from app.services.graph_builder import build_and_store_graph_window
from app.ml.temporal.adaptive import (
    AdaptiveWindowConfig, split_into_fixed_windows, split_into_adaptive_windows,
)

router = APIRouter()

@router.post("/upload", response_model=DatasetRead, status_code=status.HTTP_201_CREATED,
             summary="Upload a CloudTrail-style CSV or JSON dataset")
async def upload_dataset(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Upload a CloudTrail-style CSV or JSON file for analysis.

    Required fields in the file: timestamp, user_id (or cloud_user_id)
    Optional fields: event_id, action, service, resource, source_ip, status
    """
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {settings.max_upload_size_mb} MB).",
        )

    try:
        dataset, summary = await ingest_file(
            db=db,
            file_content=content,
            filename=file.filename or "upload.csv",
            uploaded_by=current_user.id,
            is_demo=settings.demo_mode,
        )
    except IngestionError as e:
        raise HTTPException(status_code=422, detail=str(e))

    log_audit("dataset_uploaded", user_id=current_user.id,
              resource=f"dataset/{dataset.id}", detail=summary)
    return dataset


@router.get("", response_model=List[DatasetRead], summary="List all datasets")
async def list_datasets(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    result = await db.execute(
        select(Dataset).order_by(Dataset.upload_time.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/{dataset_id}", summary="Get dataset details")
async def get_dataset(
    dataset_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Dataset)
        .options(selectinload(Dataset.graph_windows))
        .where(Dataset.id == dataset_id)
    )
    dataset = result.scalar_one_or_none()
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    return {
        "id": dataset.id,
        "filename": dataset.filename,
        "file_type": dataset.file_type,
        "status": dataset.status,
        "upload_time": dataset.upload_time,
        "processed_time": dataset.processed_time,
        "raw_event_count": dataset.raw_event_count,
        "processed_event_count": dataset.processed_event_count,
        "dropped_event_count": dataset.dropped_event_count,
        "preprocessing_report": dataset.preprocessing_report,
        "is_demo": dataset.is_demo,
        "graph_windows": [
            {
                "id": gw.id,
                "dataset_id": gw.dataset_id,
                "window_type": gw.window_type,
                "window_hours": gw.window_hours,
                "start_time": gw.start_time,
                "end_time": gw.end_time,
                "event_count": gw.event_count,
                "node_count": gw.node_count,
                "edge_count": gw.edge_count,
                "created_at": gw.created_at,
                "processing_time_ms": gw.processing_time_ms,
            }
            for gw in (dataset.graph_windows or [])
        ],
    }


@router.post("/{dataset_id}/process", response_model=MessageResponse,
             summary="Preprocess dataset and build graph windows")
async def process_dataset(
    dataset_id: int,
    body: DatasetProcessRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Preprocess a dataset and construct temporal graph windows.

    - Normalizes timestamps, deduplicates, sorts events
    - Builds graph windows (fixed or adaptive)
    - Stores graph windows in the database
    """
    ds_result = await db.execute(select(Dataset).where(Dataset.id == dataset_id))
    dataset = ds_result.scalar_one_or_none()
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    if dataset.status == "PROCESSING":
        raise HTTPException(status_code=409, detail="Dataset is already being processed.")

    dataset.status = "PROCESSING"
    await db.commit()

    try:
        # Preprocess
        report = await preprocess_dataset(db, dataset_id)

        # Load processed events
        events_result = await db.execute(
            select(CloudEvent).where(CloudEvent.dataset_id == dataset_id)
        )
        events = events_result.scalars().all()

        from app.services.preprocessing import load_processed_dataframe
        df = load_processed_dataframe(events)

        if df.empty:
            return MessageResponse(
                message="Dataset processed but contains no valid events.",
                detail=report,
            )

        # Build graph windows
        window_type = body.window_type
        windows_created = 0

        if window_type == "adaptive":
            windows, selection = split_into_adaptive_windows(df)
            wh = selection.selected_window_hours
        else:
            wh = body.window_hours or float(settings.default_window_hours)
            windows = split_into_fixed_windows(df, wh)

        for window_df, w_start, w_end in windows:
            await build_and_store_graph_window(
                db=db,
                dataset_id=dataset_id,
                events_df=window_df,
                window_start=w_start,
                window_end=w_end,
                window_type=window_type,
                window_hours=wh,
            )
            windows_created += 1

        log_audit("dataset_processed", user_id=current_user.id,
                  resource=f"dataset/{dataset_id}",
                  detail={"windows_created": windows_created})

        return MessageResponse(
            message=f"Dataset processed. {windows_created} graph window(s) created.",
            detail={**report, "windows_created": windows_created, "window_type": window_type},
        )

    except Exception as e:
        ds_result2 = await db.execute(select(Dataset).where(Dataset.id == dataset_id))
        ds = ds_result2.scalar_one_or_none()
        if ds:
            ds.status = "FAILED"
            await db.commit()
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


@router.get("/{dataset_id}/validation-summary", summary="Get dataset validation and entity metrics")
async def get_validation_summary(
    dataset_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return automatic validation results and extracted entity counts from PostgreSQL."""
    ds_result = await db.execute(select(Dataset).where(Dataset.id == dataset_id))
    dataset = ds_result.scalar_one_or_none()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    events_res = await db.execute(select(CloudEvent).where(CloudEvent.dataset_id == dataset_id))
    events = events_res.scalars().all()

    if not events:
        return {
            "dataset_id": dataset_id,
            "status": dataset.status,
            "total_records": dataset.raw_event_count or 0,
            "valid_records": 0,
            "required_fields_valid": False,
            "missing_values_handled": 0,
            "duplicate_records": 0,
            "users_count": 0,
            "ips_count": 0,
            "services_count": 0,
            "actions_count": 0,
            "resources_count": 0,
            "users": [],
            "ips": [],
            "services": [],
        }

    from app.services.preprocessing import load_processed_dataframe
    df = load_processed_dataframe(events)

    users = [u for u in df["cloud_user_id"].dropna().unique() if str(u).strip() and str(u) != "nan"]
    ips = [ip for ip in df["source_ip"].dropna().unique() if str(ip).strip() and str(ip) != "nan"]
    services = [s for s in df["service"].dropna().unique() if str(s).strip() and str(s) != "nan"]
    actions = [a for a in df["action"].dropna().unique() if str(a).strip() and str(a) != "nan"]
    resources = [r for r in df["resource"].dropna().unique() if str(r).strip() and str(r) != "nan"]

    report = dataset.preprocessing_report or {}

    return {
        "dataset_id": dataset_id,
        "filename": dataset.filename,
        "status": dataset.status,
        "total_records": dataset.raw_event_count or len(events),
        "valid_records": len(events),
        "required_fields_valid": True,
        "missing_values_handled": report.get("dropped_missing_fields", 0),
        "duplicate_records": report.get("dropped_duplicates", 0),
        "users_count": len(users),
        "ips_count": len(ips),
        "services_count": len(services),
        "actions_count": len(actions),
        "resources_count": len(resources),
        "users": users[:10],
        "ips": ips[:10],
        "services": services[:10],
    }


@router.post("/{dataset_id}/analyze-pipeline", summary="Execute complete end-to-end SOC threat intelligence pipeline")
async def run_full_pipeline(
    dataset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes the entire end-to-end research workflow:
    Dataset -> PostgreSQL -> Temporal Graph -> GNN Analysis -> Risk Evidence Fusion -> 
    Continuous Risk Evolution -> Risk-Adaptive Autonomous Enforcement -> Audit Records
    """
    ds_result = await db.execute(select(Dataset).where(Dataset.id == dataset_id))
    dataset = ds_result.scalar_one_or_none()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")

    # 1. Preprocess & build windows if needed
    gw_result = await db.execute(
        select(GraphWindow).where(GraphWindow.dataset_id == dataset_id).order_by(GraphWindow.created_at.desc())
    )
    existing_gw = gw_result.scalars().first()

    if existing_gw is None or dataset.status != "PROCESSED":
        # Process dataset
        await preprocess_dataset(db, dataset_id)
        events_res = await db.execute(select(CloudEvent).where(CloudEvent.dataset_id == dataset_id))
        events = events_res.scalars().all()
        from app.services.preprocessing import load_processed_dataframe
        df = load_processed_dataframe(events)
        if not df.empty:
            windows = split_into_fixed_windows(df, 24.0)
            for window_df, w_start, w_end in windows:
                await build_and_store_graph_window(
                    db=db,
                    dataset_id=dataset_id,
                    events_df=window_df,
                    window_start=w_start,
                    window_end=w_end,
                    window_type="fixed",
                    window_hours=24.0,
                )

        gw_res = await db.execute(
            select(GraphWindow).where(GraphWindow.dataset_id == dataset_id).order_by(GraphWindow.created_at.desc())
        )
        existing_gw = gw_res.scalars().first()

    if existing_gw is None:
        raise HTTPException(status_code=400, detail="Unable to build graph windows for this dataset.")

    # 2. Run GNN Threat Inference
    from app.services.anomaly_service import run_inference
    anomalies = await run_inference(
        db=db,
        graph_window_id=existing_gw.id,
        model_type="baseline",
        threshold=0.5,
    )

    # 3. Compute continuous risk evolution for all users in the dataset
    from app.services.risk_service import compute_continuous_risk_evolution
    from app.services.response_service import evaluate_and_enforce_user_risk
    events_res = await db.execute(select(CloudEvent).where(CloudEvent.dataset_id == dataset_id))
    events = events_res.scalars().all()
    user_ids = list(set(ev.cloud_user_id for ev in events if ev.cloud_user_id))

    for uid in user_ids:
        evo = await compute_continuous_risk_evolution(db, uid)
        if evo:
            final_step = evo[-1]
            await evaluate_and_enforce_user_risk(
                db=db,
                cloud_user_id=uid,
                risk_score=final_step["risk_score"],
                risk_level=final_step["risk_level"],
                reason=f"Risk evolution culminated at {final_step['risk_level']} ({final_step['risk_score']:.1f}) at {final_step['time_label']}",
            )

    # 4. Fetch updated database state metrics
    from app.models.database_models import CloudUserEnforcement, Anomaly, RiskScore
    enf_res = await db.execute(select(CloudUserEnforcement))
    all_enfs = enf_res.scalars().all()

    anom_res = await db.execute(
        select(Anomaly).where(Anomaly.graph_window_id == existing_gw.id, Anomaly.is_anomaly == True)
    )
    flagged_anoms = anom_res.scalars().all()

    restricted_count = sum(1 for e in all_enfs if e.status == "RESTRICTED")
    blocked_count = sum(1 for e in all_enfs if e.status == "BLOCKED")
    high_count = sum(1 for e in all_enfs if e.risk_score >= 50.0 and e.risk_score < 75.0)
    critical_count = sum(1 for e in all_enfs if e.risk_score >= 75.0)

    # Log pipeline execution audit record
    log_audit(
        "pipeline_analysis_completed",
        user_id=current_user.id,
        resource=f"dataset/{dataset_id}",
        detail={
            "events": len(events),
            "users": len(user_ids),
            "anomalies": len(flagged_anoms),
            "restricted": restricted_count,
            "blocked": blocked_count,
        }
    )

    return {
        "status": "COMPLETED",
        "message": "Full SOC Threat Intelligence Pipeline executed successfully.",
        "dataset_id": dataset_id,
        "graph_window_id": existing_gw.id,
        "events_analyzed": len(events),
        "users_analyzed": len(user_ids),
        "anomalies_detected": len(flagged_anoms),
        "high_risk_users": high_count,
        "critical_users": critical_count,
        "restricted_users": restricted_count,
        "blocked_users": blocked_count,
        "graph_nodes": existing_gw.node_count or 0,
        "graph_edges": existing_gw.edge_count or 0,
        "time_windows": 1,
    }

import asyncio
from sqlalchemy import select
from app.database.connection import AsyncSessionLocal
from app.models.database_models import RiskScore
from app.services.response_service import evaluate_and_enforce_user_risk


async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(RiskScore)
            .where(RiskScore.cloud_user_id == "u006")
            .order_by(RiskScore.created_at.desc())
        )

        risk = result.scalars().first()

        if not risk:
            print("No risk score found for u006")
            return

        print("Latest risk:", risk.risk_score, risk.risk_level)

        status, action = await evaluate_and_enforce_user_risk(
            db=db,
            cloud_user_id="u006",
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            reason="Synchronize enforcement with latest calculated risk",
            trigger_anomaly_id=None,
        )

        print("Updated status:", status)
        print("Action:", action)


asyncio.run(main())
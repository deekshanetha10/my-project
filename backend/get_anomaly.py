import asyncio
from sqlalchemy import select
from app.database.connection import AsyncSessionLocal
from app.models.database_models import Anomaly

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Anomaly).where(Anomaly.cloud_user_id == "u006")
        )
        anomalies = result.scalars().all()

        for a in anomalies:
            print(
                f"ID={a.id}, "
                f"USER={a.cloud_user_id}, "
                f"SCORE={a.anomaly_score}, "
                f"IS_ANOMALY={a.is_anomaly}, "
                f"GRAPH_WINDOW={a.graph_window_id}"
            )

asyncio.run(main())
import asyncio
from app.database.connection import AsyncSessionLocal
from app.api.simulator import simulate_risk
from app.models.schemas import SimulateRiskRequest
from app.models.database_models import User

async def main():
    async with AsyncSessionLocal() as db:
        req = SimulateRiskRequest(cloud_user_id="u006", privilege_escalation=True)
        # Using a dummy User is okay since current_user isn't strictly verified inside the logic
        res = await simulate_risk(req, db, User())
        print(f"Current: {res.current_risk_score} -> {res.simulated_risk_score}")
        print(f"Delta: {res.delta}")
        print(f"Action: {res.predicted_action}")

if __name__ == "__main__":
    asyncio.run(main())

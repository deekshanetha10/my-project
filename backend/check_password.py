import asyncio
from sqlalchemy import select
from app.database.connection import get_db
from app.models.database_models import User
from app.core.security import verify_password

async def test():
    db = await get_db().__anext__()
    result = await db.execute(
        select(User).where(User.username == "admin")
    )
    user = result.scalar_one_or_none()

    print("USER EXISTS:", user is not None)

    if user:
        print("HASH:", user.hashed_password)
        print("PASSWORD MATCH:", verify_password("Admin123!", user.hashed_password))

    await db.close()

asyncio.run(test())

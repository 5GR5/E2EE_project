import asyncio
import sys
sys.path.insert(0, 'server')

from server.db import engine
from server.models import Base

async def init():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables created successfully!")

asyncio.run(init())

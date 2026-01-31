import asyncio
from server.db import engine
from server.models import Base
from server.simple_messages import SimpleMessage  # Import to register table

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables created successfully!")

if __name__ == "__main__":
    asyncio.run(init_db())

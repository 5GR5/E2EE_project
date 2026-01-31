#!/usr/bin/env python3
"""Reset the database with all tables."""
import asyncio
import sys
import os

# Add server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'server'))

from server.db import engine
from server.models import Base
from server.simple_messages import SimpleMessage  # Import to register

async def init():
    async with engine.begin() as conn:
        print("Dropping all tables...")
        await conn.run_sync(Base.metadata.drop_all)
        print("Creating all tables...")
        await conn.run_sync(Base.metadata.create_all)
    print('✓ Database reset complete!')
    
if __name__ == '__main__':
    asyncio.run(init())

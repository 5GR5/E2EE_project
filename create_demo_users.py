#!/usr/bin/env python3
"""
Create demo users for testing the E2EE messaging app.
Creates 4 users: alice, bob, charlie, david (all with password: demo123)
"""

import asyncio
import sys
from pathlib import Path

# Add server directory to path
sys.path.insert(0, str(Path(__file__).parent / 'server'))

from server.db import get_db, init_db
from server.crud import create_user
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DEMO_USERS = [
    {"username": "alice", "password": "demo123"},
    {"username": "bob", "password": "demo123"},
    {"username": "charlie", "password": "demo123"},
    {"username": "david", "password": "demo123"}
]

async def create_demo_users():
    """Create demo users in the database."""
    print("Initializing database...")
    await init_db()

    print("\nCreating demo users...")
    async for db in get_db():
        for user_data in DEMO_USERS:
            try:
                # Hash the password
                password_hash = pwd_context.hash(user_data["password"])

                # Create user
                user = await create_user(
                    db,
                    username=user_data["username"],
                    password_hash=password_hash
                )

                if user:
                    print(f"✓ Created user: {user_data['username']}")
                else:
                    print(f"✗ User {user_data['username']} already exists")

            except Exception as e:
                print(f"✗ Error creating {user_data['username']}: {e}")

        break  # Only need one db session

    print("\n" + "="*50)
    print("Demo users created successfully!")
    print("="*50)
    print("\nYou can now login with:")
    print("  Username: alice, bob, charlie, or david")
    print("  Password: demo123")
    print()

if __name__ == "__main__":
    asyncio.run(create_demo_users())

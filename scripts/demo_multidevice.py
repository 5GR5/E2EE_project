#!/usr/bin/env python3
"""
Multi-Device Support Demonstration

This script demonstrates how the E2EE messaging app supports multiple devices
for a single user, with each device having unique encryption keys.

Run this to see:
1. User registration
2. Multiple device registration for same user
3. How messages are encrypted separately for each device
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path to import server modules
sys.path.insert(0, str(Path(__file__).parent.parent / "server"))

from sqlalchemy import select
from db import SessionLocal, engine
from models import Base, User, Device, Message
from auth import hash_password
import uuid


async def demo():
    """Demonstrate multi-device support"""

    print("=" * 70)
    print("🔐 MULTI-DEVICE SUPPORT DEMONSTRATION")
    print("=" * 70)
    print()

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with SessionLocal() as session:
        # Step 1: Create Alice
        print("📱 STEP 1: Create user 'Alice'")
        alice = User(username="alice", password_hash=hash_password("password123"))
        session.add(alice)
        await session.commit()
        await session.refresh(alice)
        print(f"   ✅ User created: alice (ID: {alice.id})")
        print()

        # Step 2: Alice registers 3 devices
        print("📱 STEP 2: Alice logs in from 3 different devices")
        print()

        devices = []
        device_names = [
            "Chrome on MacBook Pro",
            "Firefox on MacBook Pro",
            "Safari on iPhone"
        ]

        for i, device_name in enumerate(device_names, 1):
            # Each device gets unique cryptographic keys
            device = Device(
                user_id=alice.id,
                device_name=device_name,
                # In real app, these would be actual public keys
                identity_key_public=f"IK_ALICE_DEVICE{i}_PUBLIC_KEY",
                identity_signing_public=f"ISK_ALICE_DEVICE{i}_PUBLIC_KEY"
            )
            session.add(device)
            devices.append(device)
            print(f"   Device {i}: {device_name}")
            print(f"      Identity Key: IK_ALICE_DEVICE{i}_PUBLIC_KEY")

        await session.commit()
        for device in devices:
            await session.refresh(device)

        print()
        print("   ✅ All 3 devices registered with unique keys")
        print()

        # Step 3: Create Bob with 1 device
        print("📱 STEP 3: Create user 'Bob' with 1 device")
        bob = User(username="bob", password_hash=hash_password("password123"))
        session.add(bob)
        await session.commit()
        await session.refresh(bob)

        bob_device = Device(
            user_id=bob.id,
            device_name="Chrome on Windows",
            identity_key_public="IK_BOB_DEVICE1_PUBLIC_KEY",
            identity_signing_public="ISK_BOB_DEVICE1_PUBLIC_KEY"
        )
        session.add(bob_device)
        await session.commit()
        await session.refresh(bob_device)

        print(f"   ✅ Bob created with 1 device: {bob_device.device_name}")
        print()

        # Step 4: Bob sends message to Alice
        print("📨 STEP 4: Bob sends message 'Hello Alice!' to Alice")
        print()
        print("   ⚠️  Important: Bob's client must encrypt the message")
        print("       SEPARATELY for EACH of Alice's 3 devices!")
        print()

        # Simulate Bob's client querying Alice's devices
        result = await session.execute(
            select(Device).where(Device.user_id == alice.id)
        )
        alice_devices = result.scalars().all()

        print(f"   📋 Bob's client queries server: 'Who are Alice's devices?'")
        print(f"   📋 Server responds: {len(alice_devices)} devices found")
        print()

        for i, device in enumerate(alice_devices, 1):
            print(f"      Device {i}: {device.device_name}")
            print(f"         Device ID: {device.id}")
            print(f"         Identity Key: {device.identity_key_public}")

        print()
        print("   🔐 Bob's client now encrypts message 3 times:")
        print()

        # Simulate encrypting for each device
        message_id_base = str(uuid.uuid4())
        for i, alice_device in enumerate(alice_devices, 1):
            # In real app, each would have different ciphertext due to different keys
            ciphertext = f"ENCRYPTED_FOR_DEVICE_{i}_CIPHERTEXT_GIBBERISH_XYZ123"

            msg = Message(
                message_id=f"{message_id_base}_to_device_{i}",
                from_device_id=bob_device.id,
                to_device_id=alice_device.id,
                header={"n": 0, "dh_pub": "ephemeral_key"},
                ciphertext=ciphertext,
                is_initial_message=True
            )
            session.add(msg)

            print(f"      Message {i} → {alice_device.device_name}")
            print(f"         Encrypted with: {alice_device.identity_key_public}")
            print(f"         Ciphertext: {ciphertext[:40]}...")
            print()

        await session.commit()
        print("   ✅ 3 encrypted messages sent to server")
        print()

        # Step 5: Show what happens when Alice checks messages
        print("📬 STEP 5: What happens when Alice checks messages?")
        print()

        for i, alice_device in enumerate(alice_devices, 1):
            result = await session.execute(
                select(Message).where(Message.to_device_id == alice_device.id)
            )
            msgs = result.scalars().all()

            print(f"   Device {i} ({alice_device.device_name}):")
            print(f"      Receives: {len(msgs)} message(s)")
            if msgs:
                print(f"      Can decrypt using its own private keys")
                print(f"      Decrypted text: 'Hello Alice!'")
            print()

        print("=" * 70)
        print("✨ KEY TAKEAWAYS:")
        print("=" * 70)
        print()
        print("1. ✅ Same user (Alice) can have MULTIPLE devices")
        print("2. ✅ Each device has UNIQUE encryption keys")
        print("3. ✅ Sender encrypts message ONCE PER RECIPIENT DEVICE")
        print("4. ✅ Server delivers encrypted message to correct device")
        print("5. ✅ Only recipient device can decrypt (has private key)")
        print()
        print("🔒 Security: If Alice's phone is stolen, only that device's")
        print("   messages are compromised. Her laptop messages stay safe!")
        print()
        print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())

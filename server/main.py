"""
E2EE Instant Messaging Server

FastAPI application implementing a secure instant messaging server with end-to-end
encryption (E2EE) using Signal Protocol (X3DH + Double Ratchet).

Features:
- User authentication (JWT)
- Multi-device support
- Cryptographic key exchange (prekey bundles)
- WebSocket real-time messaging
- Message persistence and offline delivery

Security: Server never sees plaintext messages (true E2EE).
"""

import json
from uuid import UUID
from fastapi import FastAPI, Depends, HTTPException, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from db import get_session
from models import Base, User, Device, SignedPreKey, OneTimePreKey
from auth import hash_password, verify_password, create_access_token, get_current_user_id
from schemas import (
    RegisterIn, LoginIn, TokenOut,
    DeviceCreateIn, DeviceOut,
    KeysUploadIn, PreKeyBundleOut, SignedPreKeyIn, OneTimePreKeyIn
)
from crud import (
    get_user_by_username, get_device,
    get_active_signed_prekey, consume_one_time_prekey,
    create_message, get_undelivered_messages,
    mark_delivered, mark_read
)
from ws import presence

app = FastAPI(title="Secure IM Server (Signal-style infra)")

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:5175"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- AUTH ----

@app.post("/auth/register", response_model=TokenOut)
async def register(data: RegisterIn, session: AsyncSession = Depends(get_session)):
    """
    Register a new user account.

    Args:
        data: Registration data (username, password)
        session: Database session

    Returns:
        TokenOut: JWT access token

    Raises:
        HTTPException 409: Username already exists
    """
    existing = await get_user_by_username(session, data.username)
    if existing:
        raise HTTPException(409, "Username already exists")

    user = User(username=data.username, password_hash=hash_password(data.password))
    session.add(user)
    await session.commit()

    token = create_access_token(str(user.id))
    return TokenOut(access_token=token)

@app.post("/auth/login", response_model=TokenOut)
async def login(data: LoginIn, session: AsyncSession = Depends(get_session)):
    """
    Authenticate user and return JWT token.

    Args:
        data: Login credentials (username, password)
        session: Database session

    Returns:
        TokenOut: JWT access token

    Raises:
        HTTPException 401: Invalid credentials
    """
    user = await get_user_by_username(session, data.username)
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Bad credentials")
    token = create_access_token(str(user.id))
    return TokenOut(access_token=token)

@app.get("/users")
async def get_users(
    user_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session)
):
    """Get all users except the current user"""
    from sqlalchemy import select
    result = await session.execute(select(User))
    all_users = result.scalars().all()
    # Return all users except current user
    return [
        {"id": str(u.id), "username": u.username}
        for u in all_users
        if str(u.id) != user_id
    ]
    
    
@app.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID,
    caller_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
):
    """Delete a user and all their data (devices, keys, messages)"""
    from models import Message
    from sqlalchemy import delete as sql_delete

    # Get all device IDs for this user
    result = await session.execute(select(Device).where(Device.user_id == user_id))
    devices = result.scalars().all()
    device_ids = [d.id for d in devices]

    # Delete messages referencing these devices (no cascade on Message)
    if device_ids:
        for did in device_ids:
            await session.execute(sql_delete(Message).where(
                (Message.from_device_id == did) | (Message.to_device_id == did)
            ))

    # Delete user (cascades to devices → signed_prekeys, one_time_prekeys)
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")
    await session.delete(user)
    await session.commit()
    return {"deleted": True}


@app.post("/admin/reset")
async def admin_reset(
    caller_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
):
    """Delete all users, devices, keys, and messages from the database"""
    from models import Message
    from sqlalchemy import delete as sql_delete
    await session.execute(sql_delete(Message))
    await session.execute(sql_delete(OneTimePreKey))
    await session.execute(sql_delete(SignedPreKey))
    await session.execute(sql_delete(Device))
    await session.execute(sql_delete(User))
    await session.commit()
    return {"reset": True}


@app.get("/users/{user_id}/devices")
async def list_user_devices(
    user_id: UUID,
    _caller_user_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
):
    """
    List all devices for a specific user.

    Required for multi-device support - clients need to encrypt messages
    separately for each of the recipient's devices.

    Args:
        user_id: Target user's UUID
        _caller_user_id: Authenticated caller's ID (from JWT)
        session: Database session

    Returns:
        dict: User ID and list of their devices with public keys
    """
    result = await session.execute(
        select(Device).where(Device.user_id == user_id).order_by(Device.created_at.asc())
    )
    devices = result.scalars().all()

    return {
        "user_id": str(user_id),
        "devices": [
            {
                "device_id": str(d.id),
                "id": str(d.id),  # Also include 'id' field for compatibility
                "device_name": d.device_name,
                "identity_key_public": d.identity_key_public,
                "identity_signing_public": d.identity_signing_public
            }
            for d in devices
        ],
    }

# ---- DEVICES ----

@app.post("/devices", response_model=DeviceOut)
async def create_device(
    data: DeviceCreateIn,
    user_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
):
    device = Device(
        user_id=UUID(user_id),
        device_name=data.device_name,
        identity_key_public=data.identity_key_public,
        identity_signing_public=data.identity_signing_public,
    )
    session.add(device)
    await session.commit()
    return DeviceOut(id=device.id, device_name=device.device_name)

# ---- KEYS ----

@app.post("/keys/upload")
async def upload_keys(
    data: KeysUploadIn,
    user_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
):
    device = await get_device(session, data.device_id)
    if not device or str(device.user_id) != user_id:
        raise HTTPException(404, "Device not found")

    # Deactivate old active SPKs (optional policy)
    # Keep history, but set is_active=False for old ones
    if data.signed_prekey:
        # naive approach: deactivate all previous
        await session.execute(
            SignedPreKey.__table__.update()
            .where(SignedPreKey.device_id == device.id, SignedPreKey.is_active == True)  # noqa: E712
            .values(is_active=False)
        )
        spk = SignedPreKey(
            device_id=device.id,
            key_id=data.signed_prekey.key_id,
            public_key=data.signed_prekey.public_key,
            signature=data.signed_prekey.signature,
            is_active=True,
        )
        session.add(spk)

    for k in data.one_time_prekeys:
        session.add(OneTimePreKey(device_id=device.id, key_id=k.key_id, public_key=k.public_key))

    await session.commit()
    return {"status": "ok"}

@app.get("/keys/bundle/{target_user_id}", response_model=PreKeyBundleOut)
async def get_prekey_bundle(
    target_user_id: UUID,
    device_id: UUID | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    _caller_user_id: str = Depends(get_current_user_id),
):
    try:
        print(f"[KEY_BUNDLE] Fetching bundle for user_id={target_user_id}, device_id={device_id}")

        # choose device:
        if device_id:
            print(f"[KEY_BUNDLE] Looking up specific device: {device_id}")
            device = await get_device(session, device_id)
            if not device:
                print(f"[KEY_BUNDLE] Device not found: {device_id}")
                raise HTTPException(404, "Target device not found")
            if device.user_id != target_user_id:
                print(f"[KEY_BUNDLE] Device {device_id} belongs to user {device.user_id}, not {target_user_id}")
                raise HTTPException(404, "Target device not found")
        else:
            # pick newest device (policy)
            print(f"[KEY_BUNDLE] Looking up newest device for user {target_user_id}")
            from sqlalchemy import select
            res = await session.execute(
                select(Device).where(Device.user_id == target_user_id).order_by(Device.created_at.desc()).limit(1)
            )
            device = res.scalar_one_or_none()
            if not device:
                print(f"[KEY_BUNDLE] No devices found for user {target_user_id}")
                raise HTTPException(404, "Target user has no devices")
            print(f"[KEY_BUNDLE] Found device: {device.id}")

        print(f"[KEY_BUNDLE] Fetching signed prekey for device {device.id}")
        spk = await get_active_signed_prekey(session, device.id)
        if not spk:
            print(f"[KEY_BUNDLE] No active signed prekey for device {device.id}")
            raise HTTPException(409, "Target device has no active signed prekey")
        print(f"[KEY_BUNDLE] Found signed prekey: key_id={spk.key_id}")

        # Consume one-time prekey (session already has transaction from dependency)
        print(f"[KEY_BUNDLE] Consuming one-time prekey for device {device.id}")
        opk = await consume_one_time_prekey(session, device.id)
        if opk:
            print(f"[KEY_BUNDLE] Consumed one-time prekey: key_id={opk.key_id}")
        else:
            print(f"[KEY_BUNDLE] No one-time prekeys available")
        await session.commit()

        # Return flattened format matching client expectations
        bundle = PreKeyBundleOut(
            user_id=target_user_id,
            device_id=device.id,
            identity_key_public=device.identity_key_public,
            identity_signing_public=device.identity_signing_public,
            # Flatten signed prekey
            signed_prekey_id=spk.key_id,
            signed_prekey_public=spk.public_key,
            signed_prekey_signature=spk.signature,
            # Flatten one-time prekey (optional)
            one_time_prekey_id=opk.key_id if opk else None,
            one_time_prekey_public=opk.public_key if opk else None,
        )
        print(f"[KEY_BUNDLE] Successfully built bundle for device {device.id}")
        return bundle
    except HTTPException:
        raise
    except Exception as e:
        print(f"[KEY_BUNDLE] Unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Internal server error: {str(e)}")

# ---- WEBSOCKET ----

@app.websocket("/ws")
async def ws_endpoint(
    ws: WebSocket,
    token: str = Query(...),
    device_id: UUID = Query(...),
    session: AsyncSession = Depends(get_session),
):
    # Verify token manually (reuse get_current_user_id logic without HTTPBearer)
    import jwt, os
    from auth import JWT_SECRET, JWT_ALG
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload["sub"]
    except Exception:
        await ws.close(code=4401)
        return

    device = await get_device(session, device_id)
    if not device or str(device.user_id) != user_id:
        await ws.close(code=4403)
        return

    await presence.connect(device_id, ws)

    # Flush undelivered
    pending = await get_undelivered_messages(session, device_id)
    for m in pending:
        try:
            # Get sender's user_id and device_name from device
            sender_device = await get_device(session, m.from_device_id)
            await ws.send_text(json.dumps({
                "type": "deliver",
                "from_device_id": str(m.from_device_id),
                "from_user_id": str(sender_device.user_id) if sender_device else None,
                "from_device_name": sender_device.device_name if sender_device else "Unknown Device",
                "message_id": m.message_id,
                "header": m.header,
                "ciphertext": m.ciphertext,
                "nonce": m.nonce,
                "ad_length": m.ad_length,
                "is_initial_message": m.is_initial_message,
                "x3dh_header": m.x3dh_header,
                "server_ts": m.server_ts.isoformat(),
            }))
        except Exception:
            break  # Connection broke during flush; the message stays undelivered for next connect

    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            mtype = msg.get("type")
            print(f"[WS] Received message type={mtype} from device={device_id}")

            if mtype == "send":
                print(f"[WS] Processing send message: message_id={msg.get('message_id')}, to_device={msg.get('to_device_id')}")
                to_device_id = UUID(msg["to_device_id"])
                message_id = msg["message_id"]
                header = msg["header"]
                ciphertext = msg["ciphertext"]
                # Extract Signal protocol encryption fields
                nonce = msg.get("nonce")
                ad_length = msg.get("ad_length")
                is_initial_message = msg.get("is_initial_message", False)
                x3dh_header = msg.get("x3dh_header")

                # store
                await create_message(
                    session, message_id, device_id, to_device_id,
                    header, ciphertext, nonce, ad_length, is_initial_message, x3dh_header
                )
                await session.commit()

                # deliver if online
                peer_ws = presence.get(to_device_id)
                if peer_ws:
                    try:
                        await peer_ws.send_text(json.dumps({
                            "type": "deliver",
                            "from_device_id": str(device_id),
                            "from_user_id": str(user_id),
                            "from_device_name": device.device_name,
                            "message_id": message_id,
                            "header": header,
                            "ciphertext": ciphertext,
                            "nonce": nonce,
                            "ad_length": ad_length,
                            "is_initial_message": is_initial_message,
                            "x3dh_header": x3dh_header,
                            "server_ts": "",
                        }))
                    except Exception:
                        # Peer's connection is stale — remove it so the message
                        # will be queued for offline delivery on their next connect.
                        presence.disconnect(to_device_id, peer_ws)

            elif mtype == "ack_delivered":
                message_id = msg["message_id"]
                await mark_delivered(session, device_id, message_id)
                await session.commit()

            elif mtype == "ack_read":
                message_id = msg["message_id"]
                await mark_read(session, device_id, message_id)
                await session.commit()

            else:
                # ignore unknown
                pass

    except Exception:
        presence.disconnect(device_id, ws)
        try:
            await ws.close()
        except Exception:
            pass
        
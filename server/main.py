import json
from uuid import UUID
from fastapi import FastAPI, Depends, HTTPException, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .models import Base, User, Device, SignedPreKey, OneTimePreKey
from .auth import hash_password, verify_password, create_access_token, get_current_user_id
from .schemas import (
    RegisterIn, LoginIn, TokenOut,
    DeviceCreateIn, DeviceOut,
    KeysUploadIn, PreKeyBundleOut, SignedPreKeyIn, OneTimePreKeyIn
)
from .crud import (
    get_user_by_username, get_device,
    get_active_signed_prekey, consume_one_time_prekey,
    create_message, get_undelivered_messages,
    mark_delivered, mark_read
)
from .ws import presence

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
    user = await get_user_by_username(session, data.username)
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Bad credentials")
    token = create_access_token(str(user.id))
    return TokenOut(access_token=token)

# ---- DEVICES ----

@app.post("/devices", response_model=DeviceOut)
async def create_device(
    data: DeviceCreateIn,
    user_id: str = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
):
    device = Device(user_id=UUID(user_id), device_name=data.device_name, identity_key_public=data.identity_key_public)
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
    # choose device:
    if device_id:
        device = await get_device(session, device_id)
        if not device or device.user_id != target_user_id:
            raise HTTPException(404, "Target device not found")
    else:
        # pick newest device (policy)
        from sqlalchemy import select
        res = await session.execute(
            select(Device).where(Device.user_id == target_user_id).order_by(Device.created_at.desc()).limit(1)
        )
        device = res.scalar_one_or_none()
        if not device:
            raise HTTPException(404, "Target user has no devices")

    spk = await get_active_signed_prekey(session, device.id)
    if not spk:
        raise HTTPException(409, "Target device has no active signed prekey")

    # Transaction for consuming OPK
    async with session.begin():
        opk = await consume_one_time_prekey(session, device.id)

    bundle = PreKeyBundleOut(
        user_id=target_user_id,
        device_id=device.id,
        identity_key_public=device.identity_key_public,
        signed_prekey=SignedPreKeyIn(key_id=spk.key_id, public_key=spk.public_key, signature=spk.signature),
        one_time_prekey=OneTimePreKeyIn(key_id=opk.key_id, public_key=opk.public_key) if opk else None,
    )
    return bundle

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
    from .auth import JWT_SECRET, JWT_ALG
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
        await ws.send_text(json.dumps({
            "type": "deliver",
            "from_device_id": str(m.from_device_id),
            "message_id": m.message_id,
            "header": m.header,
            "ciphertext": m.ciphertext,
            "server_ts": m.server_ts.isoformat(),
        }))

    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            mtype = msg.get("type")

            if mtype == "send":
                to_device_id = UUID(msg["to_device_id"])
                message_id = msg["message_id"]
                header = msg["header"]
                ciphertext = msg["ciphertext"]

                # store
                await create_message(session, message_id, device_id, to_device_id, header, ciphertext)
                await session.commit()

                # deliver if online
                peer_ws = presence.get(to_device_id)
                if peer_ws:
                    await peer_ws.send_text(json.dumps({
                        "type": "deliver",
                        "from_device_id": str(device_id),
                        "message_id": message_id,
                        "header": header,
                        "ciphertext": ciphertext,
                        "server_ts": "",  # optional fill after re-read
                    }))

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
        presence.disconnect(device_id)
        try:
            await ws.close()
        except Exception:
            pass

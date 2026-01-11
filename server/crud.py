from datetime import datetime
from uuid import UUID
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User, Device, SignedPreKey, OneTimePreKey, Message

# ---- helpers for CRUD operations ----

async def get_user_by_username(session: AsyncSession, username: str) -> User | None:
    res = await session.execute(select(User).where(User.username == username))
    return res.scalar_one_or_none()

async def get_device(session: AsyncSession, device_id: UUID) -> Device | None:
    res = await session.execute(select(Device).where(Device.id == device_id))
    return res.scalar_one_or_none()

# store uploaded keys
async def create_message(
    session: AsyncSession,
    message_id: str,
    from_device_id: UUID,
    to_device_id: UUID,
    header: dict,
    ciphertext: str,
):
    msg = Message(
        message_id=message_id,
        from_device_id=from_device_id,
        to_device_id=to_device_id,
        header=header,
        ciphertext=ciphertext,
    )
    session.add(msg)
    await session.flush()
    return msg

async def mark_delivered(session: AsyncSession, to_device_id: UUID, message_id: str):
    await session.execute(
        update(Message)
        .where(Message.to_device_id == to_device_id, Message.message_id == message_id, Message.delivered_ts.is_(None))
        .values(delivered_ts=datetime.utcnow())
    )

async def mark_read(session: AsyncSession, to_device_id: UUID, message_id: str):
    await session.execute(
        update(Message)
        .where(Message.to_device_id == to_device_id, Message.message_id == message_id, Message.read_ts.is_(None))
        .values(read_ts=datetime.utcnow())
    )

# fetch undelivered messages for a device
async def get_undelivered_messages(session: AsyncSession, device_id: UUID, limit: int = 200):
    res = await session.execute(
        select(Message)
        .where(Message.to_device_id == device_id, Message.delivered_ts.is_(None))
        .order_by(Message.server_ts.asc())
        .limit(limit)
    )
    return list(res.scalars().all())

# fetch active signed prekey for a device
async def get_active_signed_prekey(session: AsyncSession, device_id: UUID) -> SignedPreKey | None:
    res = await session.execute(
        select(SignedPreKey)
        .where(SignedPreKey.device_id == device_id, SignedPreKey.is_active == True)  # noqa: E712
        .order_by(SignedPreKey.created_at.desc())
        .limit(1)
    )
    return res.scalar_one_or_none()

# consume one-time prekey for a device and mark it used
async def consume_one_time_prekey(session: AsyncSession, device_id: UUID) -> OneTimePreKey | None:
    """
    Atomically pick one unused OPK and mark consumed.
    Uses SELECT ... FOR UPDATE SKIP LOCKED to avoid races.
    """

    from sqlalchemy import text
    row = await session.execute(text("""
        SELECT id, key_id, public_key
        FROM one_time_prekeys
        WHERE device_id = :device_id AND consumed_at IS NULL
        ORDER BY created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    """), {"device_id": str(device_id)})
    r = row.first()
    if not r:
        return None

    await session.execute(
        text("UPDATE one_time_prekeys SET consumed_at = :ts WHERE id = :id"),
        {"ts": datetime.utcnow(), "id": str(r.id)}
    )
    # return a lightweight object-like dict
    opk = OneTimePreKey(id=r.id, device_id=device_id, key_id=r.key_id, public_key=r.public_key)
    return opk

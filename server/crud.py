from datetime import datetime
from uuid import UUID
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import User, Device, SignedPreKey, OneTimePreKey, Message

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
    nonce: str | None = None,
    ad_length: int | None = None,
    is_initial_message: bool = False,
    x3dh_header: dict | None = None,
):
    msg = Message(
        message_id=message_id,
        from_device_id=from_device_id,
        to_device_id=to_device_id,
        header=header,
        ciphertext=ciphertext,
        nonce=nonce,
        ad_length=ad_length,
        is_initial_message=is_initial_message,
        x3dh_header=x3dh_header,
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
    SQLite version (doesn't support FOR UPDATE SKIP LOCKED).
    """
    from sqlalchemy import update

    # Find first available one-time prekey
    res = await session.execute(
        select(OneTimePreKey)
        .where(OneTimePreKey.device_id == device_id, OneTimePreKey.consumed_at.is_(None))
        .order_by(OneTimePreKey.created_at.asc())
        .limit(1)
    )
    opk = res.scalar_one_or_none()

    if not opk:
        return None

    # Mark as consumed
    opk.consumed_at = datetime.utcnow()
    await session.flush()

    return opk


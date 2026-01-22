# Simple message storage for demo (without E2EE complexity)
from datetime import datetime
from uuid import UUID, uuid4
from sqlalchemy import select, String, DateTime, ForeignKey, Text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from models import Base

class SimpleMessage(Base):
    __tablename__ = "simple_messages"
    id: Mapped[uuid4] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    from_user_id: Mapped[uuid4] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), index=True)
    to_user_id: Mapped[uuid4] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), index=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

async def create_simple_message(session: AsyncSession, from_user_id: UUID, to_user_id: UUID, text: str):
    """Create a new simple message"""
    msg = SimpleMessage(
        from_user_id=from_user_id,
        to_user_id=to_user_id,
        text=text
    )
    session.add(msg)
    await session.commit()
    return msg

async def get_messages_between_users(session: AsyncSession, user1_id: UUID, user2_id: UUID):
    """Get all messages between two users"""
    result = await session.execute(
        select(SimpleMessage)
        .where(
            ((SimpleMessage.from_user_id == user1_id) & (SimpleMessage.to_user_id == user2_id)) |
            ((SimpleMessage.from_user_id == user2_id) & (SimpleMessage.to_user_id == user1_id))
        )
        .order_by(SimpleMessage.created_at)
    )
    return result.scalars().all()

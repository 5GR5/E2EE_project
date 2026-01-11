import uuid
from datetime import datetime
from sqlalchemy import (
    String, DateTime, Boolean, ForeignKey, Integer, JSON, Text, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

# user definitions
class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    devices: Mapped[list["Device"]] = relationship(back_populates="user", cascade="all, delete-orphan")

# device definitions (each user can have multiple devices)
class Device(Base):
    __tablename__ = "devices"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    device_name: Mapped[str] = mapped_column(String(64))
    identity_key_public: Mapped[str] = mapped_column(Text)  # base64 or hex
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="devices")
    signed_prekeys: Mapped[list["SignedPreKey"]] = relationship(back_populates="device", cascade="all, delete-orphan")
    one_time_prekeys: Mapped[list["OneTimePreKey"]] = relationship(back_populates="device", cascade="all, delete-orphan")

# signed prekey definitions
class SignedPreKey(Base):
    __tablename__ = "signed_prekeys"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id"), index=True)
    key_id: Mapped[int] = mapped_column(Integer, index=True)
    public_key: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    device: Mapped["Device"] = relationship(back_populates="signed_prekeys")

# one-time prekey definitions (each can be used only once)
class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id"), index=True)
    key_id: Mapped[int] = mapped_column(Integer, index=True)
    public_key: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)

    device: Mapped["Device"] = relationship(back_populates="one_time_prekeys")

Index("ix_otpk_device_consumed", OneTimePreKey.device_id, OneTimePreKey.consumed_at)

# message definitions
class Message(Base):
    __tablename__ = "messages"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[str] = mapped_column(String(128), index=True)  # from client, for dedup/acks
    from_device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id"), index=True)
    to_device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id"), index=True)
    header: Mapped[dict] = mapped_column(JSON)
    ciphertext: Mapped[str] = mapped_column(Text)
    server_ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    delivered_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    read_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

Index("ix_messages_to_device_ts", Message.to_device_id, Message.server_ts)

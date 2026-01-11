from pydantic import BaseModel, Field
from typing import List, Optional, Any
from uuid import UUID

class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

# JWT token output
class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class DeviceCreateIn(BaseModel):
    device_name: str
    identity_key_public: str

# Device output
class DeviceOut(BaseModel):
    id: UUID
    device_name: str

class SignedPreKeyIn(BaseModel):
    key_id: int
    public_key: str
    signature: str

class OneTimePreKeyIn(BaseModel):
    key_id: int
    public_key: str

# OTPK upload input
class KeysUploadIn(BaseModel):
    device_id: UUID
    signed_prekey: SignedPreKeyIn
    one_time_prekeys: List[OneTimePreKeyIn] = Field(default_factory=list)

# returned prekey bundle (for other users to fetch)
class PreKeyBundleOut(BaseModel):
    user_id: UUID
    device_id: UUID
    identity_key_public: str
    signed_prekey: SignedPreKeyIn
    one_time_prekey: Optional[OneTimePreKeyIn] = None  # can be null if depleted

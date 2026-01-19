from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

from .primitives import (
    x25519_pub_from_b64,
    ed25519_pub_from_b64,
    verify_ed25519,
    b64d,
)

@dataclass(frozen=True)
class SignedPreKeyPublic:
    key_id: int
    public_key_b64: str
    signature_b64: str

    def pubkey(self) -> x25519.X25519PublicKey:
        return x25519_pub_from_b64(self.public_key_b64)

    def pubkey_raw(self) -> bytes:
        return self.pubkey().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

@dataclass(frozen=True)
class OneTimePreKeyPublic:
    key_id: int
    public_key_b64: str

    def pubkey(self) -> x25519.X25519PublicKey:
        return x25519_pub_from_b64(self.public_key_b64)

@dataclass(frozen=True)
class PreKeyBundle:
    user_id: str
    device_id: str
    identity_key_public_b64: str           # X25519 IK (DH)
    identity_signing_public_b64: str       # Ed25519 IK (SIG)
    signed_prekey: SignedPreKeyPublic
    one_time_prekey: Optional[OneTimePreKeyPublic]

    def identity_dh_pub(self) -> x25519.X25519PublicKey:
        return x25519_pub_from_b64(self.identity_key_public_b64)

    def identity_sig_pub(self) -> ed25519.Ed25519PublicKey:
        return ed25519_pub_from_b64(self.identity_signing_public_b64)

def parse_bundle(d: Dict[str, Any]) -> PreKeyBundle:
    spk = d["signed_prekey"]
    otpk = d.get("one_time_prekey")
    return PreKeyBundle(
        user_id=str(d["user_id"]),
        device_id=str(d["device_id"]),
        identity_key_public_b64=d["identity_key_public"],
        identity_signing_public_b64=d["identity_signing_public"],
        signed_prekey=SignedPreKeyPublic(
            key_id=int(spk["key_id"]),
            public_key_b64=spk["public_key"],
            signature_b64=spk["signature"],
        ),
        one_time_prekey=(
            OneTimePreKeyPublic(key_id=int(otpk["key_id"]), public_key_b64=otpk["public_key"])
            if otpk else None
        ),
    )

def verify_bundle(bundle: PreKeyBundle) -> bool:
    """
    Verify SPK signature using identity signing public key.
    """
    sig_pub = bundle.identity_sig_pub()
    spk_raw = bundle.signed_prekey.pubkey_raw()
    return verify_ed25519(sig_pub, bundle.signed_prekey.signature_b64, spk_raw)

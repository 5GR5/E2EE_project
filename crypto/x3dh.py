"""
X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol.

This module implements the X3DH protocol as specified in Signal's X3DH spec:
https://signal.org/docs/specifications/x3dh/

The X3DH protocol establishes a shared secret between two parties (Alice and Bob)
using a combination of long-term identity keys and ephemeral keys.

Key derivation strictly follows:
- HKDF with SHA256
- Consistent salt (32 zero bytes)
- Consistent info label (b"X3DH")
- Consistent concatenation order of DH outputs
"""

from dataclasses import dataclass
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519

from .primitive import (
    b64e, b64d,
    x25519_pub_to_b64, x25519_pub_from_b64,
    dh, hkdf_sha256
)
from .keys import (
    x25519_priv_from_b64,
)


@dataclass
class InitialMessageHeader:
    """
    Header sent by Alice in her initial message to Bob.
    
    This header contains all information Bob needs to:
    1. Identify which of his keys to use
    2. Reconstruct the same shared secret as Alice
    3. Authenticate Alice's identity
    """
    sender_identity_dh_pub: str  # Alice's long-term DH public key (X25519)
    sender_ephemeral_pub: str     # Alice's ephemeral public key (X25519)
    receiver_signed_prekey_id: int  # Which SPK Bob used
    receiver_one_time_prekey_id: Optional[int]  # Which OPK Bob used (None if no OPK used)
    sender_device_id: str         # Alice's device identifier (for multi-device)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict."""
        return {
            "sender_identity_dh_pub": self.sender_identity_dh_pub,
            "sender_ephemeral_pub": self.sender_ephemeral_pub,
            "receiver_signed_prekey_id": self.receiver_signed_prekey_id,
            "receiver_one_time_prekey_id": self.receiver_one_time_prekey_id,
            "sender_device_id": self.sender_device_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "InitialMessageHeader":
        """Deserialize from JSON-compatible dict."""
        return InitialMessageHeader(
            sender_identity_dh_pub=d["sender_identity_dh_pub"],
            sender_ephemeral_pub=d["sender_ephemeral_pub"],
            receiver_signed_prekey_id=d["receiver_signed_prekey_id"],
            receiver_one_time_prekey_id=d["receiver_one_time_prekey_id"],
            sender_device_id=d["sender_device_id"],
        )


def _derive_shared_secret(dh1: bytes, dh2: bytes, dh3: bytes, dh4: Optional[bytes] = None) -> bytes:
    """
    Derives the final shared secret from X3DH DH outputs.
    
    Strict key derivation rules:
    - KDF input: concatenation of DH outputs in fixed order
    - Salt: 32 zero bytes (standard for X3DH)
    - Info: b"X3DH" (stable label)
    - Output: 32 bytes (256 bits)
    
    Args:
        dh1: Output of alice_IK * bob_SPK (required)
        dh2: Output of alice_EK * bob_IK (required)
        dh3: Output of alice_EK * bob_SPK (required)
        dh4: Output of alice_EK * bob_OPK (optional, only if OPK used)
        
    Returns:
        32-byte shared secret
    """
    # Concatenate DH outputs in strict order
    if dh4 is not None:
        # With OPK
        kdf_input = dh1 + dh2 + dh3 + dh4
    else:
        # Without OPK
        kdf_input = dh1 + dh2 + dh3

    # Standard X3DH parameters
    salt = b"\x00" * 32  # 32 zero bytes (standard for X3DH)
    info = b"X3DH"      # Stable label

    # Derive 32-byte key
    shared_secret = hkdf_sha256(
        ikm=kdf_input,
        salt=salt,
        info=info,
        length=32
    )
    return shared_secret


def alice_initiate(
    alice_identity_dh_priv_b64: str,
    alice_ephemeral_priv_b64: str,
    alice_identity_dh_pub_b64: str,
    alice_ephemeral_pub_b64: str,
    alice_device_id: str,
    bob_identity_dh_pub_b64: str,
    bob_signed_prekey_pub_b64: str,
    bob_signed_prekey_id: int,
    bob_one_time_prekey_pub_b64: Optional[str] = None,
    bob_one_time_prekey_id: Optional[int] = None,
) -> Tuple[InitialMessageHeader, bytes]:
    """
    Alice initiates the X3DH key agreement.
    
    Alice performs 3 or 4 Diffie-Hellman operations:
    1. alice_IK * bob_SPK
    2. alice_EK * bob_IK
    3. alice_EK * bob_SPK
    4. alice_EK * bob_OPK (optional, if Bob provided an OPK)
    
    Args:
        alice_identity_dh_priv_b64: Alice's identity DH private key (base64)
        alice_ephemeral_priv_b64: Alice's ephemeral private key (base64)
        alice_identity_dh_pub_b64: Alice's identity DH public key (base64)
        alice_ephemeral_pub_b64: Alice's ephemeral public key (base64)
        alice_device_id: Alice's device identifier
        bob_identity_dh_pub_b64: Bob's identity DH public key (base64)
        bob_signed_prekey_pub_b64: Bob's current signed prekey public (base64)
        bob_signed_prekey_id: ID of Bob's SPK
        bob_one_time_prekey_pub_b64: Bob's OPK public (base64, optional)
        bob_one_time_prekey_id: ID of Bob's OPK (optional)
        
    Returns:
        Tuple of (InitialMessageHeader, 32-byte shared secret)
        
    Raises:
        ValueError: If critical keys are missing
    """
    # Reconstruct keys from base64
    alice_ik_priv = x25519_priv_from_b64(alice_identity_dh_priv_b64)
    alice_ek_priv = x25519_priv_from_b64(alice_ephemeral_priv_b64)
    
    bob_ik_pub = x25519_pub_from_b64(bob_identity_dh_pub_b64)
    bob_spk_pub = x25519_pub_from_b64(bob_signed_prekey_pub_b64)
    
    # DH1: alice_IK * bob_SPK
    dh1 = dh(alice_ik_priv, bob_spk_pub)
    
    # DH2: alice_EK * bob_IK
    dh2 = dh(alice_ek_priv, bob_ik_pub)
    
    # DH3: alice_EK * bob_SPK
    dh3 = dh(alice_ek_priv, bob_spk_pub)
    
    # DH4 (optional): alice_EK * bob_OPK
    dh4 = None
    if bob_one_time_prekey_pub_b64 is not None:
        bob_opk_pub = x25519_pub_from_b64(bob_one_time_prekey_pub_b64)
        dh4 = dh(alice_ek_priv, bob_opk_pub)
    
    # Derive the shared secret with strict rules
    shared_secret = _derive_shared_secret(dh1, dh2, dh3, dh4)
    
    # Build initial message header
    header = InitialMessageHeader(
        sender_identity_dh_pub=alice_identity_dh_pub_b64,
        sender_ephemeral_pub=alice_ephemeral_pub_b64,
        receiver_signed_prekey_id=bob_signed_prekey_id,
        receiver_one_time_prekey_id=bob_one_time_prekey_id,
        sender_device_id=alice_device_id,
    )
    
    return header, shared_secret


def bob_respond(
    bob_identity_dh_priv_b64: str,
    bob_identity_dh_pub_b64: str,
    bob_signed_prekey_priv_b64: str,
    bob_signed_prekey_pub_b64: str,
    alice_identity_dh_pub_b64: str,
    alice_ephemeral_pub_b64: str,
    bob_one_time_prekey_priv_b64: Optional[str] = None,
) -> bytes:
    """
    Bob responds to Alice's X3DH initiation.
    
    Bob uses Alice's header to identify which keys she used, then performs
    the same 3 or 4 DH operations (in different order due to commutativity).
    
    Args:
        bob_identity_dh_priv_b64: Bob's identity DH private key (base64)
        bob_identity_dh_pub_b64: Bob's identity DH public key (base64)
        bob_signed_prekey_priv_b64: Bob's SPK private key (base64)
        bob_signed_prekey_pub_b64: Bob's SPK public key (base64)
        alice_identity_dh_pub_b64: Alice's identity DH public key (base64)
        alice_ephemeral_pub_b64: Alice's ephemeral public key (base64)
        bob_one_time_prekey_priv_b64: Bob's OPK private key (base64, optional)
        
    Returns:
        32-byte shared secret (identical to what Alice derived)
        
    Raises:
        ValueError: If critical keys are missing
    """
    # Reconstruct keys from base64
    bob_ik_priv = x25519_priv_from_b64(bob_identity_dh_priv_b64)
    bob_spk_priv = x25519_priv_from_b64(bob_signed_prekey_priv_b64)
    
    alice_ik_pub = x25519_pub_from_b64(alice_identity_dh_pub_b64)
    alice_ek_pub = x25519_pub_from_b64(alice_ephemeral_pub_b64)
    
    # DH1: bob_SPK * alice_IK (same as alice_IK * bob_SPK due to commutativity)
    dh1 = dh(bob_spk_priv, alice_ik_pub)
    
    # DH2: bob_IK * alice_EK (same as alice_EK * bob_IK)
    dh2 = dh(bob_ik_priv, alice_ek_pub)
    
    # DH3: bob_SPK * alice_EK (same as alice_EK * bob_SPK)
    dh3 = dh(bob_spk_priv, alice_ek_pub)
    
    # DH4 (optional): bob_OPK * alice_EK
    dh4 = None
    if bob_one_time_prekey_priv_b64 is not None:
        bob_opk_priv = x25519_priv_from_b64(bob_one_time_prekey_priv_b64)
        dh4 = dh(bob_opk_priv, alice_ek_pub)
    
    # Derive the shared secret with same strict rules as Alice
    shared_secret = _derive_shared_secret(dh1, dh2, dh3, dh4)
    
    return shared_secret

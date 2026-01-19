"""Cryptographic primitives and protocols for E2E encryption."""

from .primitive import (
    b64e,
    b64d,
    rand_nonce,
    x25519_keypair,
    ed25519_keypair,
    x25519_pub_to_b64,
    x25519_pub_from_b64,
    x25519_priv_to_b64,
    x25519_priv_from_b64,
    ed25519_pub_to_b64,
    ed25519_pub_from_b64,
    dh,
    hkdf_sha256,
    aead_encrypt,
    aead_decrypt,
    sign_ed25519,
    verify_ed25519,
)

from .x3dh import (
    InitialMessageHeader,
    alice_initiate,
    bob_respond,
)

__all__ = [
    # Primitives
    "b64e",
    "b64d",
    "rand_nonce",
    "x25519_keypair",
    "ed25519_keypair",
    "x25519_pub_to_b64",
    "x25519_pub_from_b64",
    "x25519_priv_to_b64",
    "x25519_priv_from_b64",
    "ed25519_pub_to_b64",
    "ed25519_pub_from_b64",
    "dh",
    "hkdf_sha256",
    "aead_encrypt",
    "aead_decrypt",
    "sign_ed25519",
    "verify_ed25519",
    # X3DH
    "InitialMessageHeader",
    "alice_initiate",
    "bob_respond",
]

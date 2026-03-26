"""
Cryptographic primitives for the Signal Protocol implementation.

Provides low-level building blocks:
- Base64 encoding/decoding utilities
- X25519 key generation and Diffie-Hellman exchange
- Ed25519 signing and verification
- HKDF-SHA256 key derivation
- AES-GCM authenticated encryption (AEAD)
"""

import base64
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    """Encode bytes to URL-safe base64 string."""
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(s.encode("utf-8"))

def rand_nonce(n: int = 12) -> bytes:
    """Generate n cryptographically secure random bytes (default 12 for AES-GCM)."""
    return os.urandom(n)

def x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate a new X25519 key pair for Diffie-Hellman key exchange."""
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()

def ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 key pair for digital signatures."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def x25519_pub_to_b64(pub: x25519.X25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(raw)

def x25519_pub_from_b64(s: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b64d(s))

def ed25519_pub_to_b64(pub: ed25519.Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(raw)

def ed25519_pub_from_b64(s: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(s))

def dh(priv: x25519.X25519PrivateKey, pub: x25519.X25519PublicKey) -> bytes:
    """Perform X25519 Diffie-Hellman key exchange, returning 32-byte shared secret."""
    return priv.exchange(pub)

def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    """Derive key material using HKDF with SHA-256."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def aead_encrypt(key32: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = rand_nonce(12)
    ct = AESGCM(key32).encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key32: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises InvalidTag if authentication fails."""
    return AESGCM(key32).decrypt(nonce, ciphertext, aad)

def sign_ed25519(priv: ed25519.Ed25519PrivateKey, msg: bytes) -> str:
    """Sign a message with Ed25519, returning base64-encoded signature."""
    return b64e(priv.sign(msg))

def verify_ed25519(pub: ed25519.Ed25519PublicKey, sig_b64: str, msg: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        pub.verify(b64d(sig_b64), msg)
        return True
    except Exception:
        return False

import base64
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def rand_nonce(n: int = 12) -> bytes:
    return os.urandom(n)

def x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()

def ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
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
    return priv.exchange(pub)

def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)

def aead_encrypt(key32: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = rand_nonce(12)
    ct = AESGCM(key32).encrypt(nonce, plaintext, aad)
    return nonce, ct

def aead_decrypt(key32: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key32).decrypt(nonce, ciphertext, aad)

def sign_ed25519(priv: ed25519.Ed25519PrivateKey, msg: bytes) -> str:
    return b64e(priv.sign(msg))

def verify_ed25519(pub: ed25519.Ed25519PublicKey, sig_b64: str, msg: bytes) -> bool:
    try:
        pub.verify(b64d(sig_b64), msg)
        return True
    except Exception:
        return False

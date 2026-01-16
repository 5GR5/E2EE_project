from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

from .primitives import (
    b64e, b64d,
    x25519_keypair, ed25519_keypair,
    x25519_pub_to_b64, ed25519_pub_to_b64,
    sign_ed25519
)
from .keystore import JsonKeyStore


def x25519_priv_to_b64(priv: x25519.X25519PrivateKey) -> str:
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return b64e(raw)

def x25519_priv_from_b64(s: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(b64d(s))

def ed25519_priv_to_b64(priv: ed25519.Ed25519PrivateKey) -> str:
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return b64e(raw)

def ed25519_priv_from_b64(s: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(s))


def create_or_load_device(ks: JsonKeyStore, device_id: str, device_name: str) -> Dict:
    """
    Creates a device with:
      - Identity DH keypair (X25519)
      - Identity Signing keypair (Ed25519)
    Stores them in JSON once.
    """
    existing = ks.get_device(device_id)
    if existing:
        return existing

    ik_dh_priv, ik_dh_pub = x25519_keypair()
    ik_sig_priv, ik_sig_pub = ed25519_keypair()

    blob = {
        "device_id": device_id,
        "device_name": device_name,
        "identity_dh": {
            "priv": x25519_priv_to_b64(ik_dh_priv),
            "pub": x25519_pub_to_b64(ik_dh_pub),
        },
        "identity_sig": {
            "priv": ed25519_priv_to_b64(ik_sig_priv),
            "pub": ed25519_pub_to_b64(ik_sig_pub),
        },
        "signed_prekey": None,          # will be set by rotate_signed_prekey()
        "one_time_prekeys": {},         # key_id -> {"priv":..,"pub":..}
        "sessions": {}                  # later for Double Ratchet states
    }
    ks.put_device(device_id, blob)
    return blob


def rotate_signed_prekey(ks: JsonKeyStore, device_id: str, spk_id: int) -> Dict:
    """
    Generates new Signed PreKey (X25519), signs its public key bytes using identity_sig_priv.
    """
    device = ks.get_device(device_id)
    if not device:
        raise ValueError("Device not found in keystore")

    spk_priv, spk_pub = x25519_keypair()

    # Sign SPK pub bytes using Ed25519 identity signing key
    sig_priv = ed25519_priv_from_b64(device["identity_sig"]["priv"])
    spk_pub_raw = spk_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signature_b64 = sign_ed25519(sig_priv, spk_pub_raw)

    device["signed_prekey"] = {
        "key_id": spk_id,
        "priv": x25519_priv_to_b64(spk_priv),
        "pub": x25519_pub_to_b64(spk_pub),
        "signature": signature_b64,
    }
    ks.put_device(device_id, device)
    return device["signed_prekey"]


def generate_one_time_prekeys(ks: JsonKeyStore, device_id: str, start_id: int, count: int) -> List[Dict]:
    """
    Generates OPKs and stores them locally. Returns the public list to upload to server.
    """
    device = ks.get_device(device_id)
    if not device:
        raise ValueError("Device not found in keystore")

    upload_list = []
    for i in range(start_id, start_id + count):
        priv, pub = x25519_keypair()
        device["one_time_prekeys"][str(i)] = {
            "priv": x25519_priv_to_b64(priv),
            "pub": x25519_pub_to_b64(pub),
        }
        upload_list.append({"key_id": i, "public_key": device["one_time_prekeys"][str(i)]["pub"]})

    ks.put_device(device_id, device)
    return upload_list


def build_keys_upload_payload(ks: JsonKeyStore, device_id: str) -> Dict:
    """
    Payload for POST /keys/upload (multi-device):
    - identity_dh_pub should already be sent when creating device (your server /devices endpoint)
    - include identity_sig_pub so others can verify SPK signature
    - include signed prekey + signature
    - include opks
    """
    device = ks.get_device(device_id)
    if not device:
        raise ValueError("Device not found in keystore")

    if not device["signed_prekey"]:
        raise ValueError("No signed prekey. Call rotate_signed_prekey first.")

    otpks = []
    for k, v in device["one_time_prekeys"].items():
        otpks.append({"key_id": int(k), "public_key": v["pub"]})

    return {
        "device_id": device_id,
        "identity_key_public": device["identity_dh"]["pub"],          # X25519 identity DH pub
        "identity_signing_public": device["identity_sig"]["pub"],     # Ed25519 identity signing pub (NEW)
        "signed_prekey": {
            "key_id": device["signed_prekey"]["key_id"],
            "public_key": device["signed_prekey"]["pub"],
            "signature": device["signed_prekey"]["signature"],
        },
        "one_time_prekeys": otpks,
    }

"""
Double Ratchet Protocol Implementation

Implements the Double Ratchet algorithm as used by Signal and other OMEMO protocols.

Key features:
- DH ratchet: Updates root key on each message from sender
- Chain ratchet: Derives per-message keys from chain key
- Out-of-order message support: Stores skipped message keys
- JSON persistence: State can be serialized/deserialized
"""

import json
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from .primitive import (
    b64e, b64d,
    x25519_keypair,
    x25519_pub_to_b64, x25519_pub_from_b64,
    dh, hkdf_sha256,
    aead_encrypt, aead_decrypt,
)
from .keys import (
    x25519_priv_to_b64, x25519_priv_from_b64,
)


# ============================================
# STEP 1: Message Header + AAD
# ============================================

@dataclass
class MessageHeader:
    """
    Header carried by every Double Ratchet message.
    
    Attributes:
        dh_pub: Sender's current ratchet public key (base64)
        pn: Previous message number (length of previous sending chain)
        n: Current message number in this chain
    """
    dh_pub: str  # base64 X25519 public key
    pn: int      # Previous message count
    n: int       # Current message count

    def to_dict(self) -> dict:
        """Serialize to dict for canonical JSON."""
        return {
            "dh_pub": self.dh_pub,
            "pn": self.pn,
            "n": self.n,
        }

    @staticmethod
    def from_dict(d: dict) -> "MessageHeader":
        """Deserialize from dict."""
        return MessageHeader(
            dh_pub=d["dh_pub"],
            pn=d["pn"],
            n=d["n"],
        )


def _canonical_json(obj: dict) -> str:
    """
    Serialize dict to canonical JSON:
    - Sorted keys
    - No whitespace
    - No trailing newline
    """
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)


def build_aad(header: MessageHeader, sender_device_id: str, receiver_device_id: str) -> bytes:
    """
    Build deterministic Additional Authenticated Data (AAD).
    
    Format:
        canonical_json(header) + b"|" + sender_device_id + b"|" + receiver_device_id + b"|v1"
    
    Args:
        header: MessageHeader with dh_pub, pn, n
        sender_device_id: Sender's device identifier
        receiver_device_id: Receiver's device identifier
        
    Returns:
        AAD bytes for AEAD encryption
    """
    header_json = _canonical_json(header.to_dict())
    aad = (
        header_json.encode('utf-8') +
        b"|" +
        sender_device_id.encode('utf-8') +
        b"|" +
        receiver_device_id.encode('utf-8') +
        b"|v1"
    )
    return aad


# ============================================
# STEP 2: KDFs (Root + Chain)
# ============================================

def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """
    Root Key Derivation (DH Ratchet).
    
    Combines current root key with DH output to derive:
    - New root key
    - New chain key
    
    Uses HKDF-SHA256 with:
    - Info: b"DRatchet_RK"
    - Salt: current RK
    - Output: 64 bytes (32 for RK + 32 for CK)
    
    Args:
        rk: Current root key (32 bytes)
        dh_out: DH(our_ratchet_priv, their_ratchet_pub) (32 bytes)
        
    Returns:
        Tuple of (new_rk, new_ck), each 32 bytes
    """
    derived = hkdf_sha256(
        ikm=dh_out,
        salt=rk,
        info=b"DRatchet_RK",
        length=64,
    )
    return derived[:32], derived[32:64]


def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """
    Chain Key Derivation (Symmetric Ratchet).
    
    Advances chain key and derives message key.
    
    Uses HKDF-SHA256 with:
    - Info: b"DRatchet_CK"
    - Salt: None
    - Output: 64 bytes (32 for new CK + 32 for MK)
    
    Args:
        ck: Current chain key (32 bytes)
        
    Returns:
        Tuple of (new_ck, mk), each 32 bytes
    """
    derived = hkdf_sha256(
        ikm=ck,
        salt=None,
        info=b"DRatchet_CK",
        length=64,
    )
    return derived[:32], derived[32:64]


# ============================================
# STEP 3: DoubleRatchetState
# ============================================

@dataclass
class DoubleRatchetState:
    """
    State of a Double Ratchet session with one peer's device.
    
    This state is per (Alice's device, Bob's device) pair.
    Persists across multiple message exchanges.
    
    Attributes:
        rk: Root key (32 bytes)
        dhs_priv_b64: Our current ratchet private key (base64)
        dhs_pub_b64: Our current ratchet public key (base64)
        dhr_pub_b64: Their current ratchet public key (base64, may be None initially)
        cks_b64: Our sending chain key (base64, may be None)
        ckr_b64: Our receiving chain key (base64, may be None)
        ns: Message number for sending
        nr: Message number for receiving
        pn: Previous message count (for header.pn)
        skipped: Dict[(dhr_pub_b64, n)] -> mk_b64. Bounded cache for out-of-order messages.
    """
    rk_b64: str
    dhs_priv_b64: str
    dhs_pub_b64: str
    dhr_pub_b64: Optional[str]  # None until first message received
    cks_b64: Optional[str]  # None until initialized
    ckr_b64: Optional[str]  # None until DH ratchet
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: Dict[Tuple[str, int], str] = field(default_factory=dict)  # (dhr_pub_b64, n) -> mk_b64
    max_skipped: int = 1000  # Max entries in skipped dict

    def to_dict(self) -> dict:
        """Serialize state to JSON-compatible dict."""
        # Convert skipped dict keys (tuples) to strings for JSON
        skipped_json = {f"{k[0]}:{k[1]}": v for k, v in self.skipped.items()}
        
        return {
            "rk_b64": self.rk_b64,
            "dhs_priv_b64": self.dhs_priv_b64,
            "dhs_pub_b64": self.dhs_pub_b64,
            "dhr_pub_b64": self.dhr_pub_b64,
            "cks_b64": self.cks_b64,
            "ckr_b64": self.ckr_b64,
            "ns": self.ns,
            "nr": self.nr,
            "pn": self.pn,
            "skipped": skipped_json,
            "max_skipped": self.max_skipped,
        }

    @staticmethod
    def from_dict(d: dict) -> "DoubleRatchetState":
        """Deserialize state from JSON-compatible dict."""
        # Convert skipped dict keys back to tuples
        skipped_json = d.get("skipped", {})
        skipped = {}
        for k, v in skipped_json.items():
            parts = k.rsplit(':', 1)  # rsplit from right to handle base64 colons
            dhr_pub_b64 = parts[0]
            n = int(parts[1])
            skipped[(dhr_pub_b64, n)] = v
        
        return DoubleRatchetState(
            rk_b64=d["rk_b64"],
            dhs_priv_b64=d["dhs_priv_b64"],
            dhs_pub_b64=d["dhs_pub_b64"],
            dhr_pub_b64=d.get("dhr_pub_b64"),
            cks_b64=d.get("cks_b64"),
            ckr_b64=d.get("ckr_b64"),
            ns=d.get("ns", 0),
            nr=d.get("nr", 0),
            pn=d.get("pn", 0),
            skipped=skipped,
            max_skipped=d.get("max_skipped", 1000),
        )

    @staticmethod
    def init(root_key: bytes) -> "DoubleRatchetState":
        """
        Initialize a Double Ratchet state from X3DH shared secret.
        
        RK starts as the X3DH shared secret (32 bytes).
        CKs and CKr are None initially and will be derived via kdf_rk:
        - CKs: derived on first encrypt (lazily from RK via DH with peer's DH public)
        - CKr: derived on first decrypt (from peer's ephemeral DH public in header)
        
        Args:
            root_key: 32-byte shared secret from X3DH
            
        Returns:
            DoubleRatchetState ready for first message
        """
        dhs_priv, dhs_pub = x25519_keypair()
        
        return DoubleRatchetState(
            rk_b64=b64e(root_key),
            dhs_priv_b64=x25519_priv_to_b64(dhs_priv),
            dhs_pub_b64=x25519_pub_to_b64(dhs_pub),
            dhr_pub_b64=None,  # Not known until first message
            cks_b64=None,      # Derived on first encrypt
            ckr_b64=None,      # Derived on first decrypt
            ns=0,
            nr=0,
            pn=0,
            skipped={},
        )


# ============================================
# STEP 4: Encrypt
# ============================================

def encrypt(
    state: DoubleRatchetState,
    plaintext: str,
    sender_device_id: str,
    receiver_device_id: str,
) -> Tuple[MessageHeader, str]:
    """
    Encrypt a message using Double Ratchet.
    
    Algorithm:
    1. Derive (CKs_new, MK) from current CKs
    2. Build header with current DHs_pub, PN, Ns
    3. Compute AAD from header + device IDs
    4. AEAD encrypt plaintext using MK and AAD
    5. Increment Ns
    
    Args:
        state: DoubleRatchetState (modified in-place)
        plaintext: Message to encrypt (str)
        sender_device_id: Sender's device ID
        receiver_device_id: Receiver's device ID
        
    Returns:
        Tuple of (MessageHeader, ciphertext_b64)
    """
    # Step 1: Initialize CKs on first encrypt if needed (derive from RK)
    if state.cks_b64 is None:
        # First message - derive CKs from RK using a DH step
        # We use DH with an empty/zero DHr for initial derivation
        # (In practice, both parties do the same DH with their own ephemeral keys)
        rk_bytes = b64d(state.rk_b64)
        zero_dh = b'\x00' * 32  # Placeholder for no peer DH yet
        rk_new_bytes, cks_bytes = kdf_rk(rk_bytes, zero_dh)
        state.rk_b64 = b64e(rk_new_bytes)
        state.cks_b64 = b64e(cks_bytes)
    
    # Step 1b: Derive new sending chain key and message key
    cks_bytes = b64d(state.cks_b64)
    cks_new_bytes, mk_bytes = kdf_ck(cks_bytes)
    state.cks_b64 = b64e(cks_new_bytes)
    
    # Step 2: Build header with current state
    header = MessageHeader(
        dh_pub=state.dhs_pub_b64,
        pn=state.pn,
        n=state.ns,
    )
    
    # Step 3: Compute AAD
    aad = build_aad(header, sender_device_id, receiver_device_id)
    
    # Step 4: AEAD encrypt
    nonce, ciphertext = aead_encrypt(mk_bytes, plaintext.encode('utf-8'), aad)
    ciphertext_b64 = b64e(nonce + ciphertext)
    
    # Step 5: Increment message counter
    state.ns += 1
    
    return header, ciphertext_b64


# ============================================
# STEP 5: Decrypt with DH Ratchet + Skipped Keys
# ============================================

def decrypt(
    state: DoubleRatchetState,
    header: MessageHeader,
    ciphertext_b64: str,
    sender_device_id: str,
    receiver_device_id: str,
) -> str:
    """
    Decrypt a message using Double Ratchet.
    
    Handles:
    - In-order messages
    - Out-of-order messages (stores skipped keys)
    - DH ratchet steps (new ephemeral keys from sender)
    
    Algorithm:
    1. Check if (header.dh_pub, header.n) is in skipped → decrypt with stored MK
    2. If header.dh_pub != current DHr:
       a. Skip remaining keys in current CKr up to header.pn
       b. Perform DH ratchet: compute new RK, CKr, CKs
       c. Reset Ns and PN
    3. Skip keys in CKr up to header.n, store in skipped
    4. Derive (CKr_new, MK) for this message number
    5. AEAD decrypt with AAD
    6. Update Nr
    
    Args:
        state: DoubleRatchetState (modified in-place)
        header: MessageHeader from received message
        ciphertext_b64: Encrypted ciphertext (base64)
        sender_device_id: Sender's device ID
        receiver_device_id: Receiver's device ID
        
    Returns:
        Decrypted plaintext (str)
        
    Raises:
        ValueError: If decryption fails or state is invalid
    """
    # Step 1: Check skipped keys
    skipped_key = (header.dh_pub, header.n)
    if skipped_key in state.skipped:
        mk_b64 = state.skipped.pop(skipped_key)
        mk_bytes = b64d(mk_b64)
        
        # Decrypt with skipped key
        ciphertext_bytes = b64d(ciphertext_b64)
        nonce = ciphertext_bytes[:12]
        ciphertext = ciphertext_bytes[12:]
        aad = build_aad(header, sender_device_id, receiver_device_id)
        
        plaintext_bytes = aead_decrypt(mk_bytes, nonce, ciphertext, aad)
        return plaintext_bytes.decode('utf-8')
    
    # Step 2: DH ratchet step if needed (not on first message from sender)
    # On first message from Alice (when Bob's dhr_pub_b64 is None), Bob should NOT ratchet
    # Bob should just use the initial RK to derive CKr
    
    if state.ckr_b64 is None:
        # First message from this sender - initialize CKr
        # If this is the very first ratchet (state.dhr_pub_b64 is None), we haven't done any DH ratchet yet
        # On the first message, both parties should use symmetric initialization (same zero_dh)
        if state.dhr_pub_b64 is None:
            # First message ever - use zero_dh like the sender did
            rk_bytes = b64d(state.rk_b64)
            zero_dh = b'\x00' * 32
            rk_new_bytes, ckr_new_bytes = kdf_rk(rk_bytes, zero_dh)
            state.rk_b64 = b64e(rk_new_bytes)
            state.ckr_b64 = b64e(ckr_new_bytes)
        else:
            # We've seen messages before but not from this sender yet (new DH ratchet) - do DH
            dhs_priv = x25519_priv_from_b64(state.dhs_priv_b64)
            dhr_pub = x25519_pub_from_b64(header.dh_pub)
            dh_out = dh(dhs_priv, dhr_pub)
            rk_bytes = b64d(state.rk_b64)
            rk_new_bytes, ckr_new_bytes = kdf_rk(rk_bytes, dh_out)
            state.rk_b64 = b64e(rk_new_bytes)
            state.ckr_b64 = b64e(ckr_new_bytes)
        
        state.dhr_pub_b64 = header.dh_pub
        state.nr = 0
    
    # Now check if we need to ratchet (sender changed their DH key)
    elif header.dh_pub != state.dhr_pub_b64:
        # DH ratchet step - sender rotated their ephemeral key
        # Skip remaining keys in current CKr up to header.pn
        if state.ckr_b64 is not None:
            ckr_bytes = b64d(state.ckr_b64)
            for i in range(header.pn - state.nr):
                ckr_bytes, mk_bytes = kdf_ck(ckr_bytes)
                # Store skipped key
                if len(state.skipped) >= state.max_skipped:
                    # Remove oldest entry (FIFO)
                    oldest_key = next(iter(state.skipped))
                    del state.skipped[oldest_key]
                state.skipped[(state.dhr_pub_b64, state.nr + i)] = b64e(mk_bytes)
        
        # Perform two-step DH ratchet
        dhs_priv = x25519_priv_from_b64(state.dhs_priv_b64)
        dhr_pub = x25519_pub_from_b64(header.dh_pub)
        
        # Step 1: DH(our_current_DHs, their_new_DHr) → RK, CKr
        dh_out_1 = dh(dhs_priv, dhr_pub)
        rk_bytes = b64d(state.rk_b64)
        rk_new_bytes, ckr_new_bytes = kdf_rk(rk_bytes, dh_out_1)
        
        # Step 2: Generate new DHs keypair and DH(new_DHs, their_new_DHr) → RK, CKs
        dhs_priv_new, dhs_pub_new = x25519_keypair()
        dh_out_2 = dh(dhs_priv_new, dhr_pub)
        rk_new2_bytes, cks_new_bytes = kdf_rk(rk_new_bytes, dh_out_2)
        
        # Update state with both new CKr and CKs
        state.rk_b64 = b64e(rk_new2_bytes)
        state.dhs_priv_b64 = x25519_priv_to_b64(dhs_priv_new)
        state.dhs_pub_b64 = x25519_pub_to_b64(dhs_pub_new)
        state.dhr_pub_b64 = header.dh_pub
        state.ckr_b64 = b64e(ckr_new_bytes)
        state.cks_b64 = b64e(cks_new_bytes)
        state.nr = 0
        state.pn = state.ns
        state.ns = 0
    
    # Step 3: Skip keys in CKr up to header.n
    ckr_bytes = b64d(state.ckr_b64)
    for _ in range(header.n - state.nr):
        ckr_bytes, mk_bytes = kdf_ck(ckr_bytes)
        if len(state.skipped) >= state.max_skipped:
            oldest_key = next(iter(state.skipped))
            del state.skipped[oldest_key]
        state.skipped[(header.dh_pub, state.nr + _)] = b64e(mk_bytes)
    
    # Step 4: Derive MK for this message
    ckr_bytes, mk_bytes = kdf_ck(ckr_bytes)
    state.ckr_b64 = b64e(ckr_bytes)
    
    # Step 5: Decrypt
    ciphertext_bytes = b64d(ciphertext_b64)
    nonce = ciphertext_bytes[:12]
    ciphertext = ciphertext_bytes[12:]
    aad = build_aad(header, sender_device_id, receiver_device_id)
    
    plaintext_bytes = aead_decrypt(mk_bytes, nonce, ciphertext, aad)
    
    # Step 6: Update Nr
    state.nr = header.n + 1
    
    return plaintext_bytes.decode('utf-8')

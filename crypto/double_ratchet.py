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

def _dh_ratchet_step(state: DoubleRatchetState, new_dhr_pub_b64: str) -> None:
    """
    Perform the full DH ratchet step when a new DHr is received.

    1) RK, CKr = kdf_rk(RK, DH(DHs_priv, new_DHr))
    2) Generate new DHs
    3) RK, CKs = kdf_rk(RK, DH(new_DHs_priv, new_DHr))
    4) Reset counters: PN = old Ns, Ns = 0, Nr = 0
    """
    dhs_priv = x25519_priv_from_b64(state.dhs_priv_b64)
    new_dhr_pub = x25519_pub_from_b64(new_dhr_pub_b64)

    rk = b64d(state.rk_b64)

    # Step 1: receiving chain
    dh_out_1 = dh(dhs_priv, new_dhr_pub)
    rk_1, ckr = kdf_rk(rk, dh_out_1)

    # Step 2: rotate our sending ratchet key
    dhs_priv_new, dhs_pub_new = x25519_keypair()

    # Step 3: sending chain
    dh_out_2 = dh(dhs_priv_new, new_dhr_pub)
    rk_2, cks = kdf_rk(rk_1, dh_out_2)

    # Commit state
    state.rk_b64 = b64e(rk_2)
    state.ckr_b64 = b64e(ckr)
    state.cks_b64 = b64e(cks)

    state.dhr_pub_b64 = new_dhr_pub_b64
    state.dhs_priv_b64 = x25519_priv_to_b64(dhs_priv_new)
    state.dhs_pub_b64 = x25519_pub_to_b64(dhs_pub_new)

    state.pn = state.ns
    state.ns = 0
    state.nr = 0



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
    def init_initiator(shared_secret: bytes, bob_spk_pub_b64: str) -> "DoubleRatchetState":
        """
        Initiator (Alice) initialization.

        - RK starts as X3DH shared secret (SK)
        - Alice generates a fresh DHs ratchet keypair
        - Alice sets DHr to Bob's Signed PreKey public (SPK pub)
        - Alice derives (RK, CKs) = kdf_rk(RK, DH(DHs_priv, DHr_pub))

        CKr is None until Alice receives Bob's first reply.
        """
        dhs_priv, dhs_pub = x25519_keypair()

        rk = shared_secret
        dhr_pub = x25519_pub_from_b64(bob_spk_pub_b64)
        dh_out = dh(dhs_priv, dhr_pub)
        rk_new, cks = kdf_rk(rk, dh_out)

        return DoubleRatchetState(
            rk_b64=b64e(rk_new),
            dhs_priv_b64=x25519_priv_to_b64(dhs_priv),
            dhs_pub_b64=x25519_pub_to_b64(dhs_pub),
            dhr_pub_b64=bob_spk_pub_b64,      # Bob's current ratchet pub
            cks_b64=b64e(cks),                # ready to encrypt immediately
            ckr_b64=None,
            ns=0,
            nr=0,
            pn=0,
            skipped={},
        )

    @staticmethod
    def init_responder(shared_secret: bytes, bob_spk_priv_b64: str, bob_spk_pub_b64: str) -> "DoubleRatchetState":
        """
        Responder (Bob) initialization.

        - RK starts as X3DH shared secret (SK)
        - Bob sets DHs to his Signed PreKey (SPK) keypair (acts as initial ratchet key)
        - DHr is unknown until first message arrives (Alice's DHs pub)
        - CKs/CKr derived when messages arrive / when Bob sends after receiving.
        """
        return DoubleRatchetState(
            rk_b64=b64e(shared_secret),
            dhs_priv_b64=bob_spk_priv_b64,     # IMPORTANT: use SPK as initial DHs
            dhs_pub_b64=bob_spk_pub_b64,
            dhr_pub_b64=None,
            cks_b64=None,
            ckr_b64=None,
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

    # If CKs is not initialized yet, we must have DHr already (we can only send after receiving at least one msg),
    # OR we are the initiator (who will already have CKs from init_initiator()).
    if state.cks_b64 is None:
        if state.dhr_pub_b64 is None:
            raise ValueError("Cannot encrypt: no CKs and no DHr. Did you initialize as initiator?")
        # We have DHr (peer ratchet pub) but no sending chain yet → do a DH ratchet step to create CKs.
        _dh_ratchet_step(state, state.dhr_pub_b64)

    # Derive new sending chain key + message key
    cks_bytes = b64d(state.cks_b64)
    cks_new_bytes, mk_bytes = kdf_ck(cks_bytes)
    state.cks_b64 = b64e(cks_new_bytes)

    header = MessageHeader(
        dh_pub=state.dhs_pub_b64,
        pn=state.pn,
        n=state.ns,
    )

    aad = build_aad(header, sender_device_id, receiver_device_id)

    nonce, ciphertext = aead_encrypt(mk_bytes, plaintext.encode("utf-8"), aad)
    ciphertext_b64 = b64e(nonce + ciphertext)

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
        # First message we are decrypting in this session.
        # We must set DHr from header and derive CKr using DH(DHs_priv, DHr_pub).
        # For responder-init, DHs_priv should be Bob's SPK priv.
        if state.dhr_pub_b64 is None:
            state.dhr_pub_b64 = header.dh_pub

        dhs_priv = x25519_priv_from_b64(state.dhs_priv_b64)
        dhr_pub = x25519_pub_from_b64(state.dhr_pub_b64)

        rk_bytes = b64d(state.rk_b64)
        dh_out = dh(dhs_priv, dhr_pub)
        rk_new, ckr = kdf_rk(rk_bytes, dh_out)

        state.rk_b64 = b64e(rk_new)
        state.ckr_b64 = b64e(ckr)
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
        
        # Perform full DH ratchet (updates RK, CKr, CKs, rotates DHs, resets counters)
        _dh_ratchet_step(state, header.dh_pub)

        if header.n < state.nr:
            raise ValueError("Replay/old message detected: header.n < current Nr")

        MAX_SKIP = 2000
        if header.n - state.nr > MAX_SKIP:
            raise ValueError("Too many skipped messages; possible DoS")

    
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



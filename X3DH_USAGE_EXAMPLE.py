"""
X3DH Usage Example

Quick reference for how to use X3DH in your application.
"""

from crypto.primitive import (
    x25519_keypair,
    x25519_pub_to_b64,
)
from crypto.keys import (
    x25519_priv_to_b64,
)
from crypto.x3dh import alice_initiate, bob_respond, InitialMessageHeader


# ========================================
# SETUP: Generate all keys
# ========================================

# Alice generates identity & ephemeral keys
alice_ik_priv, alice_ik_pub = x25519_keypair()
alice_ek_priv, alice_ek_pub = x25519_keypair()

# Bob generates identity, signed prekey, and optional one-time prekey
bob_ik_priv, bob_ik_pub = x25519_keypair()
bob_spk_priv, bob_spk_pub = x25519_keypair()
bob_opk_priv, bob_opk_pub = x25519_keypair()

# Convert to base64 for storage/transmission
alice_ik_priv_b64 = x25519_priv_to_b64(alice_ik_priv)
alice_ik_pub_b64 = x25519_pub_to_b64(alice_ik_pub)
alice_ek_priv_b64 = x25519_priv_to_b64(alice_ek_priv)
alice_ek_pub_b64 = x25519_pub_to_b64(alice_ek_pub)

bob_ik_pub_b64 = x25519_pub_to_b64(bob_ik_pub)
bob_spk_priv_b64 = x25519_priv_to_b64(bob_spk_priv)
bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)
bob_opk_priv_b64 = x25519_priv_to_b64(bob_opk_priv)
bob_opk_pub_b64 = x25519_pub_to_b64(bob_opk_pub)


# ========================================
# ALICE INITIATES SESSION
# ========================================

header, alice_shared_secret = alice_initiate(
    # Alice's keys
    alice_identity_dh_priv_b64=alice_ik_priv_b64,
    alice_identity_dh_pub_b64=alice_ik_pub_b64,
    alice_ephemeral_priv_b64=alice_ek_priv_b64,
    alice_ephemeral_pub_b64=alice_ek_pub_b64,
    alice_device_id="alice-phone",
    
    # Bob's keys (fetched from server)
    bob_identity_dh_pub_b64=bob_ik_pub_b64,
    bob_signed_prekey_pub_b64=bob_spk_pub_b64,
    bob_signed_prekey_id=1,
    bob_one_time_prekey_pub_b64=bob_opk_pub_b64,
    bob_one_time_prekey_id=42,
)

# Serialize header to send with initial message
initial_message_dict = {
    "header": header.to_dict(),
    "ciphertext": "<encrypted with alice_shared_secret>",
}

print(f"Alice shared secret: {alice_shared_secret.hex()}")
print(f"Header: {initial_message_dict['header']}")


# ========================================
# BOB RECEIVES MESSAGE & DERIVES SAME SECRET
# ========================================

# Bob receives the header from Alice
alice_header = InitialMessageHeader.from_dict(initial_message_dict["header"])

# Bob looks up Alice's identity key and ephemeral key from header
alice_ik_pub_from_header = alice_header.sender_identity_dh_pub
alice_ek_pub_from_header = alice_header.sender_ephemeral_pub

# Bob retrieves his own keys based on what Alice specified in header
spk_id_to_use = alice_header.receiver_signed_prekey_id
opk_id_to_use = alice_header.receiver_one_time_prekey_id

# Bob responds
bob_shared_secret = bob_respond(
    # Bob's keys
    bob_identity_dh_priv_b64=x25519_priv_to_b64(bob_ik_priv),
    bob_identity_dh_pub_b64=bob_ik_pub_b64,
    bob_signed_prekey_priv_b64=bob_spk_priv_b64,
    bob_signed_prekey_pub_b64=bob_spk_pub_b64,
    
    # Alice's keys (from header)
    alice_identity_dh_pub_b64=alice_ik_pub_from_header,
    alice_ephemeral_pub_b64=alice_ek_pub_from_header,
    
    # Optional OPK
    bob_one_time_prekey_priv_b64=bob_opk_priv_b64 if opk_id_to_use else None,
)

print(f"Bob shared secret: {bob_shared_secret.hex()}")

# ========================================
# VERIFY: Secrets Match
# ========================================

assert alice_shared_secret == bob_shared_secret, "Secrets don't match!"
print("✓ Alice and Bob derived the same shared secret")

# Both can now use this as the initial root key for Double Ratchet
print(f"Root key for Double Ratchet: {alice_shared_secret.hex()}")

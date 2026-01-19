"""
Complete End-to-End Example: X3DH + Double Ratchet

Demonstrates a full secure conversation:
1. X3DH key agreement (establishes initial shared secret)
2. Double Ratchet initialization (sets up message encryption)
3. Bidirectional encrypted messaging
"""

from crypto.x3dh import alice_initiate, bob_respond
from crypto.double_ratchet import DoubleRatchetState, encrypt, decrypt


# ========================================
# SETUP PHASE: X3DH Key Agreement
# ========================================

print("=" * 60)
print("SETUP: X3DH Key Agreement")
print("=" * 60)

# (Assume Bob's keys are fetched from server/key directory)
# In reality, these would be stored on the server

from crypto.primitive import x25519_keypair
from crypto.keys import x25519_priv_to_b64, x25519_pub_to_b64

# Alice's keys
alice_ik_priv, alice_ik_pub = x25519_keypair()
alice_ek_priv, alice_ek_pub = x25519_keypair()

# Bob's keys
bob_ik_priv, bob_ik_pub = x25519_keypair()
bob_spk_priv, bob_spk_pub = x25519_keypair()
bob_opk_priv, bob_opk_pub = x25519_keypair()

# Perform X3DH
x3dh_header, alice_shared_secret = alice_initiate(
    alice_identity_dh_priv_b64=x25519_priv_to_b64(alice_ik_priv),
    alice_ephemeral_priv_b64=x25519_priv_to_b64(alice_ek_priv),
    alice_identity_dh_pub_b64=x25519_pub_to_b64(alice_ik_pub),
    alice_ephemeral_pub_b64=x25519_pub_to_b64(alice_ek_pub),
    alice_device_id="alice-phone",
    bob_identity_dh_pub_b64=x25519_pub_to_b64(bob_ik_pub),
    bob_signed_prekey_pub_b64=x25519_pub_to_b64(bob_spk_pub),
    bob_signed_prekey_id=1,
    bob_one_time_prekey_pub_b64=x25519_pub_to_b64(bob_opk_pub),
    bob_one_time_prekey_id=42,
)

# Bob computes the same shared secret
bob_shared_secret = bob_respond(
    bob_identity_dh_priv_b64=x25519_priv_to_b64(bob_ik_priv),
    bob_identity_dh_pub_b64=x25519_pub_to_b64(bob_ik_pub),
    bob_signed_prekey_priv_b64=x25519_priv_to_b64(bob_spk_priv),
    bob_signed_prekey_pub_b64=x25519_pub_to_b64(bob_spk_pub),
    alice_identity_dh_pub_b64=x3dh_header.sender_identity_dh_pub,
    alice_ephemeral_pub_b64=x3dh_header.sender_ephemeral_pub,
    bob_one_time_prekey_priv_b64=x25519_priv_to_b64(bob_opk_priv),
)

assert alice_shared_secret == bob_shared_secret
print(f"✓ X3DH agreement successful")
print(f"  Root key: {alice_shared_secret.hex()[:32]}...")


# ========================================
# SETUP PHASE 2: Double Ratchet Initialization
# ========================================

print("\n" + "=" * 60)
print("SETUP: Double Ratchet Initialization")
print("=" * 60)

# Both Alice and Bob initialize their Double Ratchet state
# using the shared secret from X3DH
alice_ratchet = DoubleRatchetState.init(alice_shared_secret)
bob_ratchet = DoubleRatchetState.init(bob_shared_secret)

print(f"✓ Alice ratchet state initialized")
print(f"  RK: {alice_ratchet.rk_b64[:20]}...")
print(f"  DHs_pub: {alice_ratchet.dhs_pub_b64[:20]}...")

print(f"✓ Bob ratchet state initialized")
print(f"  RK: {bob_ratchet.rk_b64[:20]}...")
print(f"  DHs_pub: {bob_ratchet.dhs_pub_b64[:20]}...")


# ========================================
# MESSAGING PHASE: Bidirectional Communication
# ========================================

print("\n" + "=" * 60)
print("MESSAGING: Bidirectional Encrypted Communication")
print("=" * 60)

# Alice sends message 1
msg1 = "Hi Bob! This is our first encrypted message."
print(f"\nAlice sends: '{msg1}'")
header1, ct1 = encrypt(alice_ratchet, msg1, "alice-phone", "bob-phone")
print(f"  Header: {{dh_pub: {header1.dh_pub[:20]}..., n: {header1.n}, pn: {header1.pn}}}")
print(f"  Encrypted: {ct1[:40]}...")

# Bob receives and decrypts
decrypted1 = decrypt(bob_ratchet, header1, ct1, "alice-phone", "bob-phone")
print(f"Bob receives: '{decrypted1}'")
assert decrypted1 == msg1
print(f"✓ Decryption successful")

# Alice sends message 2
msg2 = "How are you doing?"
print(f"\nAlice sends: '{msg2}'")
header2, ct2 = encrypt(alice_ratchet, msg2, "alice-phone", "bob-phone")
print(f"  Header: {{dh_pub: {header2.dh_pub[:20]}..., n: {header2.n}, pn: {header2.pn}}}")

# Bob receives message 2
decrypted2 = decrypt(bob_ratchet, header2, ct2, "alice-phone", "bob-phone")
print(f"Bob receives: '{decrypted2}'")
assert decrypted2 == msg2
print(f"✓ Decryption successful")

# Bob sends reply (triggers DH ratchet for Alice)
msg3 = "I'm doing great! Thanks for asking."
print(f"\nBob sends: '{msg3}'")
header3, ct3 = encrypt(bob_ratchet, msg3, "bob-phone", "alice-phone")
print(f"  Header: {{dh_pub: {header3.dh_pub[:20]}..., n: {header3.n}, pn: {header3.pn}}}")
print(f"  NOTE: Bob's DHs_pub changed! This triggers DH ratchet for Alice")

# Alice receives Bob's message (performs DH ratchet)
decrypted3 = decrypt(alice_ratchet, header3, ct3, "bob-phone", "alice-phone")
print(f"Alice receives: '{decrypted3}'")
assert decrypted3 == msg3
print(f"✓ Decryption successful (after DH ratchet)")

# Alice sends another message after ratchet
msg4 = "Nice! Let's encrypt all our messages."
print(f"\nAlice sends: '{msg4}'")
header4, ct4 = encrypt(alice_ratchet, msg4, "alice-phone", "bob-phone")
print(f"  Header: {{dh_pub: {header4.dh_pub[:20]}..., n: {header4.n}, pn: {header4.pn}}}")

# Bob receives
decrypted4 = decrypt(bob_ratchet, header4, ct4, "alice-phone", "bob-phone")
print(f"Bob receives: '{decrypted4}'")
assert decrypted4 == msg4
print(f"✓ Decryption successful")


# ========================================
# STATE PERSISTENCE
# ========================================

print("\n" + "=" * 60)
print("STATE PERSISTENCE: Save and Restore")
print("=" * 60)

# Serialize state to JSON
alice_state_dict = alice_ratchet.to_dict()
print(f"✓ Alice ratchet state serialized to dict")
print(f"  Keys: {list(alice_state_dict.keys())}")

# In real app: save to database
# db.save("alice-bob-session", alice_state_dict)

# Later: restore from database
restored_alice_ratchet = DoubleRatchetState.from_dict(alice_state_dict)
print(f"✓ Alice ratchet state restored from dict")
print(f"  RK matches: {restored_alice_ratchet.rk_b64 == alice_ratchet.rk_b64}")
print(f"  Ns matches: {restored_alice_ratchet.ns == alice_ratchet.ns}")


# ========================================
# OUT-OF-ORDER MESSAGE HANDLING
# ========================================

print("\n" + "=" * 60)
print("OUT-OF-ORDER: Handling Late-Arriving Messages")
print("=" * 60)

# Alice sends 3 messages
print("\nAlice sends 3 messages...")
messages = [
    "Message number 1",
    "Message number 2",
    "Message number 3",
]
sent_msgs = []
for msg in messages:
    header, ct = encrypt(alice_ratchet, msg, "alice-phone", "bob-phone")
    sent_msgs.append((header, ct))
    print(f"  [{header.n}] {msg}")

# Bob receives out of order: 2, 0, 1
print("\nBob receives out of order: [2], [0], [1]")

# Receive message 2
decrypted = decrypt(bob_ratchet, sent_msgs[2][0], sent_msgs[2][1], "alice-phone", "bob-phone")
print(f"  [2] {decrypted} ✓")
print(f"      Stored 2 skipped keys: {len(bob_ratchet.skipped)} entries")

# Receive message 0
decrypted = decrypt(bob_ratchet, sent_msgs[0][0], sent_msgs[0][1], "alice-phone", "bob-phone")
print(f"  [0] {decrypted} ✓")
print(f"      Skipped keys remaining: {len(bob_ratchet.skipped)} entries")

# Receive message 1
decrypted = decrypt(bob_ratchet, sent_msgs[1][0], sent_msgs[1][1], "alice-phone", "bob-phone")
print(f"  [1] {decrypted} ✓")
print(f"      Skipped keys remaining: {len(bob_ratchet.skipped)} entries")

print("\n" + "=" * 60)
print("✓ COMPLETE END-TO-END EXAMPLE SUCCESSFUL")
print("=" * 60)

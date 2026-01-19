"""
X3DH Protocol Tests

Comprehensive unit tests ensuring X3DH key agreement works correctly:
1. Alice and Bob derive identical 32-byte secrets WITH OPK
2. Alice and Bob derive identical 32-byte secrets WITHOUT OPK
3. Output is always exactly 32 bytes
4. Different inputs produce different secrets
5. Serialization/deserialization of InitialMessageHeader works
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import crypto module
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from crypto.primitive import (
    x25519_keypair,
    x25519_pub_to_b64, x25519_pub_from_b64,
)
from crypto.keys import (
    x25519_priv_to_b64, x25519_priv_from_b64,
)
from crypto.x3dh import (
    alice_initiate,
    bob_respond,
    InitialMessageHeader,
)


class TestX3DHBasic:
    """Basic X3DH functionality tests."""

    def test_alice_bob_with_opk(self):
        """
        Test X3DH key agreement WITH One-Time PreKey.
        
        Alice and Bob should derive the exact same 32-byte secret
        when using all 4 DH operations.
        """
        # Generate Alice's keys
        alice_ik_priv, alice_ik_pub = x25519_keypair()
        alice_ek_priv, alice_ek_pub = x25519_keypair()
        
        # Generate Bob's keys
        bob_ik_priv, bob_ik_pub = x25519_keypair()
        bob_spk_priv, bob_spk_pub = x25519_keypair()
        bob_opk_priv, bob_opk_pub = x25519_keypair()
        
        # Convert to base64 for API
        alice_ik_priv_b64 = x25519_priv_to_b64(alice_ik_priv)
        alice_ik_pub_b64 = x25519_pub_to_b64(alice_ik_pub)
        alice_ek_priv_b64 = x25519_priv_to_b64(alice_ek_priv)
        alice_ek_pub_b64 = x25519_pub_to_b64(alice_ek_pub)
        
        bob_ik_priv_b64 = x25519_priv_to_b64(bob_ik_priv)
        bob_ik_pub_b64 = x25519_pub_to_b64(bob_ik_pub)
        bob_spk_priv_b64 = x25519_priv_to_b64(bob_spk_priv)
        bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)
        bob_opk_priv_b64 = x25519_priv_to_b64(bob_opk_priv)
        bob_opk_pub_b64 = x25519_pub_to_b64(bob_opk_pub)
        
        # Alice initiates
        alice_header, alice_secret = alice_initiate(
            alice_identity_dh_priv_b64=alice_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
            bob_one_time_prekey_pub_b64=bob_opk_pub_b64,
            bob_one_time_prekey_id=100,
        )
        
        # Bob responds
        bob_secret = bob_respond(
            bob_identity_dh_priv_b64=bob_ik_priv_b64,
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_priv_b64=bob_spk_priv_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            bob_one_time_prekey_priv_b64=bob_opk_priv_b64,
        )
        
        # Secrets must match exactly
        assert alice_secret == bob_secret, "Alice and Bob should derive identical secrets (with OPK)"
        
        # Secret must be exactly 32 bytes
        assert len(alice_secret) == 32, "Shared secret must be exactly 32 bytes"
        assert len(bob_secret) == 32, "Shared secret must be exactly 32 bytes"

    def test_alice_bob_without_opk(self):
        """
        Test X3DH key agreement WITHOUT One-Time PreKey.
        
        Alice and Bob should derive the exact same 32-byte secret
        when using only 3 DH operations (no OPK).
        """
        # Generate Alice's keys
        alice_ik_priv, alice_ik_pub = x25519_keypair()
        alice_ek_priv, alice_ek_pub = x25519_keypair()
        
        # Generate Bob's keys
        bob_ik_priv, bob_ik_pub = x25519_keypair()
        bob_spk_priv, bob_spk_pub = x25519_keypair()
        
        # Convert to base64
        alice_ik_priv_b64 = x25519_priv_to_b64(alice_ik_priv)
        alice_ik_pub_b64 = x25519_pub_to_b64(alice_ik_pub)
        alice_ek_priv_b64 = x25519_priv_to_b64(alice_ek_priv)
        alice_ek_pub_b64 = x25519_pub_to_b64(alice_ek_pub)
        
        bob_ik_priv_b64 = x25519_priv_to_b64(bob_ik_priv)
        bob_ik_pub_b64 = x25519_pub_to_b64(bob_ik_pub)
        bob_spk_priv_b64 = x25519_priv_to_b64(bob_spk_priv)
        bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)
        
        # Alice initiates WITHOUT OPK
        alice_header, alice_secret = alice_initiate(
            alice_identity_dh_priv_b64=alice_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
            bob_one_time_prekey_pub_b64=None,
            bob_one_time_prekey_id=None,
        )
        
        # Bob responds WITHOUT OPK
        bob_secret = bob_respond(
            bob_identity_dh_priv_b64=bob_ik_priv_b64,
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_priv_b64=bob_spk_priv_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            bob_one_time_prekey_priv_b64=None,
        )
        
        # Secrets must match exactly
        assert alice_secret == bob_secret, "Alice and Bob should derive identical secrets (without OPK)"
        
        # Secret must be exactly 32 bytes
        assert len(alice_secret) == 32, "Shared secret must be exactly 32 bytes"
        assert len(bob_secret) == 32, "Shared secret must be exactly 32 bytes"
        
        # OPK id should be None in header
        assert alice_header.receiver_one_time_prekey_id is None

    def test_secret_deterministic(self):
        """
        Test that X3DH is deterministic.
        
        Running the same initiation twice with same keys produces same secret.
        """
        # Generate keys
        alice_ik_priv, alice_ik_pub = x25519_keypair()
        alice_ek_priv, alice_ek_pub = x25519_keypair()
        bob_ik_priv, bob_ik_pub = x25519_keypair()
        bob_spk_priv, bob_spk_pub = x25519_keypair()
        
        # Convert to base64
        alice_ik_priv_b64 = x25519_priv_to_b64(alice_ik_priv)
        alice_ik_pub_b64 = x25519_pub_to_b64(alice_ik_pub)
        alice_ek_priv_b64 = x25519_priv_to_b64(alice_ek_priv)
        alice_ek_pub_b64 = x25519_pub_to_b64(alice_ek_pub)
        bob_ik_pub_b64 = x25519_pub_to_b64(bob_ik_pub)
        bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)
        
        # Alice initiates twice with same keys
        _, secret1 = alice_initiate(
            alice_identity_dh_priv_b64=alice_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
        )
        
        _, secret2 = alice_initiate(
            alice_identity_dh_priv_b64=alice_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
        )
        
        assert secret1 == secret2, "X3DH must be deterministic"

    def test_different_inputs_different_secrets(self):
        """
        Test that different key inputs produce different secrets.
        """
        # Generate two sets of Alice keys
        alice1_ik_priv, alice1_ik_pub = x25519_keypair()
        alice2_ik_priv, alice2_ik_pub = x25519_keypair()
        alice_ek_priv, alice_ek_pub = x25519_keypair()
        
        # Generate Bob's keys
        bob_ik_priv, bob_ik_pub = x25519_keypair()
        bob_spk_priv, bob_spk_pub = x25519_keypair()
        
        # Convert to base64
        alice1_ik_priv_b64 = x25519_priv_to_b64(alice1_ik_priv)
        alice1_ik_pub_b64 = x25519_pub_to_b64(alice1_ik_pub)
        alice2_ik_priv_b64 = x25519_priv_to_b64(alice2_ik_priv)
        alice2_ik_pub_b64 = x25519_pub_to_b64(alice2_ik_pub)
        alice_ek_priv_b64 = x25519_priv_to_b64(alice_ek_priv)
        alice_ek_pub_b64 = x25519_pub_to_b64(alice_ek_pub)
        bob_ik_pub_b64 = x25519_pub_to_b64(bob_ik_pub)
        bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)
        
        # Alice 1 initiates
        _, secret1 = alice_initiate(
            alice_identity_dh_priv_b64=alice1_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice1_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
        )
        
        # Alice 2 initiates (different identity key)
        _, secret2 = alice_initiate(
            alice_identity_dh_priv_b64=alice2_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice2_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-2",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
        )
        
        assert secret1 != secret2, "Different identity keys must produce different secrets"


class TestInitialMessageHeader:
    """Tests for InitialMessageHeader serialization."""

    def test_header_serialization(self):
        """Test that InitialMessageHeader can be serialized and deserialized."""
        header = InitialMessageHeader(
            sender_identity_dh_pub="alice_ik_pub_b64",
            sender_ephemeral_pub="alice_ek_pub_b64",
            receiver_signed_prekey_id=1,
            receiver_one_time_prekey_id=100,
            sender_device_id="alice-device-1",
        )
        
        # Serialize
        d = header.to_dict()
        
        # Deserialize
        header2 = InitialMessageHeader.from_dict(d)
        
        # Compare
        assert header.sender_identity_dh_pub == header2.sender_identity_dh_pub
        assert header.sender_ephemeral_pub == header2.sender_ephemeral_pub
        assert header.receiver_signed_prekey_id == header2.receiver_signed_prekey_id
        assert header.receiver_one_time_prekey_id == header2.receiver_one_time_prekey_id
        assert header.sender_device_id == header2.sender_device_id

    def test_header_without_opk(self):
        """Test InitialMessageHeader without OPK."""
        header = InitialMessageHeader(
            sender_identity_dh_pub="alice_ik_pub_b64",
            sender_ephemeral_pub="alice_ek_pub_b64",
            receiver_signed_prekey_id=1,
            receiver_one_time_prekey_id=None,
            sender_device_id="alice-device-1",
        )
        
        d = header.to_dict()
        assert d["receiver_one_time_prekey_id"] is None
        
        header2 = InitialMessageHeader.from_dict(d)
        assert header2.receiver_one_time_prekey_id is None


class TestX3DHEdgeCases:
    """Edge cases and error conditions."""

    def test_secret_length_is_32(self):
        """Verify all secrets are exactly 32 bytes (no more, no less)."""
        # Generate keys
        alice_ik_priv, alice_ik_pub = x25519_keypair()
        alice_ek_priv, alice_ek_pub = x25519_keypair()
        bob_ik_priv, bob_ik_pub = x25519_keypair()
        bob_spk_priv, bob_spk_pub = x25519_keypair()
        bob_opk_priv, bob_opk_pub = x25519_keypair()
        
        # Convert to base64
        alice_ik_priv_b64 = x25519_priv_to_b64(alice_ik_priv)
        alice_ik_pub_b64 = x25519_pub_to_b64(alice_ik_pub)
        alice_ek_priv_b64 = x25519_priv_to_b64(alice_ek_priv)
        alice_ek_pub_b64 = x25519_pub_to_b64(alice_ek_pub)
        bob_ik_pub_b64 = x25519_pub_to_b64(bob_ik_pub)
        bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)
        bob_opk_pub_b64 = x25519_pub_to_b64(bob_opk_pub)
        
        # Test WITH OPK
        _, secret_with_opk = alice_initiate(
            alice_identity_dh_priv_b64=alice_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
            bob_one_time_prekey_pub_b64=bob_opk_pub_b64,
            bob_one_time_prekey_id=100,
        )
        
        # Test WITHOUT OPK
        _, secret_without_opk = alice_initiate(
            alice_identity_dh_priv_b64=alice_ik_priv_b64,
            alice_ephemeral_priv_b64=alice_ek_priv_b64,
            alice_identity_dh_pub_b64=alice_ik_pub_b64,
            alice_ephemeral_pub_b64=alice_ek_pub_b64,
            alice_device_id="alice-device-1",
            bob_identity_dh_pub_b64=bob_ik_pub_b64,
            bob_signed_prekey_pub_b64=bob_spk_pub_b64,
            bob_signed_prekey_id=1,
            bob_one_time_prekey_pub_b64=None,
            bob_one_time_prekey_id=None,
        )
        
        # Both must be exactly 32 bytes
        assert len(secret_with_opk) == 32, "WITH OPK: secret must be 32 bytes"
        assert len(secret_without_opk) == 32, "WITHOUT OPK: secret must be 32 bytes"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

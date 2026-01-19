"""
Double Ratchet Protocol Tests

Tests for:
1. In-order messages
2. Out-of-order messages
3. DH ratchet steps (both sides sending)
4. State persistence
"""

import pytest
from crypto.double_ratchet import (
    DoubleRatchetState,
    MessageHeader,
    build_aad,
    kdf_rk,
    kdf_ck,
    encrypt,
    decrypt,
)
from crypto.primitive import (
    x25519_keypair,
)


class TestMessageHeader:
    """Tests for MessageHeader and AAD."""

    def test_header_creation(self):
        """Test creating a MessageHeader."""
        header = MessageHeader(
            dh_pub="test_pub_key_base64",
            pn=5,
            n=10,
        )
        assert header.dh_pub == "test_pub_key_base64"
        assert header.pn == 5
        assert header.n == 10

    def test_header_serialization(self):
        """Test MessageHeader serialization."""
        header = MessageHeader(dh_pub="abc123", pn=2, n=3)
        d = header.to_dict()
        
        assert d["dh_pub"] == "abc123"
        assert d["pn"] == 2
        assert d["n"] == 3
        
        # Deserialize
        header2 = MessageHeader.from_dict(d)
        assert header2.dh_pub == header.dh_pub
        assert header2.pn == header.pn
        assert header2.n == header.n

    def test_build_aad_deterministic(self):
        """Test that AAD is deterministic."""
        header = MessageHeader(dh_pub="pub123", pn=1, n=2)
        
        aad1 = build_aad(header, "alice", "bob")
        aad2 = build_aad(header, "alice", "bob")
        
        assert aad1 == aad2

    def test_build_aad_different_devices(self):
        """Test that different device IDs produce different AAD."""
        header = MessageHeader(dh_pub="pub123", pn=1, n=2)
        
        aad1 = build_aad(header, "alice", "bob")
        aad2 = build_aad(header, "alice", "charlie")
        
        assert aad1 != aad2

    def test_build_aad_different_headers(self):
        """Test that different headers produce different AAD."""
        header1 = MessageHeader(dh_pub="pub123", pn=1, n=2)
        header2 = MessageHeader(dh_pub="pub456", pn=1, n=2)
        
        aad1 = build_aad(header1, "alice", "bob")
        aad2 = build_aad(header2, "alice", "bob")
        
        assert aad1 != aad2


class TestKDFs:
    """Tests for Root KDF and Chain KDF."""

    def test_kdf_rk_output_size(self):
        """Test that kdf_rk produces 32-byte keys."""
        rk = b"\x00" * 32
        dh_out = b"\x01" * 32
        
        rk_new, ck_new = kdf_rk(rk, dh_out)
        
        assert len(rk_new) == 32
        assert len(ck_new) == 32

    def test_kdf_rk_deterministic(self):
        """Test that kdf_rk is deterministic."""
        rk = b"\x00" * 32
        dh_out = b"\x01" * 32
        
        rk1, ck1 = kdf_rk(rk, dh_out)
        rk2, ck2 = kdf_rk(rk, dh_out)
        
        assert rk1 == rk2
        assert ck1 == ck2

    def test_kdf_ck_output_size(self):
        """Test that kdf_ck produces 32-byte keys."""
        ck = b"\x00" * 32
        
        ck_new, mk = kdf_ck(ck)
        
        assert len(ck_new) == 32
        assert len(mk) == 32

    def test_kdf_ck_deterministic(self):
        """Test that kdf_ck is deterministic."""
        ck = b"\x00" * 32
        
        ck1, mk1 = kdf_ck(ck)
        ck2, mk2 = kdf_ck(ck)
        
        assert ck1 == ck2
        assert mk1 == mk2

    def test_kdf_ck_chain(self):
        """Test chaining kdf_ck produces different keys."""
        ck = b"\x00" * 32
        
        ck1, mk1 = kdf_ck(ck)
        ck2, mk2 = kdf_ck(ck1)
        ck3, mk3 = kdf_ck(ck2)
        
        # All should be different
        assert ck1 != ck
        assert ck2 != ck1
        assert ck3 != ck2
        assert mk1 != mk2
        assert mk2 != mk3


class TestDoubleRatchetState:
    """Tests for DoubleRatchetState initialization and persistence."""

    def test_state_init(self):
        """Test initializing state from root key."""
        root_key = b"\x00" * 32
        state = DoubleRatchetState.init(root_key)
        
        assert state.rk_b64 is not None
        assert state.dhs_priv_b64 is not None
        assert state.dhs_pub_b64 is not None
        assert state.dhr_pub_b64 is None  # Not set yet
        assert state.cks_b64 is None  # Derived lazily on first encrypt
        assert state.ckr_b64 is None  # Derived on first receive
        assert state.ns == 0
        assert state.nr == 0
        assert state.pn == 0
        assert len(state.skipped) == 0

    def test_state_serialization(self):
        """Test state serialization and deserialization."""
        root_key = b"\x00" * 32
        state1 = DoubleRatchetState.init(root_key)
        
        # Serialize
        d = state1.to_dict()
        
        # Deserialize
        state2 = DoubleRatchetState.from_dict(d)
        
        # Compare
        assert state1.rk_b64 == state2.rk_b64
        assert state1.dhs_priv_b64 == state2.dhs_priv_b64
        assert state1.dhs_pub_b64 == state2.dhs_pub_b64
        assert state1.ns == state2.ns
        assert state1.nr == state2.nr

    def test_state_serialization_with_skipped(self):
        """Test state serialization with skipped keys."""
        root_key = b"\x00" * 32
        state1 = DoubleRatchetState.init(root_key)
        
        # Add some skipped keys
        state1.skipped[("pub_key_1", 5)] = "mk_1_b64"
        state1.skipped[("pub_key_2", 10)] = "mk_2_b64"
        
        # Serialize and deserialize
        d = state1.to_dict()
        state2 = DoubleRatchetState.from_dict(d)
        
        # Check skipped keys are preserved
        assert ("pub_key_1", 5) in state2.skipped
        assert ("pub_key_2", 10) in state2.skipped
        assert state2.skipped[("pub_key_1", 5)] == "mk_1_b64"
        assert state2.skipped[("pub_key_2", 10)] == "mk_2_b64"


class TestDoubleRatchetBasic:
    """Basic Double Ratchet tests (in-order messages)."""

    def test_encrypt_decrypt_single_message(self):
        """Test encrypting and decrypting a single message."""
        root_key = b"\x00" * 32
        
        # Alice initializes
        alice_state = DoubleRatchetState.init(root_key)
        
        # Bob initializes with same root key
        bob_state = DoubleRatchetState.init(root_key)
        # Bob does NOT know Alice's ratchet pub initially - it comes in the header
        
        # Alice encrypts
        plaintext = "Hello, Bob!"
        header, ciphertext_b64 = encrypt(alice_state, plaintext, "alice", "bob")
        
        # Bob decrypts
        decrypted = decrypt(bob_state, header, ciphertext_b64, "alice", "bob")
        
        assert decrypted == plaintext

    def test_encrypt_decrypt_multiple_messages_in_order(self):
        """Test sending multiple messages in order."""
        root_key = b"\x00" * 32
        
        # Alice and Bob initialize
        alice_state = DoubleRatchetState.init(root_key)
        bob_state = DoubleRatchetState.init(root_key)
        
        messages = ["Hello", "World", "How are you?"]
        
        # Alice sends messages
        for msg in messages:
            header, ciphertext_b64 = encrypt(alice_state, msg, "alice", "bob")
            decrypted = decrypt(bob_state, header, ciphertext_b64, "alice", "bob")
            assert decrypted == msg

    def test_encrypt_decrypt_bidirectional(self):
        """Test bidirectional communication (both sides sending)."""
        root_key = b"\x00" * 32
        
        # Alice initializes
        alice_state = DoubleRatchetState.init(root_key)
        
        # Bob initializes
        bob_state = DoubleRatchetState.init(root_key)
        
        # Alice sends to Bob
        alice_msg = "Hi Bob"
        header1, ct1 = encrypt(alice_state, alice_msg, "alice", "bob")
        decrypted1 = decrypt(bob_state, header1, ct1, "alice", "bob")
        assert decrypted1 == alice_msg
        
        # Bob sends to Alice (DH ratchet step for Alice)
        bob_msg = "Hi Alice"
        header2, ct2 = encrypt(bob_state, bob_msg, "bob", "alice")
        decrypted2 = decrypt(alice_state, header2, ct2, "bob", "alice")
        assert decrypted2 == bob_msg
        
        # Alice sends again (should work after receiving Bob's ratchet update)
        alice_msg2 = "How are you?"
        header3, ct3 = encrypt(alice_state, alice_msg2, "alice", "bob")
        decrypted3 = decrypt(bob_state, header3, ct3, "alice", "bob")
        assert decrypted3 == alice_msg2


class TestDoubleRatchetOutOfOrder:
    """Test out-of-order message delivery."""

    def test_out_of_order_messages(self):
        """Test receiving messages out of order (0, 2, 1)."""
        root_key = b"\x00" * 32
        
        alice_state = DoubleRatchetState.init(root_key)
        bob_state = DoubleRatchetState.init(root_key)
        
        # Alice sends 3 messages
        messages = ["msg0", "msg1", "msg2"]
        headers = []
        ciphertexts = []
        
        for msg in messages:
            header, ct = encrypt(alice_state, msg, "alice", "bob")
            headers.append(header)
            ciphertexts.append(ct)
        
        # Bob receives in order: 0, 2, 1
        # Receive message 0
        decrypted0 = decrypt(bob_state, headers[0], ciphertexts[0], "alice", "bob")
        assert decrypted0 == "msg0"
        
        # Receive message 2 (out of order)
        decrypted2 = decrypt(bob_state, headers[2], ciphertexts[2], "alice", "bob")
        assert decrypted2 == "msg2"
        
        # Receive message 1 (from skipped)
        decrypted1 = decrypt(bob_state, headers[1], ciphertexts[1], "alice", "bob")
        assert decrypted1 == "msg1"

    def test_skipped_keys_stored(self):
        """Test that skipped keys are properly stored."""
        root_key = b"\x00" * 32
        
        alice_state = DoubleRatchetState.init(root_key)
        bob_state = DoubleRatchetState.init(root_key)
        
        # Alice sends 3 messages
        headers = []
        ciphertexts = []
        
        for i in range(3):
            header, ct = encrypt(alice_state, f"msg{i}", "alice", "bob")
            headers.append(header)
            ciphertexts.append(ct)
        
        # Bob receives out of order: 2, then 0, 1
        # After receiving message 2, there should be 2 skipped keys
        decrypt(bob_state, headers[2], ciphertexts[2], "alice", "bob")
        assert len(bob_state.skipped) == 2
        
        # After receiving message 0, skipped should decrease
        decrypt(bob_state, headers[0], ciphertexts[0], "alice", "bob")
        assert len(bob_state.skipped) == 1
        
        # After receiving message 1, skipped should be empty
        decrypt(bob_state, headers[1], ciphertexts[1], "alice", "bob")
        assert len(bob_state.skipped) == 0

    def test_dh_ratchet_with_out_of_order(self):
        """Test DH ratchet with out-of-order messages."""
        root_key = b"\x00" * 32
        
        alice_state = DoubleRatchetState.init(root_key)
        bob_state = DoubleRatchetState.init(root_key)
        
        # Alice sends message 0
        h0, c0 = encrypt(alice_state, "msg_alice_0", "alice", "bob")
        
        # Bob receives message 0
        decrypt(bob_state, h0, c0, "alice", "bob")
        
        # Bob sends message 0 and 1 (DH ratchet for Alice)
        h_bob0, c_bob0 = encrypt(bob_state, "msg_bob_0", "bob", "alice")
        h_bob1, c_bob1 = encrypt(bob_state, "msg_bob_1", "bob", "alice")
        
        # Alice sends message 1
        h1, c1 = encrypt(alice_state, "msg_alice_1", "alice", "bob")
        
        # Alice receives Bob's messages out of order (1, 0)
        msg_bob1 = decrypt(alice_state, h_bob1, c_bob1, "bob", "alice")
        assert msg_bob1 == "msg_bob_1"
        
        msg_bob0 = decrypt(alice_state, h_bob0, c_bob0, "bob", "alice")
        assert msg_bob0 == "msg_bob_0"
        
        # Bob receives Alice's new message after ratchet
        msg_alice1 = decrypt(bob_state, h1, c1, "alice", "bob")
        assert msg_alice1 == "msg_alice_1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

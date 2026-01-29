from crypto.double_ratchet import DoubleRatchetState, MessageHeader, encrypt, decrypt
from crypto.primitive import x25519_keypair
from crypto.keys import x25519_priv_to_b64
from crypto.primitive import x25519_pub_to_b64


def test_double_ratchet_basic_roundtrip():
    """
    Alice initializes as initiator with Bob's SPK public.
    Bob initializes as responder with his SPK keypair.
    Alice encrypts -> Bob decrypts.
    """

    shared_secret = b"\x11" * 32  # pretend X3DH output, stable for test

    # Bob's signed prekey (SPK) used as initial ratchet key for responder
    bob_spk_priv, bob_spk_pub = x25519_keypair()
    bob_spk_priv_b64 = x25519_priv_to_b64(bob_spk_priv)
    bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)

    alice_device_id = "alice_device_1"
    bob_device_id = "bob_device_1"

    alice_state = DoubleRatchetState.init_initiator(shared_secret, bob_spk_pub_b64)
    bob_state = DoubleRatchetState.init_responder(shared_secret, bob_spk_priv_b64, bob_spk_pub_b64)

    header, ct = encrypt(alice_state, "hello", alice_device_id, bob_device_id)
    pt = decrypt(bob_state, header, ct, alice_device_id, bob_device_id)
    assert pt == "hello"


def test_double_ratchet_out_of_order():
    """
    Alice sends 3 messages. Bob receives them out of order (2,0,1).
    Skipped-key storage should make this work.
    """
    shared_secret = b"\x22" * 32

    bob_spk_priv, bob_spk_pub = x25519_keypair()
    bob_spk_priv_b64 = x25519_priv_to_b64(bob_spk_priv)
    bob_spk_pub_b64 = x25519_pub_to_b64(bob_spk_pub)

    alice_device_id = "alice_device_1"
    bob_device_id = "bob_device_1"

    alice_state = DoubleRatchetState.init_initiator(shared_secret, bob_spk_pub_b64)
    bob_state = DoubleRatchetState.init_responder(shared_secret, bob_spk_priv_b64, bob_spk_pub_b64)

    msgs = ["m0", "m1", "m2"]
    packets = [encrypt(alice_state, m, alice_device_id, bob_device_id) for m in msgs]

    # Receive out of order: 2, 0, 1
    h2, c2 = packets[2]
    h0, c0 = packets[0]
    h1, c1 = packets[1]

    assert decrypt(bob_state, h2, c2, alice_device_id, bob_device_id) == "m2"
    assert decrypt(bob_state, h0, c0, alice_device_id, bob_device_id) == "m0"
    assert decrypt(bob_state, h1, c1, alice_device_id, bob_device_id) == "m1"

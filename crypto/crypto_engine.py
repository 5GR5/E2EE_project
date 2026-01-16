import os
import base64
import json
import time
from typing import Dict, Optional, Tuple, List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================
# PART 1: Low-Level Crypto Primitives
# ==========================================

class CryptoUtils:
    """
    Helper class for raw cryptographic operations (Curve25519, AES-GCM, SHA256).
    Keeps the complex math isolated from the logic.
    """

    @staticmethod
    def generate_identity_key_pair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        """Generates a long-term Identity Key (Curve25519)."""
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def generate_signing_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generates a Signing Key (Ed25519) to sign PreKeys."""
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def sign(signing_key: ed25519.Ed25519PrivateKey, message: bytes) -> str:
        """Signs a message and returns Base64 signature."""
        signature = signing_key.sign(message)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify(verify_key: ed25519.Ed25519PublicKey, signature_b64: str, message: bytes) -> bool:
        """Verifies a Base64 signature."""
        try:
            sig_bytes = base64.b64decode(signature_b64)
            verify_key.verify(sig_bytes, message)
            return True
        except Exception:
            return False

    @staticmethod
    def encode_key(public_key) -> str:
        """Encodes a public key to Base64 for transport."""
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw_bytes).decode('utf-8')

    @staticmethod
    def decode_key(b64_key: str) -> x25519.X25519PublicKey:
        """Decodes a Base64 string back to a Curve25519 public key."""
        key_bytes = base64.b64decode(b64_key)
        return x25519.X25519PublicKey.from_public_bytes(key_bytes)

    @staticmethod
    def dh(private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey) -> bytes:
        """Performs a Diffie-Hellman exchange to get raw shared bytes."""
        return private_key.exchange(public_key)

    @staticmethod
    def kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        KDF for the Symmetric-Key Ratchet.
        Input: Chain Key
        Output: (New Chain Key, Message Key)
        """
        # We derive 64 bytes: 32 for the next chain key, 32 for the message key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"Ratchet_Step_2",
        )
        derived = hkdf.derive(chain_key)
        return derived[:32], derived[32:]

    @staticmethod
    def kdf_root(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        """
        KDF for the Diffie-Hellman Ratchet.
        Input: Old Root Key + New DH Output
        Output: (New Root Key, New Chain Key)
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=root_key, # The old root key acts as salt
            info=b"Root_Ratchet_Step_1",
        )
        derived = hkdf.derive(dh_out)
        return derived[:32], derived[32:]


# ==========================================
# PART 2: The Logic (X3DH & Double Ratchet)
# ==========================================

class DoubleRatchetSession:
    """
    Manages the state of an encrypted session (Double Ratchet).
    Stores root keys, chain keys, and handles encryption/decryption.
    """
    def __init__(self, root_key: bytes, remote_pub_ratchet: x25519.X25519PublicKey = None):
        # State variables
        self.root_key = root_key
        
        # Ratchet keys
        self.my_ratchet_priv, self.my_ratchet_pub = CryptoUtils.generate_identity_key_pair()
        self.remote_ratchet_pub = remote_pub_ratchet

        # Chain keys (sending and receiving)
        self.send_chain_key = None
        self.recv_chain_key = None
        
        # If we are the initiator (we don't have a remote ratchet key yet), 
        # we initialize our sending chain immediately.
        # If we are the receiver, we wait for the first message to initialize.
        if remote_pub_ratchet:
            # We are ALICE (Initiator)
            # We jumpstart the sending chain using the initial root key
            self.send_chain_key = self.root_key # Simplification for X3DH startup
        
    def _ratchet_diffie_hellman(self, new_remote_public_key: x25519.X25519PublicKey):
        """
        Performs the 'Double' part of the ratchet: The DH Ratchet.
        Updates the Root Key and Chain Keys based on new entropy from the peer.
        """
        self.remote_ratchet_pub = new_remote_public_key
        
        # 1. DH Output = My Priv * Their New Pub
        dh_out = CryptoUtils.dh(self.my_ratchet_priv, self.remote_ratchet_pub)
        
        # 2. Update Root + Get Receiver Chain
        self.root_key, self.recv_chain_key = CryptoUtils.kdf_root(self.root_key, dh_out)
        
        # 3. Generate new key pair for myself
        self.my_ratchet_priv, self.my_ratchet_pub = CryptoUtils.generate_identity_key_pair()
        
        # 4. DH Output = My New Priv * Their Pub
        dh_out_2 = CryptoUtils.dh(self.my_ratchet_priv, self.remote_ratchet_pub)
        
        # 5. Update Root + Get Sender Chain
        self.root_key, self.send_chain_key = CryptoUtils.kdf_root(self.root_key, dh_out_2)

    def encrypt(self, plaintext: str) -> Dict:
        """
        Encrypts a message using the current sending chain.
        Returns the header (needed for routing/ratchet) and ciphertext.
        """
        # Ratchet the sending chain forward
        self.send_chain_key, message_key = CryptoUtils.kdf_chain(self.send_chain_key)
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)
        ciphertext_bytes = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        return {
            "header": {
                "ratchet_pub": CryptoUtils.encode_key(self.my_ratchet_pub),
                # In a real app, you'd add N (message number) and PN (prev message number) here
            },
            "ciphertext": CryptoUtils.encode_key(nonce + ciphertext_bytes) # Prepend nonce
        }

    def decrypt(self, header: Dict, ciphertext_b64: str) -> str:
        """
        Decrypts a message. Handles the ratchet step if a new key is seen.
        """
        incoming_ratchet_pub_str = header["ratchet_pub"]
        incoming_ratchet_pub = CryptoUtils.decode_key(incoming_ratchet_pub_str)
        
        # Check if the sender has rotated their ratchet key (DH Ratchet step)
        if (self.remote_ratchet_pub is None) or \
           (incoming_ratchet_pub_str != CryptoUtils.encode_key(self.remote_ratchet_pub)):
            self._ratchet_diffie_hellman(incoming_ratchet_pub)

        # Ratchet the receiving chain forward
        self.recv_chain_key, message_key = CryptoUtils.kdf_chain(self.recv_chain_key)
        
        # Decrypt
        full_cipher = base64.b64decode(ciphertext_b64)
        nonce = full_cipher[:12]
        ciphertext = full_cipher[12:]
        
        aesgcm = AESGCM(message_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')


class SignalBrain:
    """
    The Main Interface.
    Usage:
    1. Initialize.
    2. generate_keys() -> Send to server.
    3. start_chat(peer_bundle) -> Returns a Session.
    4. receive_chat(my_keys, incoming_x3dh_data) -> Returns a Session.
    """
    def __init__(self, user_id: str):
        self.user_id = user_id
        # In a real app, load these from disk!
        self.identity_priv, self.identity_pub = CryptoUtils.generate_identity_key_pair()
        self.signed_prekey_priv = None 
        self.one_time_prekeys = {} # key_id -> private_key

    def generate_registration_payload(self) -> Dict:
        """
        Generates the payload for POST /keys/upload.
        Creates: Signed PreKey, One-Time PreKeys.
        """
        # 1. Create Signed PreKey
        spk_priv, spk_pub = CryptoUtils.generate_identity_key_pair()
        self.signed_prekey_priv = spk_priv
        
        # Sign it (using a separate signing key is standard, but simplified here to use IK or separate Ed25519)
        # Note: Your server expects a signature. Signal usually signs with the Identity Key.
        # But Identity Key is X25519 (DH), not Ed25519 (Sign). 
        # Standard solution: Use X25519 for everything (complicated math) or keep a separate Ed25519 Identity.
        # We will generate a dedicated signing identity just for this bundle for now.
        sig_priv, _ = CryptoUtils.generate_signing_key_pair()
        spk_pub_bytes = spk_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        signature = CryptoUtils.sign(sig_priv, spk_pub_bytes)

        # 2. Create One-Time PreKeys
        otpks = []
        for i in range(10):
            opk_priv, opk_pub = CryptoUtils.generate_identity_key_pair()
            self.one_time_prekeys[i] = opk_priv
            otpks.append({
                "key_id": i,
                "public_key": CryptoUtils.encode_key(opk_pub)
            })

        return {
            "identity_key_public": CryptoUtils.encode_key(self.identity_pub), # For Device creation
            "signed_prekey": {
                "key_id": 1,
                "public_key": CryptoUtils.encode_key(spk_pub),
                "signature": signature
            },
            "one_time_prekeys": otpks
        }

    def x3dh_send_initial(self, peer_bundle: Dict) -> DoubleRatchetSession:
        """
        Performs the X3DH Handshake (Alice Side).
        Returns a Session object ready to encrypt the first message.
        """
        # Load Peer Keys
        peer_ik = CryptoUtils.decode_key(peer_bundle['identity_key_public'])
        peer_spk = CryptoUtils.decode_key(peer_bundle['signed_prekey']['public_key'])
        
        # My Ephemeral Key
        ek_priv, ek_pub = CryptoUtils.generate_identity_key_pair()

        # DH1: My IK * Their SPK
        dh1 = CryptoUtils.dh(self.identity_priv, peer_spk)
        # DH2: My EK * Their IK
        dh2 = CryptoUtils.dh(ek_priv, peer_ik)
        # DH3: My EK * Their SPK
        dh3 = CryptoUtils.dh(ek_priv, peer_spk)
        
        sk_input = dh1 + dh2 + dh3

        # DH4: My EK * Their OPK (if exists)
        if peer_bundle.get('one_time_prekey'):
            peer_opk = CryptoUtils.decode_key(peer_bundle['one_time_prekey']['public_key'])
            dh4 = CryptoUtils.dh(ek_priv, peer_opk)
            sk_input += dh4

        # Derive Initial Root Key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'\x00'*32, # Zero-filled salt
            info=b"X3DH_Result",
        )
        root_key = hkdf.derive(sk_input)

        # Initialize Session
        # Note: We pass peer_spk as the "initial remote ratchet" to kickstart the process
        return DoubleRatchetSession(root_key=root_key, remote_pub_ratchet=peer_spk)

    def x3dh_receive_initial(self, sender_ik_b64: str, sender_ek_b64: str, my_opk_id: int = None) -> DoubleRatchetSession:
        """
        Performs the X3DH Handshake (Bob Side).
        Reconstructs the shared secret using my private keys and sender's public keys.
        """
        sender_ik = CryptoUtils.decode_key(sender_ik_b64)
        sender_ek = CryptoUtils.decode_key(sender_ek_b64)

        # DH1: Their IK * My SPK
        dh1 = CryptoUtils.dh(self.signed_prekey_priv, sender_ik)
        # DH2: Their EK * My IK
        dh2 = CryptoUtils.dh(self.identity_priv, sender_ek)
        # DH3: Their EK * My SPK
        dh3 = CryptoUtils.dh(self.signed_prekey_priv, sender_ek)

        sk_input = dh1 + dh2 + dh3

        if my_opk_id is not None and my_opk_id in self.one_time_prekeys:
            # DH4: Their EK * My OPK
            opk_priv = self.one_time_prekeys.pop(my_opk_id) # Consume it!
            dh4 = CryptoUtils.dh(opk_priv, sender_ek)
            sk_input += dh4

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'\x00'*32,
            info=b"X3DH_Result",
        )
        root_key = hkdf.derive(sk_input)
        
        # Bob starts with just the root key. 
        # The first message he receives will trigger the first ratchet step.
        return DoubleRatchetSession(root_key=root_key, remote_pub_ratchet=None)
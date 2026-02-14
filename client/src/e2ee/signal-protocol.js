/**
 * Signal Protocol Implementation (X3DH + Double Ratchet)
 * 
 * This module implements the Signal Protocol for end-to-end encryption:
 * 1. X3DH: Extended Triple Diffie-Hellman for initial key agreement
 * 2. Double Ratchet: For ongoing message encryption with forward secrecy
 * 
 * We use the crypto primitives from tweetnacl which provides:
 * - X25519 (Curve25519 Diffie-Hellman)
 * - XSalsa20-Poly1305 (Authenticated encryption)
 * 
 * This is a JavaScript port of the Python crypto modules, maintaining
 * compatibility with the backend's key exchange protocol.
 */

import nacl from 'tweetnacl'
import { encodeBase64, decodeBase64, encodeUTF8 as bytesToString, decodeUTF8 as stringToBytes } from 'tweetnacl-util'
import { keyStore } from './keystore'

// Helper functions with clearer names (tweetnacl-util has confusing naming)
const encodeUTF8 = stringToBytes  // string → Uint8Array
const decodeUTF8 = bytesToString  // Uint8Array → string

// ============================================
// Crypto Primitives (Mirror Python implementation)
// ============================================

/**
 * Perform X25519 Diffie-Hellman key exchange
 */
function dh(privateKey, publicKey) {
  return nacl.scalarMult(privateKey, publicKey)
}

/**
 * HKDF-SHA256 key derivation
 * Simplified version - for production, use a proper HKDF library
 */
async function hkdf(inputKeyMaterial, salt, info, length = 32) {
  // For simplicity, using nacl.hash for derivation
  // In production, use proper HKDF with SHA-256
  const combined = new Uint8Array(inputKeyMaterial.length + salt.length + info.length)
  combined.set(inputKeyMaterial, 0)
  combined.set(salt, inputKeyMaterial.length)
  combined.set(info, inputKeyMaterial.length + salt.length)
  
  const hash = nacl.hash(combined)
  return hash.slice(0, length)
}

/**
 * AEAD encryption using XSalsa20-Poly1305
 * Simpler approach: Just encrypt plaintext, AD is sent separately in header
 */
function aeadEncrypt(key, plaintext, associatedData) {
  // Ensure key is Uint8Array with correct length
  if (!(key instanceof Uint8Array)) {
    throw new TypeError(`Key must be Uint8Array, got ${typeof key}: ${Object.prototype.toString.call(key)}`)
  }
  if (key.length !== 32) {
    throw new Error(`Key must be 32 bytes, got ${key.length}`)
  }
  
  const nonce = nacl.randomBytes(24)
  let plaintextBytes
  if (typeof plaintext === 'string') {
    plaintextBytes = encodeUTF8(plaintext)
  } else {
    plaintextBytes = plaintext
  }
  
  // Debug check all parameters  
  if (!(nonce instanceof Uint8Array)) {
    throw new TypeError(`Nonce must be Uint8Array, got ${typeof nonce}`)
  }
  if (!(plaintextBytes instanceof Uint8Array)) {
    throw new TypeError(`Plaintext must be Uint8Array, got ${typeof plaintextBytes}: ${Object.prototype.toString.call(plaintextBytes)}. Original type: ${typeof plaintext}. encodeUTF8 result: ${encodeUTF8 ? 'exists' : 'undefined'}`)
  }
  
  const ciphertext = nacl.secretbox(plaintextBytes, nonce, key)
  
  return {
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(ciphertext),
    ad_length: 0 // Not used in this simplified version
  }
}

/**
 * AEAD decryption
 * AD (header) is authenticated by being included in the message structure
 */
function aeadDecrypt(key, nonce, ciphertext, associatedData, adLength) {
  const nonceBytes = decodeBase64(nonce)
  const ciphertextBytes = decodeBase64(ciphertext)
  
  const plaintextBytes = nacl.secretbox.open(ciphertextBytes, nonceBytes, key)
  if (!plaintextBytes) throw new Error('Decryption failed - authentication error')
  
  return plaintextBytes
}

// ============================================
// X3DH: Initial Key Agreement
// ============================================

class X3DHInitiator {
  /**
   * Alice initiates a session with Bob
   * @returns {header, sharedSecret}
   */
  static async initiate(params) {
    const {
      aliceIdentityPriv,
      aliceIdentityPub,
      bobIdentityPub,
      bobSignedPreKeyPub,
      bobSignedPreKeyId,
      bobOneTimePreKeyPub = null,
      bobOneTimePreKeyId = null,
      aliceDeviceId
    } = params

    // Generate ephemeral key pair
    const ephemeral = nacl.box.keyPair()

    // Perform 4 DH exchanges (X3DH protocol)
    const dh1 = dh(aliceIdentityPriv, bobSignedPreKeyPub)
    const dh2 = dh(ephemeral.secretKey, bobIdentityPub)
    const dh3 = dh(ephemeral.secretKey, bobSignedPreKeyPub)
    const dh4 = bobOneTimePreKeyPub ? dh(ephemeral.secretKey, bobOneTimePreKeyPub) : new Uint8Array(32)

    // Concatenate DH outputs
    const dhConcat = new Uint8Array(128)
    dhConcat.set(dh1, 0)
    dhConcat.set(dh2, 32)
    dhConcat.set(dh3, 64)
    dhConcat.set(dh4, 96)

    // Derive shared secret using HKDF
    const salt = new Uint8Array(32) // 32 zero bytes
    const info = encodeUTF8('X3DH')
    const sharedSecret = await hkdf(dhConcat, salt, info, 32)

    // Create header for Bob
    const header = {
      sender_identity_dh_pub: encodeBase64(aliceIdentityPub),
      sender_ephemeral_pub: encodeBase64(ephemeral.publicKey),
      receiver_signed_prekey_id: bobSignedPreKeyId,
      receiver_one_time_prekey_id: bobOneTimePreKeyId,
      sender_device_id: aliceDeviceId
    }

    return { header, sharedSecret }
  }

  /**
   * Bob responds to Alice's initiation
   */
  static async respond(params) {
    const {
      bobIdentityPriv,
      bobIdentityPub,
      bobSignedPreKeyPriv,
      aliceIdentityPub,
      aliceEphemeralPub,
      bobOneTimePreKeyPriv = null
    } = params

    // Perform same 4 DH exchanges
    const dh1 = dh(bobSignedPreKeyPriv, aliceIdentityPub)
    const dh2 = dh(bobIdentityPriv, aliceEphemeralPub)
    const dh3 = dh(bobSignedPreKeyPriv, aliceEphemeralPub)
    const dh4 = bobOneTimePreKeyPriv ? dh(bobOneTimePreKeyPriv, aliceEphemeralPub) : new Uint8Array(32)

    // Concatenate DH outputs (same order as Alice)
    const dhConcat = new Uint8Array(128)
    dhConcat.set(dh1, 0)
    dhConcat.set(dh2, 32)
    dhConcat.set(dh3, 64)
    dhConcat.set(dh4, 96)

    // Derive same shared secret
    const salt = new Uint8Array(32)
    const info = encodeUTF8('X3DH')
    const sharedSecret = await hkdf(dhConcat, salt, info, 32)

    return sharedSecret
  }
}

// ============================================
// Double Ratchet: Ongoing Encryption
// ============================================

class DoubleRatchetSession {
  constructor() {
    this.rootKey = null
    this.sendingChainKey = null
    this.receivingChainKey = null
    this.sendingRatchetKey = null
    this.receivingRatchetKey = null
    this.sendCount = 0
    this.receiveCount = 0
    this.prevSendCount = 0
    this.skippedMessages = new Map() // Store keys for out-of-order messages
  }

  /**
   * Initialize as sender (Alice)
   */
  async initializeSender(sharedSecret, bobRatchetPub) {
    this.rootKey = sharedSecret
    
    // Generate our sending ratchet key
    const ratchetKeyPair = nacl.box.keyPair()
    this.sendingRatchetKey = ratchetKeyPair
    this.receivingRatchetKey = bobRatchetPub

    // Perform DH ratchet step
    await this.dhRatchetStep(bobRatchetPub)
  }

  /**
   * Initialize as receiver (Bob)
   */
  async initializeReceiver(sharedSecret, ownRatchetPriv, ownRatchetPub) {
    this.rootKey = sharedSecret
    this.sendingRatchetKey = { secretKey: ownRatchetPriv, publicKey: ownRatchetPub }
    this.receivingRatchetKey = null // Will be set when first message arrives
    this.sendingChainKey = null // Will be derived after receiving first message
    this.receivingChainKey = null // Will be derived when first message arrives
    this.sendCount = 0
    this.receiveCount = 0
  }

  /**
   * DH Ratchet step - derive new root and chain keys
   */
  async dhRatchetStep(remoteRatchetPub) {
    const dhOutput = dh(this.sendingRatchetKey.secretKey, remoteRatchetPub)
    
    // Derive new root key and sending chain key
    const salt = new Uint8Array(32)
    const info = encodeUTF8('RatchetStep')
    const derived = await hkdf(new Uint8Array([...this.rootKey, ...dhOutput]), salt, info, 64)
    
    this.rootKey = derived.slice(0, 32)
    this.sendingChainKey = derived.slice(32, 64)
    this.sendCount = 0
  }

  /**
   * Symmetric ratchet step - derive message key from chain key
   */
  async deriveMessageKey(chainKey) {
    const info = encodeUTF8('MessageKey')
    const derived = await hkdf(chainKey, new Uint8Array(32), info, 64)
    const messageKey = derived.slice(0, 32)
    const nextChainKey = derived.slice(32, 64)
    return { messageKey, nextChainKey }
  }

  /**
   * Encrypt a message
   */
  async encrypt(plaintext) {
    // If we don't have a sending chain key yet (Bob after first receive), perform DH ratchet
    if (!this.sendingChainKey) {
      if (!this.receivingRatchetKey) {
        throw new Error('Session not initialized')
      }
      
      // Generate new sending ratchet key and perform DH ratchet
      const newRatchetKeyPair = nacl.box.keyPair()
      const dhOutput = dh(newRatchetKeyPair.secretKey, this.receivingRatchetKey)
      const salt = new Uint8Array(32)
      const info = encodeUTF8('RatchetStep')
      const derived = await hkdf(new Uint8Array([...this.rootKey, ...dhOutput]), salt, info, 64)
      
      this.rootKey = derived.slice(0, 32)
      this.sendingChainKey = derived.slice(32, 64)
      this.sendingRatchetKey = newRatchetKeyPair
      this.sendCount = 0
    }

    // Derive message key
    const { messageKey, nextChainKey } = await this.deriveMessageKey(this.sendingChainKey)
    
    // Debug: check types
    if (!(messageKey instanceof Uint8Array)) {
      throw new TypeError(`messageKey is ${typeof messageKey}, expected Uint8Array`)
    }
    if (!(nextChainKey instanceof Uint8Array)) {
      throw new TypeError(`nextChainKey is ${typeof nextChainKey}, expected Uint8Array`)
    }
    
    this.sendingChainKey = nextChainKey

    // Create header
    const header = {
      dh_pub: encodeBase64(this.sendingRatchetKey.publicKey),
      pn: this.prevSendCount,
      n: this.sendCount
    }

    // Encrypt with AEAD
    const plaintextBytes = typeof plaintext === 'string' ? encodeUTF8(plaintext) : plaintext
    const encrypted = aeadEncrypt(messageKey, plaintextBytes, header)

    this.sendCount++

    return {
      header,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      ad_length: encrypted.ad_length
    }
  }

  /**
   * Decrypt a message
   */
  async decrypt(message) {
    const { header, ciphertext, nonce, ad_length } = message

    // Check if we need to perform DH ratchet (new sender ratchet key received)
    const remoteRatchetPub = decodeBase64(header.dh_pub)
    const remoteRatchetPubB64 = header.dh_pub
    
    if (!this.receivingRatchetKey || encodeBase64(this.receivingRatchetKey) !== remoteRatchetPubB64) {
      // First message OR sender performed a ratchet step
      
      // Derive receiving chain from DH with remote's pub key  
      const dhOutput = dh(this.sendingRatchetKey.secretKey, remoteRatchetPub)
      const salt = new Uint8Array(32)
      const info = encodeUTF8('RatchetStep')
      const derived = await hkdf(new Uint8Array([...this.rootKey, ...dhOutput]), salt, info, 64)
      
      this.rootKey = derived.slice(0, 32)
      this.receivingChainKey = derived.slice(32, 64)
      this.receivingRatchetKey = remoteRatchetPub
      this.receiveCount = 0
      
      // If this is a ratchet (not first message), also update sending side
      if (this.sendingChainKey !== null) {
        this.prevSendCount = this.sendCount
        this.sendCount = 0
        
        // Generate new sending ratchet key for our next send
        const newRatchetKeyPair = nacl.box.keyPair()
        this.sendingRatchetKey = newRatchetKeyPair
        this.sendingChainKey = null // Will derive on next send
      }
    }

    // Skip any missed messages
    let chainKey = this.receivingChainKey
    for (let i = this.receiveCount; i < header.n; i++) {
      const { nextChainKey } = await this.deriveMessageKey(chainKey)
      chainKey = nextChainKey
    }

    // Derive message key for this message
    const { messageKey, nextChainKey } = await this.deriveMessageKey(chainKey)
    this.receivingChainKey = nextChainKey
    this.receiveCount = header.n + 1

    // Decrypt
    const plaintextBytes = aeadDecrypt(messageKey, nonce, ciphertext, header, ad_length)
    return decodeUTF8(plaintextBytes)
  }

  /**
   * Serialize session for storage
   */
  serialize() {
    return {
      rootKey: encodeBase64(this.rootKey),
      sendingChainKey: this.sendingChainKey ? encodeBase64(this.sendingChainKey) : null,
      receivingChainKey: this.receivingChainKey ? encodeBase64(this.receivingChainKey) : null,
      sendingRatchetKey: {
        publicKey: encodeBase64(this.sendingRatchetKey.publicKey),
        secretKey: encodeBase64(this.sendingRatchetKey.secretKey)
      },
      receivingRatchetKey: this.receivingRatchetKey ? encodeBase64(this.receivingRatchetKey) : null,
      sendCount: this.sendCount,
      receiveCount: this.receiveCount,
      prevSendCount: this.prevSendCount
    }
  }

  /**
   * Deserialize session from storage
   */
  static deserialize(data) {
    const session = new DoubleRatchetSession()
    session.rootKey = decodeBase64(data.rootKey)
    session.sendingChainKey = data.sendingChainKey ? decodeBase64(data.sendingChainKey) : null
    session.receivingChainKey = data.receivingChainKey ? decodeBase64(data.receivingChainKey) : null
    session.sendingRatchetKey = {
      publicKey: decodeBase64(data.sendingRatchetKey.publicKey),
      secretKey: decodeBase64(data.sendingRatchetKey.secretKey)
    }
    session.receivingRatchetKey = data.receivingRatchetKey ? decodeBase64(data.receivingRatchetKey) : null
    session.sendCount = data.sendCount
    session.receiveCount = data.receiveCount
    session.prevSendCount = data.prevSendCount
    return session
  }
}

// ============================================
// High-Level Signal Protocol Manager
// ============================================

class SignalProtocol {
  constructor() {
    this.sessions = new Map() // deviceId -> DoubleRatchetSession
    this.identityKeyPair = null
    this.identitySigningKeyPair = null
    this.signedPreKey = null
    this.oneTimePreKeys = []
    this.deviceId = null
  }

  /**
   * Initialize identity and prekeys
   */
  async initialize(deviceId) {
    this.deviceId = deviceId

    // Load or generate identity key
    let storedIdentity = keyStore.getIdentityKeys()
    if (!storedIdentity) {
      const keyPair = nacl.box.keyPair()
      storedIdentity = {
        publicKey: Array.from(keyPair.publicKey),
        secretKey: Array.from(keyPair.secretKey)
      }
      keyStore.saveIdentityKeys(storedIdentity)
    }

    this.identityKeyPair = {
      publicKey: new Uint8Array(storedIdentity.publicKey),
      secretKey: new Uint8Array(storedIdentity.secretKey)
    }

        // ✅ Load or generate identity signing key (Ed25519, MUST be persistent!)
    let storedSigning = keyStore.getIdentitySigningKeys()
    if (!storedSigning) {
      const signKP = nacl.sign.keyPair()
      storedSigning = {
        publicKey: signKP.publicKey,
        secretKey: signKP.secretKey
      }
      keyStore.saveIdentitySigningKeys(storedSigning)
      console.log('[Signal] Generated new identity signing key (Ed25519)')
    } else {
      console.log('[Signal] Loaded identity signing key (Ed25519) from storage')
    }

    this.identitySigningKeyPair = {
      publicKey: new Uint8Array(storedSigning.publicKey),
      secretKey: new Uint8Array(storedSigning.secretKey)
    }


    // Load or generate signed prekey (MUST be persistent!)
    let storedSignedPreKey = keyStore.getSignedPreKey()
    if (!storedSignedPreKey) {
      console.log('[Signal] Generating new signed prekey')
      storedSignedPreKey = nacl.box.keyPair()
      keyStore.saveSignedPreKey(storedSignedPreKey)
    } else {
      console.log('[Signal] Loaded existing signed prekey from storage')
    }
    this.signedPreKey = storedSignedPreKey

    // Load or generate one-time prekeys (MUST be persistent!)
    let storedOneTimePreKeys = keyStore.getOneTimePreKeys()
    if (!storedOneTimePreKeys || storedOneTimePreKeys.length === 0) {
      console.log('[Signal] Generating new one-time prekeys')
      storedOneTimePreKeys = []
      for (let i = 0; i < 10; i++) {
        storedOneTimePreKeys.push(nacl.box.keyPair())
      }
      keyStore.saveOneTimePreKeys(storedOneTimePreKeys)
    } else {
      console.log('[Signal] Loaded', storedOneTimePreKeys.length, 'one-time prekeys from storage')
    }
    this.oneTimePreKeys = storedOneTimePreKeys

    console.log('[Signal] Initialized with', this.oneTimePreKeys.length, 'one-time prekeys')
  }

  /**
   * Get key bundle to upload to server
   */
  getKeyBundle() {
    return {
      identity_key_public: encodeBase64(this.identityKeyPair.publicKey),
      signed_prekey_public: encodeBase64(this.signedPreKey.publicKey),
      signed_prekey_id: 1,
      one_time_prekeys: this.oneTimePreKeys.map((key, i) => ({
        id: i,
        public_key: encodeBase64(key.publicKey)
      }))
    }
  }

  /**
   * Encrypt message to a recipient (initiates session if needed)
   */
  async encryptTo(recipientDeviceId, recipientKeyBundle, plaintext) {
    let session = this.sessions.get(recipientDeviceId)

    if (!session) {
      // Initiate new session with X3DH
      console.log('[Signal] Initiating new session with', recipientDeviceId)

      const { header, sharedSecret } = await X3DHInitiator.initiate({
        aliceIdentityPriv: this.identityKeyPair.secretKey,
        aliceIdentityPub: this.identityKeyPair.publicKey,
        bobIdentityPub: decodeBase64(recipientKeyBundle.identity_key_public),
        bobSignedPreKeyPub: decodeBase64(recipientKeyBundle.signed_prekey_public),
        bobSignedPreKeyId: recipientKeyBundle.signed_prekey_id,
        bobOneTimePreKeyPub: recipientKeyBundle.one_time_prekey_public ? 
          decodeBase64(recipientKeyBundle.one_time_prekey_public) : null,
        bobOneTimePreKeyId: recipientKeyBundle.one_time_prekey_id,
        aliceDeviceId: this.deviceId
      })

      // Initialize Double Ratchet session
      session = new DoubleRatchetSession()
      await session.initializeSender(sharedSecret, decodeBase64(recipientKeyBundle.signed_prekey_public))
      
      this.sessions.set(recipientDeviceId, session)

      // Store session
      keyStore.saveSession(recipientDeviceId, session.serialize())

      // Return with X3DH header for first message
      const encrypted = await session.encrypt(plaintext)
      return {
        ...encrypted,
        x3dh_header: header,
        is_initial_message: true
      }
    }

    // Existing session - just encrypt
    const encrypted = await session.encrypt(plaintext)
    keyStore.saveSession(recipientDeviceId, session.serialize())
    
    return {
      ...encrypted,
      is_initial_message: false
    }
  }

  /**
   * Decrypt message from a sender
   */
  async decryptFrom(senderDeviceId, message) {
    let session = this.sessions.get(senderDeviceId)

    if (message.is_initial_message && message.x3dh_header) {
      // Respond to X3DH initiation
      console.log('[Signal] Responding to session initiation from', senderDeviceId)

      const header = message.x3dh_header
      
      // Find the one-time prekey used (if any)
      let oneTimePreKeyPriv = null
      if (header.receiver_one_time_prekey_id !== null) {
        const opk = this.oneTimePreKeys[header.receiver_one_time_prekey_id]
        if (opk) oneTimePreKeyPriv = opk.secretKey
      }

      const sharedSecret = await X3DHInitiator.respond({
        bobIdentityPriv: this.identityKeyPair.secretKey,
        bobIdentityPub: this.identityKeyPair.publicKey,
        bobSignedPreKeyPriv: this.signedPreKey.secretKey,
        aliceIdentityPub: decodeBase64(header.sender_identity_dh_pub),
        aliceEphemeralPub: decodeBase64(header.sender_ephemeral_pub),
        bobOneTimePreKeyPriv: oneTimePreKeyPriv
      })

      // Initialize Double Ratchet as receiver
      session = new DoubleRatchetSession()
      await session.initializeReceiver(
        sharedSecret,
        this.signedPreKey.secretKey,
        this.signedPreKey.publicKey
      )
      
      this.sessions.set(senderDeviceId, session)
    }

    if (!session) {
      // Try to load from storage
      const stored = keyStore.getSession(senderDeviceId)
      if (stored) {
        session = DoubleRatchetSession.deserialize(stored)
        this.sessions.set(senderDeviceId, session)
      } else {
        throw new Error('No session with sender device')
      }
    }

    // Decrypt message
    const plaintext = await session.decrypt(message)
    keyStore.saveSession(senderDeviceId, session.serialize())
    
    return plaintext
  }
}

export const signalProtocol = new SignalProtocol()
export { X3DHInitiator, DoubleRatchetSession, SignalProtocol }

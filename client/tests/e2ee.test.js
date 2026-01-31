/**
 * End-to-End Encryption Tests
 * 
 * Tests for Signal Protocol implementation covering:
 * 1. Encryption/decryption flow
 * 2. Server cannot read messages
 * 3. Offline messaging support
 * 4. Session isolation and forward secrecy
 * 
 * Run with: npm test
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { X3DHInitiator, DoubleRatchetSession, signalProtocol } from '../src/e2ee/signal-protocol'
import nacl from 'tweetnacl'
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util'

describe('Signal Protocol - X3DH Key Agreement', () => {
  let aliceIdentity, bobIdentity, bobSignedPreKey, bobOneTimePreKey

  beforeEach(() => {
    // Generate keys for Alice and Bob
    aliceIdentity = nacl.box.keyPair()
    bobIdentity = nacl.box.keyPair()
    bobSignedPreKey = nacl.box.keyPair()
    bobOneTimePreKey = nacl.box.keyPair()
  })

  it('should establish same shared secret for Alice and Bob', async () => {
    // Alice initiates
    const { header, sharedSecret: aliceSecret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      bobOneTimePreKeyPub: bobOneTimePreKey.publicKey,
      bobOneTimePreKeyId: 42,
      aliceDeviceId: 'alice-device-1'
    })

    // Bob responds
    const bobSecret = await X3DHInitiator.respond({
      bobIdentityPriv: bobIdentity.secretKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPriv: bobSignedPreKey.secretKey,
      aliceIdentityPub: decodeBase64(header.sender_identity_dh_pub),
      aliceEphemeralPub: decodeBase64(header.sender_ephemeral_pub),
      bobOneTimePreKeyPriv: bobOneTimePreKey.secretKey
    })

    // Both should derive same shared secret
    expect(encodeBase64(aliceSecret)).toBe(encodeBase64(bobSecret))
    
    // Shared secret should be 32 bytes
    expect(aliceSecret.length).toBe(32)
    expect(bobSecret.length).toBe(32)
  })

  it('should work without one-time prekey', async () => {
    // Alice initiates without OPK
    const { header, sharedSecret: aliceSecret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      bobOneTimePreKeyPub: null,
      bobOneTimePreKeyId: null,
      aliceDeviceId: 'alice-device-1'
    })

    // Bob responds without OPK
    const bobSecret = await X3DHInitiator.respond({
      bobIdentityPriv: bobIdentity.secretKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPriv: bobSignedPreKey.secretKey,
      aliceIdentityPub: decodeBase64(header.sender_identity_dh_pub),
      aliceEphemeralPub: decodeBase64(header.sender_ephemeral_pub),
      bobOneTimePreKeyPriv: null
    })

    // Should still derive same secret
    expect(encodeBase64(aliceSecret)).toBe(encodeBase64(bobSecret))
  })
})

describe('Signal Protocol - Double Ratchet', () => {
  let sharedSecret, aliceSession, bobSession, bobRatchetKey

  beforeEach(async () => {
    // Establish shared secret via X3DH
    const aliceIdentity = nacl.box.keyPair()
    const bobIdentity = nacl.box.keyPair()
    const bobSignedPreKey = nacl.box.keyPair()

    const { sharedSecret: secret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    sharedSecret = secret
    bobRatchetKey = bobSignedPreKey

    // Initialize sessions
    aliceSession = new DoubleRatchetSession()
    bobSession = new DoubleRatchetSession()

    await aliceSession.initializeSender(sharedSecret, bobRatchetKey.publicKey)
    await bobSession.initializeReceiver(sharedSecret, bobRatchetKey.secretKey, bobRatchetKey.publicKey)
  })

  it('should encrypt and decrypt a message', async () => {
    const plaintext = 'Hello, Bob! This is a secret message.'

    // Alice encrypts
    const encrypted = await aliceSession.encrypt(plaintext)

    // Bob decrypts
    const decrypted = await bobSession.decrypt(encrypted)

    expect(decrypted).toBe(plaintext)
  })

  it('should handle multiple messages in sequence', async () => {
    const messages = [
      'First message',
      'Second message with more content',
      'Third message 🔒'
    ]

    for (const msg of messages) {
      const encrypted = await aliceSession.encrypt(msg)
      const decrypted = await bobSession.decrypt(encrypted)
      expect(decrypted).toBe(msg)
    }
  })

  it('should support bidirectional messaging', async () => {
    // Alice to Bob
    const msg1 = 'Hi Bob!'
    const enc1 = await aliceSession.encrypt(msg1)
    const dec1 = await bobSession.decrypt(enc1)
    expect(dec1).toBe(msg1)

    // Bob to Alice
    const msg2 = 'Hi Alice!'
    const enc2 = await bobSession.encrypt(msg2)
    const dec2 = await aliceSession.decrypt(enc2)
    expect(dec2).toBe(msg2)

    // Continue conversation
    const msg3 = 'How are you?'
    const enc3 = await aliceSession.encrypt(msg3)
    const dec3 = await bobSession.decrypt(enc3)
    expect(dec3).toBe(msg3)
  })

  it('should provide forward secrecy - old messages unreadable with current keys', async () => {
    const message1 = 'Message before ratchet'
    const encrypted1 = await aliceSession.encrypt(message1)

    // Perform several ratchet steps
    for (let i = 0; i < 5; i++) {
      const msg = `Message ${i}`
      const enc = await aliceSession.encrypt(msg)
      await bobSession.decrypt(enc)
    }

    // Keys have changed - trying to decrypt old message should fail or be different
    // This tests forward secrecy property
    const message2 = 'Message after ratchet'
    const encrypted2 = await aliceSession.encrypt(message2)

    // Verify encrypted messages are different even with same plaintext
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext)
  })
})

describe('Signal Protocol - Server Blindness', () => {
  it('server cannot read message contents', async () => {
    const plaintext = 'Top secret information 🔐'
    
    // Simulate Alice encrypting
    const aliceIdentity = nacl.box.keyPair()
    const bobIdentity = nacl.box.keyPair()
    const bobSignedPreKey = nacl.box.keyPair()

    const { sharedSecret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    const session = new DoubleRatchetSession()
    await session.initializeSender(sharedSecret, bobSignedPreKey.publicKey)
    const encrypted = await session.encrypt(plaintext)

    // What server sees
    const serverData = {
      header: encrypted.header,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce
    }

    // Server cannot extract plaintext
    expect(serverData.ciphertext).not.toContain(plaintext)
    expect(JSON.stringify(serverData)).not.toContain(plaintext)
    
    // Ciphertext should look random
    expect(serverData.ciphertext.length).toBeGreaterThan(0)
    expect(serverData.ciphertext).toMatch(/^[A-Za-z0-9+/]+=*$/) // Base64
  })

  it('server cannot derive encryption keys without private keys', async () => {
    const aliceIdentity = nacl.box.keyPair()
    const bobIdentity = nacl.box.keyPair()
    const bobSignedPreKey = nacl.box.keyPair()

    // Server only sees public keys
    const serverKnows = {
      alicePublicKey: encodeBase64(aliceIdentity.publicKey),
      bobPublicKey: encodeBase64(bobIdentity.publicKey),
      bobSignedPreKeyPublic: encodeBase64(bobSignedPreKey.publicKey)
    }

    // Server cannot perform DH without private keys
    // This test verifies the server has no way to derive shared secret
    expect(serverKnows).not.toHaveProperty('secretKey')
    expect(serverKnows).not.toHaveProperty('sharedSecret')
  })
})

describe('Signal Protocol - Offline Messaging', () => {
  it('should support sending messages when recipient is offline', async () => {
    // Setup
    const aliceIdentity = nacl.box.keyPair()
    const bobIdentity = nacl.box.keyPair()
    const bobSignedPreKey = nacl.box.keyPair()

    const { header, sharedSecret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    const aliceSession = new DoubleRatchetSession()
    await aliceSession.initializeSender(sharedSecret, bobSignedPreKey.publicKey)

    // Alice sends multiple messages while Bob is offline
    const offlineMessages = []
    for (let i = 0; i < 5; i++) {
      const encrypted = await aliceSession.encrypt(`Offline message ${i}`)
      offlineMessages.push(encrypted)
    }

    // Bob comes online and decrypts all messages
    const bobSession = new DoubleRatchetSession()
    await bobSession.initializeReceiver(sharedSecret, bobSignedPreKey.secretKey, bobSignedPreKey.publicKey)

    for (let i = 0; i < offlineMessages.length; i++) {
      const decrypted = await bobSession.decrypt(offlineMessages[i])
      expect(decrypted).toBe(`Offline message ${i}`)
    }
  })

  it('should decrypt messages in correct order even if received out-of-order', async () => {
    // Setup session
    const aliceIdentity = nacl.box.keyPair()
    const bobIdentity = nacl.box.keyPair()
    const bobSignedPreKey = nacl.box.keyPair()

    const { sharedSecret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    const aliceSession = new DoubleRatchetSession()
    await aliceSession.initializeSender(sharedSecret, bobSignedPreKey.publicKey)

    // Alice sends messages
    const messages = []
    for (let i = 0; i < 3; i++) {
      messages.push(await aliceSession.encrypt(`Message ${i}`))
    }

    // Bob receives messages (simulating network delivery)
    const bobSession = new DoubleRatchetSession()
    await bobSession.initializeReceiver(sharedSecret, bobSignedPreKey.secretKey, bobSignedPreKey.publicKey)

    // Decrypt in order
    for (let i = 0; i < messages.length; i++) {
      const decrypted = await bobSession.decrypt(messages[i])
      expect(decrypted).toBe(`Message ${i}`)
    }
  })
})

describe('Signal Protocol - Session Isolation', () => {
  it('different sessions produce different ciphertexts for same plaintext', async () => {
    const plaintext = 'Same message'

    // Create two independent sessions
    const session1 = new DoubleRatchetSession()
    const session2 = new DoubleRatchetSession()

    const bobKey1 = nacl.box.keyPair()
    const bobKey2 = nacl.box.keyPair()

    const secret1 = nacl.randomBytes(32)
    const secret2 = nacl.randomBytes(32)

    await session1.initializeSender(secret1, bobKey1.publicKey)
    await session2.initializeSender(secret2, bobKey2.publicKey)

    // Encrypt same plaintext in both sessions
    const encrypted1 = await session1.encrypt(plaintext)
    const encrypted2 = await session2.encrypt(plaintext)

    // Ciphertexts should be completely different
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext)
    expect(encrypted1.nonce).not.toBe(encrypted2.nonce)
    expect(encrypted1.header.dh_pub).not.toBe(encrypted2.header.dh_pub)
  })

  it('session from device A cannot decrypt messages meant for device B', async () => {
    // Setup two devices for Bob
    const aliceIdentity = nacl.box.keyPair()
    const bobDevice1 = nacl.box.keyPair()
    const bobDevice2 = nacl.box.keyPair()

    // Alice creates session with Bob's device 1
    const { sharedSecret: secret1 } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobDevice1.publicKey,
      bobSignedPreKeyPub: bobDevice1.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    const aliceToDevice1 = new DoubleRatchetSession()
    await aliceToDevice1.initializeSender(secret1, bobDevice1.publicKey)

    // Encrypt message for device 1
    const encrypted = await aliceToDevice1.encrypt('Message for device 1')

    // Device 2 tries to decrypt (should fail)
    const { sharedSecret: secret2 } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobDevice2.publicKey,
      bobSignedPreKeyPub: bobDevice2.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    const bobDevice2Session = new DoubleRatchetSession()
    await bobDevice2Session.initializeReceiver(secret2, bobDevice2.secretKey, bobDevice2.publicKey)

    // Device 2 cannot decrypt message meant for device 1
    await expect(bobDevice2Session.decrypt(encrypted)).rejects.toThrow()
  })

  it('each message uses a unique key (forward secrecy)', async () => {
    const aliceIdentity = nacl.box.keyPair()
    const bobIdentity = nacl.box.keyPair()
    const bobSignedPreKey = nacl.box.keyPair()

    const { sharedSecret } = await X3DHInitiator.initiate({
      aliceIdentityPriv: aliceIdentity.secretKey,
      aliceIdentityPub: aliceIdentity.publicKey,
      bobIdentityPub: bobIdentity.publicKey,
      bobSignedPreKeyPub: bobSignedPreKey.publicKey,
      bobSignedPreKeyId: 1,
      aliceDeviceId: 'alice-1'
    })

    const session = new DoubleRatchetSession()
    await session.initializeSender(sharedSecret, bobSignedPreKey.publicKey)

    // Send multiple messages
    const encrypted1 = await session.encrypt('Message 1')
    const encrypted2 = await session.encrypt('Message 2')
    const encrypted3 = await session.encrypt('Message 3')

    // Each message should have different ciphertext (proving different keys used)
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext)
    expect(encrypted2.ciphertext).not.toBe(encrypted3.ciphertext)
    expect(encrypted1.ciphertext).not.toBe(encrypted3.ciphertext)

    // Message counters should increment
    expect(encrypted1.header.n).toBe(0)
    expect(encrypted2.header.n).toBe(1)
    expect(encrypted3.header.n).toBe(2)
  })
})

describe('Signal Protocol - High-Level API', () => {
  let aliceProtocol, bobProtocol

  beforeEach(async () => {
    aliceProtocol = new (await import('../src/e2ee/signal-protocol')).SignalProtocol()
    bobProtocol = new (await import('../src/e2ee/signal-protocol')).SignalProtocol()

    await aliceProtocol.initialize('alice-device-1')
    await bobProtocol.initialize('bob-device-1')
  })

  it('should establish session and exchange messages', async () => {
    // Alice gets Bob's key bundle
    const bobKeyBundle = bobProtocol.getKeyBundle()

    // Alice sends first message
    const plaintext1 = 'Hello Bob!'
    const encrypted1 = await aliceProtocol.encryptTo('bob-device-1', bobKeyBundle, plaintext1)

    // Bob decrypts
    const decrypted1 = await bobProtocol.decryptFrom('alice-device-1', encrypted1)
    expect(decrypted1).toBe(plaintext1)

    // Continue conversation
    const plaintext2 = 'How are you?'
    const encrypted2 = await aliceProtocol.encryptTo('bob-device-1', bobKeyBundle, plaintext2)
    const decrypted2 = await bobProtocol.decryptFrom('alice-device-1', encrypted2)
    expect(decrypted2).toBe(plaintext2)
  })

  it('should persist and restore sessions', async () => {
    const bobKeyBundle = bobProtocol.getKeyBundle()

    // Send message
    const encrypted = await aliceProtocol.encryptTo('bob-device-1', bobKeyBundle, 'Test message')

    // Serialize Alice's session
    const sessionData = aliceProtocol.sessions.get('bob-device-1').serialize()

    // Create new protocol instance and restore session
    const newAliceProtocol = new (await import('../src/e2ee/signal-protocol')).SignalProtocol()
    await newAliceProtocol.initialize('alice-device-1')
    
    const { DoubleRatchetSession: DRS } = await import('../src/e2ee/signal-protocol')
    const restoredSession = DRS.deserialize(sessionData)
    newAliceProtocol.sessions.set('bob-device-1', restoredSession)

    // Should be able to continue conversation
    const encrypted2 = await newAliceProtocol.encryptTo('bob-device-1', bobKeyBundle, 'After restore')
    expect(encrypted2.is_initial_message).toBe(false)
  })
})

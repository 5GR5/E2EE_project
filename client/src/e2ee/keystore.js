// Simple localStorage-based key storage
export class KeyStore {
  /**
   * Creates a new KeyStore instance with localStorage backing.
   */
  constructor() {
    this.prefix = 'e2ee_'
  }

  /**
   * Saves the X25519 identity key pair to localStorage.
   * @param {Object} keys - The identity key pair object
   */
  saveIdentityKeys(keys) {
    localStorage.setItem(this.prefix + 'identity', JSON.stringify(keys))
  }

  /**
   * Retrieves the X25519 identity key pair from localStorage.
   * @returns {Object|null} The identity key pair or null if not found
   */
  getIdentityKeys() {
    const data = localStorage.getItem(this.prefix + 'identity')
    return data ? JSON.parse(data) : null
  }

  /**
   * Saves the Double Ratchet session state for a peer device.
   * @param {string} peerDeviceId - The device ID of the peer
   * @param {Object} sessionState - The session state to save
   */
  saveSession(peerDeviceId, sessionState) {
    localStorage.setItem(this.prefix + 'session_' + peerDeviceId, JSON.stringify(sessionState))
  }

  /**
   * Retrieves the Double Ratchet session state for a peer device.
   * @param {string} peerDeviceId - The device ID of the peer
   * @returns {Object|null} The session state or null if not found
   */
  getSession(peerDeviceId) {
    const data = localStorage.getItem(this.prefix + 'session_' + peerDeviceId)
    return data ? JSON.parse(data) : null
  }

  /**
   * Saves the current device ID.
   * @param {string} deviceId - The device ID to save
   */
  saveDeviceId(deviceId) {
    localStorage.setItem(this.prefix + 'device_id', deviceId)
  }

  /**
   * Retrieves the current device ID.
   * @returns {string|null} The device ID or null if not set
   */
  getDeviceId() {
    return localStorage.getItem(this.prefix + 'device_id')
  }

  /**
   * Saves the Ed25519 signing key pair.
   * @param {Object} keyPair - The signing key pair with publicKey and secretKey Uint8Arrays
   */
  saveSigningKey(keyPair) {
    localStorage.setItem(this.prefix + 'signing_key', JSON.stringify({
      publicKey: Array.from(keyPair.publicKey),
      secretKey: Array.from(keyPair.secretKey)
    }))
  }

  /**
   * Retrieves the Ed25519 signing key pair.
   * @returns {Object|null} The signing key pair or null if not found
   */
  getSigningKey() {
    const data = localStorage.getItem(this.prefix + 'signing_key')
    if (!data) return null
    const parsed = JSON.parse(data)
    return {
      publicKey: new Uint8Array(parsed.publicKey),
      secretKey: new Uint8Array(parsed.secretKey)
    }
  }

  /**
   * Saves the signed prekey pair.
   * @param {Object} keyPair - The signed prekey pair with publicKey and secretKey Uint8Arrays
   */
  saveSignedPreKey(keyPair) {
    localStorage.setItem(this.prefix + 'signed_prekey', JSON.stringify({
      publicKey: Array.from(keyPair.publicKey),
      secretKey: Array.from(keyPair.secretKey)
    }))
  }

  /**
   * Retrieves the signed prekey pair.
   * @returns {Object|null} The signed prekey pair or null if not found
   */
  getSignedPreKey() {
    const data = localStorage.getItem(this.prefix + 'signed_prekey')
    if (!data) return null
    const parsed = JSON.parse(data)
    return {
      publicKey: new Uint8Array(parsed.publicKey),
      secretKey: new Uint8Array(parsed.secretKey)
    }
  }

  /**
   * Saves the one-time prekey pairs.
   * @param {Array} keyPairs - Array of one-time prekey pairs
   */
  saveOneTimePreKeys(keyPairs) {
    localStorage.setItem(this.prefix + 'one_time_prekeys', JSON.stringify(
      keyPairs.map(kp => ({
        publicKey: Array.from(kp.publicKey),
        secretKey: Array.from(kp.secretKey)
      }))
    ))
  }

  /**
   * Retrieves the one-time prekey pairs.
   * @returns {Array|null} Array of one-time prekey pairs or null if not found
   */
  getOneTimePreKeys() {
    const data = localStorage.getItem(this.prefix + 'one_time_prekeys')
    if (!data) return null
    const parsed = JSON.parse(data)
    return parsed.map(kp => ({
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey)
    }))
  }

  /**
   * Clears all stored keys and sessions from localStorage.
   */
  clear() {
    const keys = Object.keys(localStorage)
    keys.forEach(key => {
      if (key.startsWith(this.prefix)) {
        localStorage.removeItem(key)
      }
    })
  }
}

export const keyStore = new KeyStore()

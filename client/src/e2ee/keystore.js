// Simple localStorage-based key storage
export class KeyStore {
  constructor() {
    this.prefix = 'e2ee_'
  }

  // Identity keys (long-term)
  saveIdentityKeys(keys) {
    localStorage.setItem(this.prefix + 'identity', JSON.stringify(keys))
  }

  getIdentityKeys() {
    const data = localStorage.getItem(this.prefix + 'identity')
    return data ? JSON.parse(data) : null
  }

    // Identity signing keys (Ed25519 long-term)
  saveIdentitySigningKeys(keys) {
    localStorage.setItem(this.prefix + 'identity_signing', JSON.stringify({
      publicKey: Array.from(keys.publicKey),
      secretKey: Array.from(keys.secretKey)
    }))
  }

  getIdentitySigningKeys() {
    const data = localStorage.getItem(this.prefix + 'identity_signing')
    if (!data) return null
    const parsed = JSON.parse(data)
    return {
      publicKey: new Uint8Array(parsed.publicKey),
      secretKey: new Uint8Array(parsed.secretKey)
    }
  }


  // Session state per peer device
  saveSession(peerDeviceId, sessionState) {
    localStorage.setItem(this.prefix + 'session_' + peerDeviceId, JSON.stringify(sessionState))
  }

  getSession(peerDeviceId) {
    const data = localStorage.getItem(this.prefix + 'session_' + peerDeviceId)
    return data ? JSON.parse(data) : null
  }

  // Device ID
  saveDeviceId(deviceId) {
    localStorage.setItem(this.prefix + 'device_id', deviceId)
  }

  getDeviceId() {
    return localStorage.getItem(this.prefix + 'device_id')
  }

  // Signed prekey
  saveSignedPreKey(keyPair) {
    localStorage.setItem(this.prefix + 'signed_prekey', JSON.stringify({
      publicKey: Array.from(keyPair.publicKey),
      secretKey: Array.from(keyPair.secretKey)
    }))
  }

  getSignedPreKey() {
    const data = localStorage.getItem(this.prefix + 'signed_prekey')
    if (!data) return null
    const parsed = JSON.parse(data)
    return {
      publicKey: new Uint8Array(parsed.publicKey),
      secretKey: new Uint8Array(parsed.secretKey)
    }
  }

  // One-time prekeys
  saveOneTimePreKeys(keyPairs) {
    localStorage.setItem(this.prefix + 'one_time_prekeys', JSON.stringify(
      keyPairs.map(kp => ({
        publicKey: Array.from(kp.publicKey),
        secretKey: Array.from(kp.secretKey)
      }))
    ))
  }

  getOneTimePreKeys() {
    const data = localStorage.getItem(this.prefix + 'one_time_prekeys')
    if (!data) return null
    const parsed = JSON.parse(data)
    return parsed.map(kp => ({
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey)
    }))
  }

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

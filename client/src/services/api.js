// API service for HTTP calls to the server
import { wsService } from '/services/Websocket'


const API_URL = 'http://localhost:8000'

export const api = {
  // Authentication
  async register(username, password) {
    const res = await fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })

    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Registration failed')
    }

    return res.json() // { access_token, token_type }
  },

  async login(username, password) {
    const res = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })

    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Login failed')
    }

    return res.json() // { access_token, token_type }
  },

  // Device management
async createDevice(token, deviceName, identityKeyPublic, identitySigningPublic) {
  const res = await fetch(`${API_URL}/devices`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      device_name: deviceName || 'web',
      identity_key_public: identityKeyPublic || 'placeholder_identity_key',
      identity_signing_public: identitySigningPublic || 'placeholder_signing_key'
    })
  })

  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }))
    throw new Error(error.detail || 'Device creation failed')
  }

  return res.json() // { id, device_name }
},


  // Keys (for future E2EE integration)
  async uploadKeys(token, deviceId, signedPreKey, oneTimePreKeys) {
    const res = await fetch(`${API_URL}/keys/upload`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        device_id: deviceId,
        signed_prekey: signedPreKey,
        one_time_prekeys: oneTimePreKeys
      })
    })

    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Key upload failed')
    }

    return res.json()
  },

  async getKeyBundle(token, targetUserId) {
    const res = await fetch(`${API_URL}/keys/bundle/${targetUserId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })

    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Failed to get key bundle')
    }

    return res.json()
  },

  // Get all users
  async getUsers(token) {
    const res = await fetch(`${API_URL}/users`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })

    if (!res.ok) {
      const error = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }))
      throw new Error(`${res.status}: ${error.detail || 'Failed to get users'}`)
    }

    return res.json()
  },

  // Send message
  async sendMessage(token, toUserId, text) {
    const res = await fetch(`${API_URL}/messages/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ to_user_id: toUserId, text })
    })

    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Failed to send message')
    }

    return res.json()
  },

  // Get messages with another user
  async getMessages(token, otherUserId) {
    const res = await fetch(`${API_URL}/messages/${otherUserId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })

    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Failed to get messages')
    }

    return res.json()
  }
}

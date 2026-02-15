// WebSocket service for real-time messaging with E2EE
import { signalProtocol } from '../e2ee/signal-protocol'

const WS_URL = 'ws://localhost:8000/ws'
const API_URL = 'http://localhost:8000'

class WebSocketService {
  constructor() {
    this.ws = null
    this.token = null
    this.deviceId = null
    this.messageHandlers = []
    this.statusHandlers = []
  }

  connect(token, deviceId) {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      console.log('WebSocket already connected')
      return
    }

    this.token = token
    this.deviceId = deviceId

    // Initialize Signal Protocol
    signalProtocol.initialize(deviceId).then(() => {
      console.log('[WS] Signal Protocol initialized')
    })

    const url = `${WS_URL}?token=${token}&device_id=${deviceId}`
    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      console.log('WebSocket connected')
      this.notifyStatus('connected')
    }

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        console.log('WebSocket message received:', data)

        // Decrypt message if it's encrypted (handle both 'deliver' from server and 'message' type)
        if ((data.type === 'deliver' || data.type === 'message') && data.header && data.ciphertext) {
          this.decryptAndNotify(data)
        } else {
          this.notifyMessage(data)
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err)
      }
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      this.notifyStatus('error')
    }

    this.ws.onclose = () => {
      console.log('WebSocket disconnected')
      this.notifyStatus('disconnected')
    }
  }

  /**
   * Decrypt received message and notify handlers
   */
  async decryptAndNotify(data) {
    try {
      const senderDeviceId = data.from_device_id
      const message = {
        header: data.header,
        ciphertext: data.ciphertext,
        nonce: data.nonce,
        ad_length: data.ad_length,
        is_initial_message: data.is_initial_message || false,
        x3dh_header: data.x3dh_header || null
      }

      const plaintext = await signalProtocol.decryptFrom(senderDeviceId, message)
      
      // Notify with decrypted message
      this.notifyMessage({
        type: 'message',
        from_device_id: senderDeviceId,
        from_user_id: data.from_user_id,
        from_device_name: data.from_device_name,
        text: plaintext,
        timestamp: data.timestamp || new Date().toISOString()
      })
    } catch (err) {
      console.error('[WS] Failed to decrypt message:', err)
    }
  }

  disconnect() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  /**
   * Send encrypted message using Signal Protocol
   */
  async sendEncrypted(toDeviceId, toUserId, plaintext) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected')
    }

    // Only fetch the key bundle when no session exists (avoids consuming one-time prekeys unnecessarily)
    const hasSession = signalProtocol.sessions.has(toDeviceId) || !!signalProtocol.loadSessionFromStorage(toDeviceId)
    const keyBundle = hasSession ? null : await this.fetchKeyBundle(toUserId, toDeviceId)

    // Encrypt using Signal Protocol
    const encrypted = await signalProtocol.encryptTo(toDeviceId, keyBundle, plaintext)

    // Generate message ID
    const messageId = crypto.randomUUID()

    // Send encrypted message
    const payload = {
      type: 'send',
      to_device_id: toDeviceId,
      message_id: messageId,
      header: encrypted.header,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      ad_length: encrypted.ad_length,
      is_initial_message: encrypted.is_initial_message,
      x3dh_header: encrypted.x3dh_header || null
    }

    console.log('[WS] Sending encrypted message:', messageId)
    this.ws.send(JSON.stringify(payload))
    return messageId
  }

  /**
   * Fetch recipient's key bundle from server
   */
  async fetchKeyBundle(userId, deviceId) {
    // Use correct endpoint: /keys/bundle/{user_id}?device_id={device_id}
    const url = `${API_URL}/keys/bundle/${userId}${deviceId ? `?device_id=${deviceId}` : ''}`
    console.log('[WS] Fetching key bundle from:', url)

    try {
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${this.token}` }
      })

      if (!response.ok) {
        const errorText = await response.text()
        console.error('[WS] Key bundle fetch failed:', response.status, errorText)

        // Fallback: get basic device info
        console.log('[WS] Trying fallback: get device info')
        const devicesResponse = await fetch(`${API_URL}/users/${userId}/devices`, {
          headers: { 'Authorization': `Bearer ${this.token}` }
        })

        if (!devicesResponse.ok) {
          const fallbackError = await devicesResponse.text()
          console.error('[WS] Fallback also failed:', fallbackError)
          throw new Error(`Failed to fetch key bundle: ${response.status}`)
        }

        const { devices } = await devicesResponse.json()
        console.log('[WS] Got devices:', devices)
        const device = devices.find(d => d.device_id === deviceId || d.id === deviceId)

        if (!device) throw new Error('Device not found')

        return {
          identity_key_public: device.identity_key_public,
          signed_prekey_public: device.identity_key_public, // Fallback
          signed_prekey_id: 1,
          one_time_prekey_public: null,
          one_time_prekey_id: null
        }
      }

      const bundle = await response.json()
      console.log('[WS] Got key bundle:', bundle)
      return bundle
    } catch (err) {
      console.error('[WS] fetchKeyBundle exception:', err)
      throw err
    }
  }

  /**
   * Send encrypted message to all devices of a user
   */
  async sendMessageToUser(toUserId, text) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected')
    }
    if (!this.token) {
      throw new Error('Missing token')
    }

    const { devices } = await listUserDevices(toUserId, this.token)
    if (!devices || devices.length === 0) {
      throw new Error('Target user has no devices')
    }

    // Send encrypted message to all recipient devices
    for (const dev of devices) {
      const deviceId = dev.device_id || dev.id
      try {
        await this.sendEncrypted(deviceId, toUserId, text)
        console.log('[WS] Encrypted message sent to device:', deviceId)
      } catch (err) {
        console.error('[WS] Failed to send to device:', deviceId, err)
        // Continue to other devices even if one fails
      }
    }

    return true
  }

  // Legacy method for backwards compatibility (now uses encryption)
  sendPlaintext(toDeviceId, text) {
    console.warn('[WS] sendPlaintext is deprecated, use sendEncrypted')
    return this.sendEncrypted(toDeviceId, null, text)
  }

  onMessage(handler) {
    this.messageHandlers.push(handler)
  }

  onStatus(handler) {
    this.statusHandlers.push(handler)
  }

  notifyMessage(data) {
    this.messageHandlers.forEach(handler => handler(data))
  }

  notifyStatus(status) {
    this.statusHandlers.forEach(handler => handler(status))
  }

  removeHandlers() {
    this.messageHandlers = []
    this.statusHandlers = []
  }
}

export const wsService = new WebSocketService()

export async function listUserDevices(userId, token) {
  const res = await fetch(`${API_URL}/users/${userId}/devices`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error("Failed to fetch user devices")
  return await res.json() // { user_id, devices:[{device_id, device_name}] }
}


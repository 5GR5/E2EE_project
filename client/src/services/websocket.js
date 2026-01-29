// WebSocket service for real-time messaging

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
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected')
      return
    }

    this.token = token
    this.deviceId = deviceId

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
        this.notifyMessage(data)
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

  disconnect() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

sendMessage(toDeviceId, header, ciphertext) {
  if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
    throw new Error('WebSocket not connected')
  }

  // Generate a message_id (UUID). Modern browsers support crypto.randomUUID()
  const messageId = crypto.randomUUID()

  const payload = {
    type: 'send',
    to_device_id: toDeviceId,
    message_id: messageId,
    header,
    ciphertext
  }

  this.ws.send(JSON.stringify(payload))
  return messageId
}

sendPlaintext(toDeviceId, text) {
  const header = { plaintext: true }
  const ciphertext = text
  return this.sendMessage(toDeviceId, header, ciphertext)
}

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

  for (const dev of devices) {
    // server returns {device_id: "..."}
    this.sendPlaintext(dev.device_id, text)
  }

  return true
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
  });
  if (!res.ok) throw new Error("Failed to fetch user devices");
  return await res.json(); // { user_id, devices:[{device_id, device_name}] }
}


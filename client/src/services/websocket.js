// WebSocket service for real-time messaging

const WS_URL = 'ws://localhost:8000/ws'

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

  sendMessage(toDeviceId, message) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.error('WebSocket not connected')
      return false
    }

    const payload = {
      type: 'send',
      to_device_id: toDeviceId,
      // For now, send plain text (encryption will be added later)
      header: { plaintext: true },
      ciphertext: message
    }

    this.ws.send(JSON.stringify(payload))
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

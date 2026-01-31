// localStorage service for persisting data

const STORAGE_KEYS = {
  TOKEN: 'auth_token_v2',
  USERNAME: 'username_v2',
  DEVICE_ID: 'device_id_v2',
  USER_ID: 'user_id_v2',
  MESSAGES: 'messages_v2',
  USERS: 'users_v2'
}

export const storage = {
  // Auth
  saveAuth(token, username, deviceId, userId) {
    localStorage.setItem(STORAGE_KEYS.TOKEN, token)
    localStorage.setItem(STORAGE_KEYS.USERNAME, username)
    if (deviceId) localStorage.setItem(STORAGE_KEYS.DEVICE_ID, deviceId)
    if (userId) localStorage.setItem(STORAGE_KEYS.USER_ID, userId)
  },

  getAuth() {
    return {
      token: localStorage.getItem(STORAGE_KEYS.TOKEN),
      username: localStorage.getItem(STORAGE_KEYS.USERNAME),
      deviceId: localStorage.getItem(STORAGE_KEYS.DEVICE_ID),
      userId: localStorage.getItem(STORAGE_KEYS.USER_ID)
    }
  },

  clearAuth() {
    localStorage.removeItem(STORAGE_KEYS.TOKEN)
    localStorage.removeItem(STORAGE_KEYS.USERNAME)
    localStorage.removeItem(STORAGE_KEYS.DEVICE_ID)
    localStorage.removeItem(STORAGE_KEYS.USER_ID)
  },

  // Messages (object format: { userId: [messages] })
  saveMessages(messages) {
    localStorage.setItem(STORAGE_KEYS.MESSAGES, JSON.stringify(messages))
  },

  getMessages() {
    const data = localStorage.getItem(STORAGE_KEYS.MESSAGES)
    return data ? JSON.parse(data) : {}
  },

  // Users
  saveUsers(users) {
    localStorage.setItem(STORAGE_KEYS.USERS, JSON.stringify(users))
  },

  getUsers() {
    const data = localStorage.getItem(STORAGE_KEYS.USERS)
    return data ? JSON.parse(data) : []
  },

  clear() {
    this.clearAuth()
    localStorage.removeItem(STORAGE_KEYS.MESSAGES)
    localStorage.removeItem(STORAGE_KEYS.USERS)
  }
}

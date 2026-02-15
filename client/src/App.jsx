import { useState, useEffect } from 'react'
import { wsService } from './services/websocket'
import { signalProtocol } from './e2ee/signal-protocol'
import { encodeBase64 } from 'tweetnacl-util'
import { Auth } from './components/Auth'
import { ChatList } from './components/ChatList'
import { ChatWindow } from './components/ChatWindow'
import { MessageInput } from './components/MessageInput'
import { api } from './services/api'
import { storage } from './services/storage'
import './App.css'

// Helper function to check if JWT token is expired
function isTokenExpired(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]))
    const expirationTime = payload.exp * 1000 // Convert to milliseconds
    return Date.now() >= expirationTime
  } catch {
    return true // If we can't parse it, consider it expired
  }
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentUser, setCurrentUser] = useState('')
  const [token, setToken] = useState(null)
  const [currentUserId, setCurrentUserId] = useState(null)
  const [deviceId, setDeviceId] = useState(null)
  const [users, setUsers] = useState([])
  const [selectedUser, setSelectedUser] = useState(null)
  const [messages, setMessages] = useState({})

  // Setup WebSocket message handler
  const setupMessageHandler = () => {
    // Clear any existing handlers to prevent duplicates
    wsService.removeHandlers()

    wsService.onMessage((data) => {
      // Handle both 'message' (after decryption) and 'deliver' types
      if (data.type === 'message' || data.type === 'deliver') {
        console.log('[App] Received message:', data)
        const msg = {
          from: data.from_user_id,     // Use user ID, not device ID
          fromDeviceId: data.from_device_id, // Include device ID for display
          fromDeviceName: data.from_device_name || 'Unknown Device', // Device name
          text: data.text,             // Use decrypted text, not ciphertext
          timestamp: data.timestamp || new Date().toISOString()
        }
        setMessages(prev => {
          const senderId = data.from_user_id
          return {
            ...prev,
            [senderId]: [...(prev[senderId] || []), msg]
          }
        })
      }
    })
  }

  // Load saved auth and messages on mount
  useEffect(() => {
    const savedAuth = storage.getAuth()
    if (savedAuth.token && savedAuth.username) {
      // Check if token is expired
      if (isTokenExpired(savedAuth.token)) {
        storage.clear()
      } else {
        setToken(savedAuth.token)
        setCurrentUser(savedAuth.username)
        setCurrentUserId(savedAuth.userId)
        setIsAuthenticated(true)

        // Load saved messages from localStorage
        const savedMessages = storage.getMessages()
        setMessages(savedMessages)

        // Restore deviceId and reconnect WebSocket if available
        if (savedAuth.deviceId) {
          setDeviceId(savedAuth.deviceId)
          wsService.connect(savedAuth.token, savedAuth.deviceId)
          // Setup message handler for restored session
          setupMessageHandler()
        }
      }
    }
  }, [])

  // Fetch real users from server
  useEffect(() => {
    if (isAuthenticated && token) {
      const fetchUsers = async () => {
        try {
          const usersList = await api.getUsers(token)
          setUsers(usersList.map(u => ({
            ...u,
            lastMessage: '',
            unread: 0
          })))
        } catch (err) {
          console.error('Failed to fetch users:', err)
          // If 401 Unauthorized, token is invalid - log out
          if (err.message.includes('401') || err.message.includes('Unauthorized')) {
            handleLogout()
          }
        }
      }
      fetchUsers()

      // Refresh users list every 5 seconds to see new registrations
      const interval = setInterval(fetchUsers, 5000)
      return () => clearInterval(interval)
    }
  }, [isAuthenticated, token])

  // NOTE: Disabled REST API polling since we're using WebSocket for E2EE messages
  // The /messages endpoint returns plaintext simple messages, not encrypted WebSocket messages
  // All messages now come through WebSocket in real-time

  const handleLogin = async (username, password, isLogin) => {
    try {
      let authData
      if (isLogin) {
        authData = await api.login(username, password)
      } else {
        authData = await api.register(username, password)
      }

      setToken(authData.access_token)
      setCurrentUser(username)
      setIsAuthenticated(true)

      // Decode JWT to get user ID
      const payload = JSON.parse(atob(authData.access_token.split('.')[1]))
      setCurrentUserId(payload.sub)

      // Reuse existing device on login to avoid creating duplicate devices
      const savedAuth = storage.getAuth()
      const existingDeviceId = savedAuth.deviceId && savedAuth.username === username ? savedAuth.deviceId : null

      let devId
      if (existingDeviceId) {
        // Reuse the existing device — just reinitialize Signal Protocol with saved keys
        await signalProtocol.initialize(existingDeviceId)
        devId = existingDeviceId
      } else {
        // First time (registration or login after logout) — create a fresh device
        const tempDeviceId = `${username}-device-${Date.now()}`
        await signalProtocol.initialize(tempDeviceId)

        const identityPublicKey = encodeBase64(signalProtocol.identityKeyPair.publicKey)
        const dev = await api.createDevice(authData.access_token, {
          device_name: 'web',
          identity_key_public: identityPublicKey,
          identity_signing_public: encodeBase64(signalProtocol.signingKeyPair.publicKey)
        })
        devId = dev.id

        const keyBundle = signalProtocol.getKeyBundle()
        await api.uploadKeys(
          authData.access_token,
          devId,
          {
            key_id: keyBundle.signed_prekey_id,
            public_key: keyBundle.signed_prekey_public,
            signature: keyBundle.signed_prekey_signature
          },
          keyBundle.one_time_prekeys.map(k => ({
            key_id: k.id,
            public_key: k.public_key
          }))
        )
        console.log('[App] Keys uploaded to server')
      }

      setDeviceId(devId)
      storage.saveAuth(authData.access_token, username, devId, payload.sub)
      wsService.connect(authData.access_token, devId)

      // Listen for incoming messages via WebSocket
      setupMessageHandler()

    } catch (err) {
      throw err
    }
  }

  const handleLogout = () => {
    storage.clear()
    setIsAuthenticated(false)
    setCurrentUser('')
    setToken(null)
    setCurrentUserId(null)
    setUsers([])
    setSelectedUser(null)
    setMessages({})
    wsService.disconnect()
    setDeviceId(null)

  }

  const handleSelectUser = (user) => {
    setSelectedUser(user)
  }

  const handleResetAll = async () => {
    if (!window.confirm('Delete ALL users, messages and keys? This cannot be undone.')) return
    try {
      await api.resetAll(token)
      handleLogout()
    } catch (err) {
      console.error('Reset failed:', err)
    }
  }

  const handleDeleteUser = async (user) => {
    if (!window.confirm(`Delete user "${user.username}"? This cannot be undone.`)) return
    try {
      await api.deleteUser(token, user.id)
      setUsers(prev => prev.filter(u => u.id !== user.id))
      if (selectedUser?.id === user.id) setSelectedUser(null)
    } catch (err) {
      console.error('Failed to delete user:', err)
    }
  }

  const handleSendMessage = async (text) => {
    if (!selectedUser || !token) return

    try {
      await wsService.sendMessageToUser(selectedUser.id, text)
      
      // Optimistically add message to UI
      const newMessage = {
        from: currentUserId,
        to: selectedUser.id,
        text,
        timestamp: new Date().toISOString()
      }
      
      setMessages(prev => ({
        ...prev,
        [selectedUser.id]: [...(prev[selectedUser.id] || []), newMessage]
      }))
    } catch (err) {
      console.error('Failed to send message:', err)
    }
  }

  if (!isAuthenticated) {
    return <Auth onLogin={handleLogin} />
  }

  return (
    <div className="app">
      <ChatList
        users={users}
        currentUser={currentUser}
        selectedUser={selectedUser}
        onSelectUser={handleSelectUser}
        onLogout={handleLogout}
        onDeleteUser={handleDeleteUser}
        onResetAll={handleResetAll}
      />

      <div className="chat-main">
        <ChatWindow
          selectedUser={selectedUser}
          messages={messages[selectedUser?.id] || []}
          currentUser={currentUser}
          currentUserId={currentUserId}
        />
        <MessageInput
          onSend={handleSendMessage}
          disabled={!selectedUser}
        />
      </div>
    </div>
  )
}

export default App

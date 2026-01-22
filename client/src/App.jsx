import { useState, useEffect } from 'react'
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
  const [users, setUsers] = useState([])
  const [selectedUser, setSelectedUser] = useState(null)
  const [messages, setMessages] = useState({})

  // Load saved auth on mount
  useEffect(() => {
    const savedAuth = storage.getAuth()
    if (savedAuth.token && savedAuth.username) {
      // Check if token is expired
      if (isTokenExpired(savedAuth.token)) {
        storage.clear()
      } else {
        setToken(savedAuth.token)
        setCurrentUser(savedAuth.username)
        setIsAuthenticated(true)
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

  // Poll for messages with selected user
  useEffect(() => {
    if (isAuthenticated && token && selectedUser) {
      const fetchMessages = async () => {
        try {
          const msgs = await api.getMessages(token, selectedUser.id)
          setMessages(prev => ({
            ...prev,
            [selectedUser.id]: msgs.map(m => ({
              from: m.from_user_id,
              to: m.to_user_id,
              text: m.text,
              timestamp: m.created_at
            }))
          }))
        } catch (err) {
          console.error('Failed to fetch messages:', err)
        }
      }
      
      fetchMessages()
      // Poll every 2 seconds for new messages
      const interval = setInterval(fetchMessages, 2000)
      return () => clearInterval(interval)
    }
  }, [isAuthenticated, token, selectedUser])

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

      // Save to localStorage
      storage.saveAuth(authData.access_token, username, payload.sub)
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
  }

  const handleSelectUser = (user) => {
    setSelectedUser(user)
  }

  const handleSendMessage = async (text) => {
    if (!selectedUser || !token) return

    try {
      await api.sendMessage(token, selectedUser.id, text)
      
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

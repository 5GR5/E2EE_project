import { useState } from 'react'
import './App.css'

function App() {
  const [screen, setScreen] = useState('auth') // 'auth', 'login', 'chat'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(null)
  const [messages, setMessages] = useState([])
  const [inputMessage, setInputMessage] = useState('')

  const API_URL = 'http://localhost:8000'

  const handleRegister = async () => {
    try {
      const res = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      const data = await res.json()
      if (res.ok && data.access_token) {
        setToken(data.access_token)
        setScreen('chat')
        setMessages([{ text: `Welcome ${username}!`, type: 'system' }])
      } else {
        alert('Registration failed: ' + (data.detail || 'Unknown error'))
      }
    } catch (err) {
      alert('Registration failed: ' + err.message)
    }
  }

  const handleLogin = async () => {
    try {
      const res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      const data = await res.json()
      if (res.ok && data.access_token) {
        setToken(data.access_token)
        setScreen('chat')
        setMessages([{ text: `Welcome back ${username}!`, type: 'system' }])
      } else {
        alert('Login failed: ' + (data.detail || 'Unknown error'))
      }
    } catch (err) {
      alert('Login failed: ' + err.message)
    }
  }

  const handleSendMessage = () => {
    if (inputMessage.trim()) {
      setMessages([...messages, { text: inputMessage, type: 'sent' }])
      setInputMessage('')
      // TODO: Send via WebSocket
    }
  }

  return (
    <div className="app-container">
      {screen === 'auth' && (
        <div className="auth-container">
          <h1>E2EE Messaging</h1>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button onClick={handleRegister}>Register</button>
          <button onClick={() => setScreen('login')}>Already have account? Login</button>
        </div>
      )}

      {screen === 'login' && (
        <div className="auth-container">
          <h1>E2EE Messaging - Login</h1>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button onClick={handleLogin}>Login</button>
          <button onClick={() => setScreen('auth')}>Back to Register</button>
        </div>
      )}

      {screen === 'chat' && (
        <div className="chat-container">
          <h1>Chat</h1>
          <div className="messages">
            {messages.map((msg, idx) => (
              <div key={idx} className={`message ${msg.type}`}>
                {msg.text}
              </div>
            ))}
          </div>
          <div className="input-area">
            <input
              type="text"
              placeholder="Type a message..."
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
            />
            <button onClick={handleSendMessage}>Send</button>
          </div>
        </div>
      )}
    </div>
  )
}

export default App

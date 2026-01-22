import { useEffect, useRef } from 'react'

export function ChatWindow({ selectedUser, messages, currentUser, currentUserId }) {
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  if (!selectedUser) {
    return (
      <div className="chat-window">
        <div className="empty-chat">
          <div className="empty-chat-icon">💬</div>
          <h2>SecureChat</h2>
          <p>Select a user from the list to start messaging</p>
        </div>
      </div>
    )
  }

  return (
    <div className="chat-window">
      <div className="chat-window-header">
        <div className="user-avatar">{selectedUser.username[0].toUpperCase()}</div>
        <div className="chat-window-header-info">
          <div className="chat-window-name">{selectedUser.username}</div>
          <div className="chat-window-status">online</div>
        </div>
      </div>

      <div className="chat-window-messages">
        {messages.length === 0 ? (
          <div className="no-messages">
            <p>No messages yet</p>
            <small>Send a message to start the conversation</small>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div
              key={idx}
              className={`message ${msg.from === currentUserId ? 'sent' : 'received'}`}
            >
              <div className="message-content">{msg.text}</div>
              <div className="message-time">
                {new Date(msg.timestamp).toLocaleTimeString('en-US', {
                  hour: '2-digit',
                  minute: '2-digit'
                })}
              </div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>
    </div>
  )
}

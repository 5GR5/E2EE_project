import { useState } from 'react'

export function MessageInput({ onSend, disabled }) {
  const [message, setMessage] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (message.trim()) {
      onSend(message.trim())
      setMessage('')
    }
  }

  return (
    <div className="message-input">
      <form onSubmit={handleSubmit}>
        <button type="button" className="btn-emoji" disabled>
          😊
        </button>

        <input
          type="text"
          placeholder={disabled ? 'Select a user to send a message' : 'Type a message...'}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          disabled={disabled}
          autoFocus={!disabled}
        />

        <button
          type="submit"
          className="btn-send"
          disabled={disabled || !message.trim()}
        >
          ➤
        </button>
      </form>
    </div>
  )
}

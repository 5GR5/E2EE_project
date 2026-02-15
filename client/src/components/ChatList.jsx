export function ChatList({ users, currentUser, selectedUser, onSelectUser, onLogout, onDeleteUser, onResetAll }) {
  return (
    <div className="chat-list">
      <div className="chat-list-header">
        <div className="user-info">
          <div className="user-avatar">{currentUser[0].toUpperCase()}</div>
          <span className="user-name">{currentUser}</span>
        </div>
        <div className="header-actions">
          {onResetAll && (
            <button onClick={onResetAll} className="btn-reset-db" title="Clear all data (Admin)">
              🗑
            </button>
          )}
          <button onClick={onLogout} className="btn-logout" title="Logout">
            ⎋
          </button>
        </div>
      </div>

      <div className="chat-list-search">
        <input type="text" placeholder="Search users..." disabled />
      </div>

      <div className="chat-list-users">
        {users.length === 0 ? (
          <div className="empty-state">
            <p>No other users available</p>
            <small>Create more accounts to start chatting</small>
          </div>
        ) : (
          users.map((user) => (
            <div
              key={user.username}
              className={`chat-list-item ${selectedUser?.username === user.username ? 'active' : ''}`}
              onClick={() => onSelectUser(user)}
            >
              <div className="user-avatar">{user.username[0].toUpperCase()}</div>
              <div className="chat-list-item-info">
                <div className="chat-list-item-name">{user.username}</div>
                <div className="chat-list-item-message">
                  {user.lastMessage || 'Start a conversation'}
                </div>
              </div>
              {user.unread > 0 && (
                <div className="unread-badge">{user.unread}</div>
              )}
              {onDeleteUser && (
                <button
                  className="btn-delete-user"
                  title={`Delete ${user.username}`}
                  onClick={(e) => { e.stopPropagation(); onDeleteUser(user) }}
                >
                  ✕
                </button>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

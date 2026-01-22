# SecureChat - E2EE Messaging Client

A modern, WhatsApp-like messaging interface for end-to-end encrypted communication.

## Features

- **Clean WhatsApp-style UI** - Modern dark theme with intuitive design
- **Real-time messaging** - WebSocket-based instant message delivery
- **User authentication** - Secure login and registration
- **Local persistence** - Messages and auth stored in browser localStorage
- **Simple architecture** - Easy to understand and extend

## Project Structure

```
client/src/
├── components/          # UI components
│   ├── Auth.jsx        # Login/Register screens
│   ├── ChatList.jsx    # Left sidebar with users
│   ├── ChatWindow.jsx  # Message display area
│   └── MessageInput.jsx # Message input box
├── services/           # Business logic
│   ├── api.js         # HTTP API calls
│   ├── websocket.js   # WebSocket service
│   └── storage.js     # localStorage helpers
├── App.jsx            # Main app component
└── App.css            # WhatsApp-like styling
```

## Getting Started

### 1. Install dependencies

```bash
cd client
npm install
```

### 2. Start the server (your friends' backend)

In the project root:

```bash
cd server
pip install -r requierments.txt
uvicorn main:app --reload
```

### 3. Initialize database and create demo users

```bash
# Initialize database tables
python init_db.py

# Create 4 demo users (alice, bob, charlie, david)
python create_demo_users.py
```

### 4. Start the client

```bash
cd client
npm run dev
```

The app will open at `http://localhost:5173`

## Demo Users

After running `create_demo_users.py`, you can login with:

- **Username:** alice, bob, charlie, or david
- **Password:** demo123

## How to Test

1. Open the app in multiple browser windows/tabs (or use incognito mode)
2. Login as different users in each window
3. Start chatting between users
4. Messages appear in real-time across all connected clients

## Architecture Overview

### Services Layer

**`api.js`** - Handles HTTP requests to the server
- User registration and login
- Device creation
- Key management (for future E2EE)

**`websocket.js`** - Manages WebSocket connection
- Connects to server when authenticated
- Sends and receives messages in real-time
- Handles connection status

**`storage.js`** - LocalStorage wrapper
- Persists auth tokens
- Saves message history
- Stores user list

### Components

**`Auth`** - Login/Register screens
- Simple form with username/password
- Toggle between login and registration
- Error handling

**`ChatList`** - User list sidebar
- Shows available users
- Displays last message preview
- Unread message badges

**`ChatWindow`** - Message display
- Shows conversation history
- Distinguishes sent vs received messages
- Auto-scrolls to latest message

**`MessageInput`** - Send message UI
- Text input with send button
- Disabled when no user selected

## Adding E2EE Later

The app is structured to easily add encryption:

1. Import crypto functions from `/crypto` directory
2. Generate keys during device creation (in `handleLogin`)
3. Upload keys using `api.uploadKeys()`
4. Before sending: encrypt message using Double Ratchet
5. On receiving: decrypt message using Double Ratchet

The crypto layer is already built and tested - it just needs integration!

## Customization

### Change Colors

Edit `App.css` - main colors are:
- Primary green: `#25d366`
- Dark background: `#111`
- Chat bubbles: `#005c4b` (sent), `#202c33` (received)

### Add More Users

Edit the `demoUsers` array in `App.jsx:70`:

```javascript
const demoUsers = ['alice', 'bob', 'charlie', 'david', 'eve']
```

### Change API URL

Edit `API_URL` in `services/api.js:3` and `WS_URL` in `services/websocket.js:3`

## Next Steps

1. **Add E2EE** - Integrate the crypto layer for encrypted messages
2. **User search** - Enable the search bar in chat list
3. **Read receipts** - Show when messages are delivered/read
4. **Typing indicators** - Show when someone is typing
5. **File sharing** - Send images and files
6. **Group chats** - Support multi-user conversations

## Troubleshooting

**WebSocket won't connect:**
- Make sure the server is running on port 8000
- Check that you're logged in (token exists)
- Look for errors in browser console

**Messages not appearing:**
- Open browser DevTools > Network > WS tab
- Check if WebSocket connection is active
- Verify both users are connected

**Can't login:**
- Make sure database is initialized (`python init_db.py`)
- Check if demo users are created (`python create_demo_users.py`)
- Verify server is running

## Technologies

- **React 18.3** - UI framework
- **Vite 5.2** - Fast build tool
- **WebSocket** - Real-time communication
- **LocalStorage** - Client-side persistence

Built with ❤️ for secure, private messaging.

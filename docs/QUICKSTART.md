# Quick Start Guide

Get your WhatsApp-like E2EE messaging app running in 5 minutes!

## Prerequisites

- Python 3.10+ installed
- Node.js 16+ installed
- SQLite (built-in, no setup required)

## Setup Steps

### 1. Set up the database

```bash
# Initialize the database tables
python scripts/init_db.py

# Create 4 demo users: alice, bob, charlie, david (password: demo123)
python scripts/create_demo_users.py
```

### 2. Start the server

```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload
```

Server will run on `http://localhost:8000`

### 3. Start the client (in a new terminal)

```bash
cd client
npm install
npm run dev
```

Client will open at `http://localhost:5173`

## Test It Out

1. Open the app in your browser
2. Login with:
   - Username: `alice` (or bob, charlie, david)
   - Password: `demo123`

3. Open a new incognito/private window
4. Login as a different user (e.g., `bob`)
5. Start chatting between the two windows!

## What You Get

- Modern WhatsApp-like dark theme UI
- Real-time messaging via WebSocket
- 4 demo users ready to chat
- Messages saved in browser localStorage
- Simple, clean architecture

## Next Steps

See [client/README.md](client/README.md) for:
- Architecture details
- How to customize
- How to add E2EE encryption
- Troubleshooting tips

## File Structure

```
New simplified architecture:

client/src/
├── components/         # Clean React components
│   ├── Auth.jsx       # Login/Register
│   ├── ChatList.jsx   # User list sidebar
│   ├── ChatWindow.jsx # Messages display
│   └── MessageInput.jsx
├── services/          # Separated business logic
│   ├── api.js        # HTTP calls
│   ├── websocket.js  # WebSocket service
│   └── storage.js    # localStorage
└── App.jsx           # Main app
```

The old complicated code is replaced with this clean, organized structure!

---

**Have fun chatting!** 🚀

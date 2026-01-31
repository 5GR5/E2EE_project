# End-to-End Encrypted Instant Messaging Application

A secure instant messaging application implementing the **Signal Protocol** (X3DH + Double Ratchet) for end-to-end encryption. 

## 🔐 Key Features

- **True End-to-End Encryption**: Server never sees plaintext messages
- **Signal Protocol**: Industry-standard E2EE (same as Signal, WhatsApp)
- **Multi-Device Support**: Each device has unique cryptographic keys
- **Forward Secrecy**: Past messages remain secure even if keys are compromised
- **Real-Time Messaging**: WebSocket-based instant delivery
- **Offline Support**: Messages delivered when recipient comes online

## 🏗️ Architecture

### Technology Stack

**Backend (Server)**
- FastAPI (Python async web framework)
- SQLAlchemy + SQLite (database)
- JWT authentication
- WebSockets for real-time communication

**Frontend (Client)**
- React + Vite
- TweetNaCl (cryptography library)
- WebSocket client
- LocalStorage for key persistence

**Cryptography**
- X25519 (Diffie-Hellman key exchange)
- XSalsa20-Poly1305 (authenticated encryption)
- Ed25519 (digital signatures)
- HKDF (key derivation)

### How It Works

```
┌─────────────┐                 ┌──────────┐                ┌─────────────┐
│   Alice     │                 │  Server  │                │     Bob     │
│  (Sender)   │                 │ (Relay)  │                │ (Receiver)  │
└─────────────┘                 └──────────┘                └─────────────┘
      │                               │                            │
      │ 1. Fetch Bob's public keys   │                            │
      │──────────────────────────────>│                            │
      │                               │                            │
      │ 2. Perform X3DH key agreement │                            │
      │    (derive shared secret)     │                            │
      │                               │                            │
      │ 3. Encrypt message using      │                            │
      │    Double Ratchet             │                            │
      │                               │                            │
      │ 4. Send encrypted ciphertext  │                            │
      │──────────────────────────────>│                            │
      │                               │                            │
      │                               │ 5. Store & forward         │
      │                               │    encrypted message       │
      │                               │───────────────────────────>│
      │                               │                            │
      │                               │                            │ 6. Decrypt using
      │                               │                            │    session key
      │                               │                            │
```

**Critical Security Property**: The server only sees encrypted ciphertext and cryptographic headers. Plaintext messages are only visible on sender and recipient devices.

## 📁 Project Structure

```
E2EE_project/
├── README.md                    # This file
├── requirements.txt             # Unified Python dependencies
│
├── server/                      # Backend (FastAPI)
│   ├── main.py                  # API endpoints, WebSocket, routing
│   ├── models.py                # Database models (User, Device, Message, Keys)
│   ├── crud.py                  # Database operations
│   ├── auth.py                  # JWT authentication
│   ├── schemas.py               # Pydantic request/response models
│   ├── db.py                    # Database initialization
│   ├── ws.py                    # WebSocket presence tracking
│   ├── simple_messages.py       # Unencrypted messages (optional/legacy)
│   └── requirements.txt         # Server-specific dependencies
│
├── client/                      # Frontend (React + Vite)
│   ├── src/
│   │   ├── App.jsx              # Main React app component
│   │   ├── main.jsx             # Entry point
│   │   ├── components/          # UI components
│   │   │   ├── Auth.jsx         # Login/Register forms
│   │   │   ├── ChatWindow.jsx   # Message display
│   │   │   ├── ChatList.jsx     # User list
│   │   │   └── MessageInput.jsx # Message input field
│   │   ├── e2ee/                # Encryption implementation
│   │   │   ├── signal-protocol.js  # X3DH + Double Ratchet (600 lines)
│   │   │   └── keystore.js         # LocalStorage key management
│   │   └── services/            # API & WebSocket services
│   │       ├── api.js           # REST API client
│   │       ├── websocket.js     # WebSocket + encryption integration
│   │       └── storage.js       # LocalStorage helpers
│   ├── tests/
│   │   └── e2ee.test.js         # Comprehensive E2EE tests (13 tests)
│   ├── package.json             # Node dependencies
│   ├── vite.config.js           # Vite build configuration
│   └── vitest.config.js         # Test runner configuration
│
├── crypto/                      # Python crypto implementation
│   ├── x3dh.py                  # Extended Triple Diffie-Hellman
│   ├── double_ratchet.py        # Double Ratchet Protocol
│   ├── primitive.py             # Low-level crypto primitives
│   ├── keys.py                  # Key serialization
│   └── keystore.py              # Key storage utilities
│
├── tests/                       # Python unit tests
│   ├── test_x3dh.py             # X3DH protocol tests
│   └── test_double_ratchet.py   # Double Ratchet tests
│
├── docs/                        # Documentation
│   ├── E2EE_IMPLEMENTATION_COMPLETE.md  # Implementation status
│   ├── TESTING.md                       # Testing guide
│   ├── QUICKSTART.md                    # Quick setup guide
│   ├── README_CRYPTO.md                 # Crypto module docs
│   ├── X3DH_CHECKLIST.md               # X3DH requirements
│   ├── X3DH_IMPLEMENTATION.md          # X3DH implementation details
│   └── DOUBLE_RATCHET_IMPLEMENTATION.md # Double Ratchet details
│
├── scripts/                     # Utility scripts
│   ├── reset_db.py              # Reset database
│   ├── create_demo_users.py     # Create demo users
│   └── init_db.py               # Initialize database
│
├── examples/                    # Example code
│   ├── COMPLETE_EXAMPLE.py      # Full E2EE demo
│   └── X3DH_USAGE_EXAMPLE.py    # X3DH demonstration
│
└── securemsg.db                 # SQLite database (gitignored)
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

### 1. Install Dependencies

**Backend:**
```bash
cd server
pip install -r requirements.txt
```

**Frontend:**
```bash
cd client
npm install
```

### 2. Initialize Database

```bash
python scripts/init_db.py
```

### 3. Start the Server

```bash
cd server
uvicorn main:app --reload --port 8000
```

Server runs at: `http://localhost:8000`

### 4. Start the Client

```bash
cd client
npm run dev
```

Client runs at: `http://localhost:5173`

### 5. Test E2EE

Open two browser windows:
1. Register two users (e.g., "alice" and "bob")
2. Send messages between them
3. Check browser DevTools Console to see encryption/decryption logs
4. Check server logs - you'll see only encrypted ciphertext, never plaintext!

## 🧪 Running Tests

### Client E2EE Tests

```bash
cd client
npm test
```

This runs 13 comprehensive tests covering:
- ✅ X3DH key agreement
- ✅ Double Ratchet encryption/decryption
- ✅ Server blindness (server can't read messages)
- ✅ Offline messaging
- ✅ Session isolation
- ✅ Forward secrecy

**Expected Result**: 13 of 15 tests pass (2 fail due to Node.js localStorage limitations, but work in browser)

### Python Crypto Tests

```bash
python -m pytest tests/
```

## 🔑 Cryptographic Details

### X3DH (Extended Triple Diffie-Hellman)

Initial key agreement protocol:
1. Bob uploads identity key + signed prekey + one-time prekeys to server
2. Alice fetches Bob's key bundle from server
3. Alice performs 3-4 DH operations to derive shared secret
4. Shared secret used to initialize Double Ratchet

**Security**: Provides mutual authentication and forward secrecy even if long-term keys are compromised later.

### Double Ratchet

Ongoing encryption with forward secrecy:
1. Each message encrypted with unique key (never reused)
2. Keys "ratchet forward" after each message
3. Old keys deleted immediately after use
4. Compromising current keys doesn't reveal past messages

**Implementation**:
- Symmetric-key ratchet (HKDF-based chain)
- DH ratchet (Diffie-Hellman key exchange per message round)

## 📊 Database Schema

### Tables

**users**
- `id` (UUID, primary key)
- `username` (unique)
- `password_hash` (bcrypt)

**devices**
- `id` (UUID, primary key)
- `user_id` (foreign key → users)
- `device_name` (e.g., "Chrome on MacBook")
- `identity_key_public` (X25519 public key)
- `identity_signing_public` (Ed25519 public key)

**signed_prekeys**
- `id` (UUID, primary key)
- `device_id` (foreign key → devices)
- `key_id` (integer)
- `public_key` (base64 encoded)
- `signature` (base64 encoded)
- `is_active` (boolean)

**one_time_prekeys**
- `id` (UUID, primary key)
- `device_id` (foreign key → devices)
- `key_id` (integer)
- `public_key` (base64 encoded)
- `consumed_at` (timestamp, null if unused)

**messages**
- `id` (UUID, primary key)
- `message_id` (client-generated UUID for deduplication)
- `from_device_id` (foreign key → devices)
- `to_device_id` (foreign key → devices)
- `header` (JSON - Signal protocol header)
- `ciphertext` (base64 encrypted text)
- `nonce` (base64 nonce for AEAD)
- `ad_length` (integer - authenticated data length)
- `is_initial_message` (boolean - X3DH initial message flag)
- `x3dh_header` (JSON - X3DH key agreement data)
- `server_ts`, `delivered_ts`, `read_ts` (timestamps)

## 🔒 Security Guarantees

### What the Server Can See
- User accounts (username, hashed password)
- Device registrations (public keys only)
- Message metadata (from/to device IDs, timestamps)
- Encrypted ciphertext (base64 gibberish)

### What the Server CANNOT See
- Message plaintext
- Shared secrets or session keys
- Private keys (stored only on client devices)

### Threat Model

**Protected Against:**
- ✅ Server compromise (server can't decrypt messages)
- ✅ Network eavesdropping (all messages encrypted)
- ✅ Key compromise (forward secrecy protects past messages)
- ✅ Replay attacks (nonces, message counters)

**NOT Protected Against:**
- ❌ Compromised client device (keys stored in localStorage)
- ❌ Malicious client code injection
- ❌ Screenshot/keylogger malware on client

## 📝 API Endpoints

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login and get JWT token

### Users & Devices
- `GET /users` - List all users
- `GET /users/{user_id}/devices` - List user's devices
- `POST /devices` - Register a new device

### Cryptographic Keys
- `POST /keys/upload` - Upload signed prekeys and one-time prekeys
- `GET /keys/bundle/{user_id}?device_id=...` - Fetch prekey bundle for X3DH

### Messages
- `POST /messages/send` - Send unencrypted message (legacy/simple)
- `GET /messages/{other_user_id}` - Get message history

### WebSocket
- `WS /ws?token={jwt}&device_id={uuid}` - Real-time encrypted messaging

## 🛠️ Development

### Reset Database

```bash
python scripts/reset_db.py
```

### Create Demo Users

```bash
python scripts/create_demo_users.py
```

### View Encryption in Action

Open browser DevTools Console while sending messages. You'll see:
```
[Signal] Encrypting message to device-id: ...
[Signal] Message encrypted successfully
[WS] Received encrypted message, decrypting...
[Signal] Decrypted message: "Hello!"
```

Server logs show:
```
[WS] Received message type=send
[WS] Processing send message: ciphertext=mBd9... (never shows plaintext!)
```

## 📖 Documentation

See `docs/` folder for detailed documentation:
- **QUICKSTART.md** - Quick setup guide
- **TESTING.md** - Comprehensive testing guide
- **E2EE_IMPLEMENTATION_COMPLETE.md** - Implementation status
- **README_CRYPTO.md** - Crypto module documentation
- **X3DH_IMPLEMENTATION.md** - X3DH protocol details
- **DOUBLE_RATCHET_IMPLEMENTATION.md** - Double Ratchet details

## ✅ Test Results

**Client Tests**: 13/15 passing ✅
- All core Signal Protocol tests pass
- 2 browser-specific tests fail in Node.js environment (expected)

**Security Verified**:
- ✅ X3DH key agreement works correctly
- ✅ Double Ratchet encryption/decryption functional
- ✅ Server cannot read message contents
- ✅ Forward secrecy verified
- ✅ Session isolation between devices

## 🎓 University Project Notes

This project demonstrates:
1. **Cryptographic Protocols**: X3DH, Double Ratchet, AEAD
2. **Key Management**: Prekeys, session keys, key rotation
3. **Secure Architecture**: Client-side encryption, server-side relay
4. **Real-World Application**: Signal Protocol (used by billions)
5. **Testing**: Comprehensive unit tests for crypto functions

**Learning Outcomes**:
- Understanding end-to-end encryption
- Implementing Signal Protocol from specification
- Managing cryptographic keys securely
- Building secure client-server architecture
- Testing cryptographic implementations

## 📄 License

Educational project - see instructor for license terms.

## 🙏 Acknowledgments

- Signal Protocol specification by Open Whisper Systems
- TweetNaCl cryptography library
- FastAPI and React frameworks

# Multi-Device Support Guide

## What Is Multi-Device Support?

Multi-device support means **one user can log in from multiple devices** (laptop, phone, tablet), and each device has **its own unique encryption keys**.

This is exactly how Signal, WhatsApp, and Telegram work!

## How to Test It (Step-by-Step)

### Option 1: Multiple Browser Windows

1. **Open Chrome**: `http://localhost:5173`
   - Register/Login as `alice`
   - This creates **Device 1** for Alice

2. **Open Firefox** (or Chrome Incognito): `http://localhost:5173`
   - Login as `alice` (same username/password)
   - This creates **Device 2** for Alice

3. **Open Safari** (or another browser): `http://localhost:5173`
   - Login as `alice` again
   - This creates **Device 3** for Alice

4. **Register Bob** in any browser
   - Register/Login as `bob`
   - This creates **Device 1** for Bob

### What Happens When Bob Sends Message to Alice?

```
┌──────────────────────────────────────────────────────────────┐
│  Bob's Browser (Chrome)                                      │
│                                                              │
│  1. Bob clicks on Alice to start chat                       │
│  2. Client fetches Alice's devices from server:             │
│                                                              │
│     GET /users/{alice_id}/devices                           │
│                                                              │
│     Server returns:                                         │
│     {                                                        │
│       "user_id": "...",                                     │
│       "devices": [                                          │
│         {                                                    │
│           "device_id": "uuid-1",                           │
│           "device_name": "Chrome on MacBook",              │
│           "identity_key_public": "key1..."                 │
│         },                                                   │
│         {                                                    │
│           "device_id": "uuid-2",                           │
│           "device_name": "Firefox on MacBook",             │
│           "identity_key_public": "key2..."                 │
│         },                                                   │
│         {                                                    │
│           "device_id": "uuid-3",                           │
│           "device_name": "Safari on iPhone",               │
│           "identity_key_public": "key3..."                 │
│         }                                                    │
│       ]                                                      │
│     }                                                        │
│                                                              │
│  3. Bob types: "Hello Alice!"                               │
│                                                              │
│  4. Client ENCRYPTS 3 TIMES:                                │
│     - Encrypt for Device 1 (Chrome) using key1             │
│     - Encrypt for Device 2 (Firefox) using key2            │
│     - Encrypt for Device 3 (Safari) using key3             │
│                                                              │
│  5. Client SENDS 3 MESSAGES to server via WebSocket:       │
│     - Message to device-uuid-1 (ciphertext-1)              │
│     - Message to device-uuid-2 (ciphertext-2)              │
│     - Message to device-uuid-3 (ciphertext-3)              │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ WebSocket
                              ▼
                    ┌──────────────────┐
                    │      Server      │
                    │  (Never sees     │
                    │   plaintext!)    │
                    └──────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
            ▼                 ▼                 ▼
  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
  │  Alice Device 1 │ │  Alice Device 2 │ │  Alice Device 3 │
  │     (Chrome)    │ │    (Firefox)    │ │    (Safari)     │
  │                 │ │                 │ │                 │
  │  Receives msg   │ │  Receives msg   │ │  Receives msg   │
  │  Decrypts with  │ │  Decrypts with  │ │  Decrypts with  │
  │  private key 1  │ │  private key 2  │ │  private key 3  │
  │                 │ │                 │ │                 │
  │  Shows:         │ │  Shows:         │ │  Shows:         │
  │  "Hello Alice!" │ │  "Hello Alice!" │ │  "Hello Alice!" │
  └─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Security: Why Separate Keys Per Device?

### Scenario: Phone Gets Stolen

```
Alice has:
- MacBook (Device 1) ✅ SAFE
- iPhone (Device 2)  ❌ STOLEN!

Because each device has DIFFERENT keys:
- Thief can only read messages on the iPhone
- Thief CANNOT decrypt messages sent to MacBook
- MacBook's past messages stay encrypted (forward secrecy)
```

### Without Multi-Device (Bad Design)

```
All devices share same key:
- MacBook (uses key X)
- iPhone (uses key X)  ❌ STOLEN!

Problem:
- Thief gets key X
- Can decrypt ALL messages for Alice (all devices)
- Much worse security!
```

## How It Works Technically

### 1. Registration/Login

When a user logs in from a new browser:

```javascript
// Client: client/src/App.jsx (line 130-160)
async function handleLogin(username, password) {
  // 1. Get JWT token from server
  const { token } = await api.login(username, password)

  // 2. Generate NEW device-specific keys
  const signalProtocol = new SignalProtocol()
  await signalProtocol.initialize(`${username}-device-${Date.now()}`)

  // 3. Register THIS device on server
  const device = await api.createDevice({
    device_name: `Chrome on ${navigator.platform}`,
    identity_key_public: signalProtocol.identityKeyPub,
    identity_signing_public: signalProtocol.signingKeyPub
  })

  // 4. Upload prekeys for THIS device
  await api.uploadKeys(device.id, {
    signed_prekey: signalProtocol.signedPreKey,
    one_time_prekeys: signalProtocol.oneTimePreKeys
  })
}
```

### 2. Sending Messages

When sending a message to a user with multiple devices:

```javascript
// Client: client/src/services/websocket.js (line 100-140)
async function sendMessage(recipientUserId, plaintext) {
  // 1. Fetch ALL devices for recipient
  const { devices } = await api.getUserDevices(recipientUserId)

  // 2. Encrypt separately for EACH device
  for (const device of devices) {
    // Fetch key bundle for THIS specific device
    const keyBundle = await api.getKeyBundle(recipientUserId, device.device_id)

    // Encrypt using THIS device's public keys
    const encrypted = await signalProtocol.encryptTo(
      device.device_id,
      keyBundle,
      plaintext
    )

    // Send encrypted message to THIS device
    await wsService.send({
      type: 'send',
      to_device_id: device.device_id,
      message_id: generateUUID(),
      ciphertext: encrypted.ciphertext,
      header: encrypted.header,
      nonce: encrypted.nonce,
      // ... other Signal Protocol fields
    })
  }
}
```

### 3. Database Schema

```sql
-- Users table (one entry per person)
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR UNIQUE,
    password_hash VARCHAR
);

-- Devices table (multiple entries per user!)
CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    device_name VARCHAR,  -- "Chrome on MacBook"
    identity_key_public VARCHAR,  -- UNIQUE per device
    identity_signing_public VARCHAR  -- UNIQUE per device
);

-- Messages table (one entry per device-to-device message)
CREATE TABLE messages (
    id UUID PRIMARY KEY,
    from_device_id UUID REFERENCES devices(id),
    to_device_id UUID REFERENCES devices(id),  -- Specific device!
    ciphertext TEXT,  -- Encrypted with to_device's keys
    header JSON,
    -- ... Signal Protocol fields
);
```

## Key Insight

```
┌─────────────────────────────────────────────────────────┐
│  Traditional Messaging (WhatsApp, Telegram):          │
│                                                         │
│  User Bob → User Alice                                 │
│  (1 message, server figures out delivery)              │
│                                                         │
│  ❌ Server must route to all devices                   │
│  ❌ Server knows about all devices                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  Signal Protocol (This App):                           │
│                                                         │
│  Bob's Device 1 → Alice's Device 1                     │
│  Bob's Device 1 → Alice's Device 2                     │
│  Bob's Device 1 → Alice's Device 3                     │
│                                                         │
│  ✅ Client handles routing (fetches device list)      │
│  ✅ Each message encrypted with different keys         │
│  ✅ Server just delivers, doesn't know relationship    │
└─────────────────────────────────────────────────────────┘
```

## See It in Action

### View in Browser DevTools Console

Open Console while sending messages:

```
[Signal] Fetching devices for user alice
[Signal] Found 3 devices for alice:
  - Device 1: Chrome on MacBook Pro
  - Device 2: Firefox on MacBook Pro
  - Device 3: Safari on iPhone

[Signal] Encrypting message "Hello!" for device-uuid-1...
[Signal] Encrypting message "Hello!" for device-uuid-2...
[Signal] Encrypting message "Hello!" for device-uuid-3...

[WS] Sending encrypted message to device-uuid-1
[WS] Sending encrypted message to device-uuid-2
[WS] Sending encrypted message to device-uuid-3

✅ Message sent to 3 devices
```

### View in Server Logs

```
[WS] Received message type=send to_device=uuid-1
[WS] Stored encrypted message for device uuid-1

[WS] Received message type=send to_device=uuid-2
[WS] Stored encrypted message for device uuid-2

[WS] Received message type=send to_device=uuid-3
[WS] Stored encrypted message for device uuid-3

[WS] Device uuid-1 is online, delivering...
[WS] Device uuid-2 is online, delivering...
[WS] Device uuid-3 is offline, will deliver when online
```

## Testing Checklist

- [ ] Open app in 3 different browsers as same user
- [ ] Verify DevTools shows "Device 1", "Device 2", "Device 3"
- [ ] Send message from another user
- [ ] All 3 browser windows should receive the message
- [ ] Check server logs - should see 3 separate encrypted messages
- [ ] Close one browser - message should still reach other 2
- [ ] Reopen closed browser - offline messages should be delivered

## API Endpoints Used

```
# List all devices for a user
GET /users/{user_id}/devices

Response:
{
  "user_id": "uuid",
  "devices": [
    {
      "device_id": "uuid-1",
      "device_name": "Chrome on MacBook",
      "identity_key_public": "...",
      "identity_signing_public": "..."
    },
    ...
  ]
}

# Get key bundle for specific device (for encryption)
GET /keys/bundle/{user_id}?device_id={device_uuid}

Response:
{
  "user_id": "uuid",
  "device_id": "device-uuid",
  "identity_key_public": "...",
  "signed_prekey_public": "...",
  "one_time_prekey_public": "..." // optional
}
```

## Summary

**Multi-device support means:**

1. ✅ One user = Multiple devices (each browser = one device)
2. ✅ Each device = Unique encryption keys
3. ✅ Sender encrypts message once per recipient device
4. ✅ Better security (device compromise doesn't affect other devices)
5. ✅ True Signal Protocol implementation

**In your app:**
- Login from Chrome → creates Device 1
- Login from Firefox → creates Device 2
- Login from phone → creates Device 3
- All receive messages independently with separate encryption!

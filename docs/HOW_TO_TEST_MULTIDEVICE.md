# How to Test Multi-Device Support

## Quick Test (5 minutes)

### Step 1: Start the Server and Client

```bash
# Terminal 1: Start server
cd server
uvicorn main:app --reload --port 8000

# Terminal 2: Start client
cd client
npm run dev
```

### Step 2: Open Multiple Browsers

1. **Chrome**: Open `http://localhost:5173`
2. **Firefox**: Open `http://localhost:5173`
3. **Safari** (or Chrome Incognito): Open `http://localhost:5173`

### Step 3: Register Users

**In Chrome:**
- Click "Register"
- Username: `alice`
- Password: `password123`
- Click Register

**In Firefox:**
- Click "Register"
- Username: `bob`
- Password: `password123`
- Click Register

### Step 4: Create Second Device for Alice

**In Safari (or Chrome Incognito):**
- Click "Login" (not Register!)
- Username: `alice`
- Password: `password123`
- Click Login

✨ **You now have:**
- Alice on 2 devices (Chrome + Safari)
- Bob on 1 device (Firefox)

### Step 5: Send Messages & See Device Labels

**In Firefox (Bob's browser):**
1. Click on "alice" in the user list
2. Type: "Hello Alice!"
3. Send

**Watch what happens:**

In **Chrome (Alice Device 1)**:
- Message appears: "Hello Alice!"
- Device label shows: **"📱 Firefox on ..."**

In **Safari (Alice Device 2)**:
- SAME message appears: "Hello Alice!"
- SAME device label: **"📱 Firefox on ..."**

Both of Alice's devices receive the message with the device name shown!

### Step 6: Verify Server Behavior

**Check Server Console:**
```
[WS] Received message type=send to_device=<uuid-1>
[WS] Received message type=send to_device=<uuid-2>
```

You should see TWO messages sent (one per Alice device)!

### Step 7: Test Offline Delivery

**Close Safari (Alice Device 2)**

**In Firefox (Bob):**
- Send another message: "Are you there?"

**In Chrome (Alice Device 1):**
- Message received immediately
- Shows device badge

**Reopen Safari (Alice Device 2):**
- Message appears automatically (offline delivery works!)
- Same device badge shown

## What You'll See

### Message Display

```
┌─────────────────────────────────────┐
│  Hello Alice!                       │
│  📱 Firefox on MacOS  2:30 PM       │
└─────────────────────────────────────┘
   ↑                      ↑
   Device name            Timestamp
```

### Browser Console Logs

**Bob's Console (Sender):**
```
[Signal] Fetching devices for user alice
[Signal] Found 2 devices:
  - Device 1: Chrome on MacOS
  - Device 2: Safari on MacOS
[Signal] Encrypting for device-uuid-1...
[Signal] Encrypting for device-uuid-2...
[WS] Sent 2 encrypted messages
```

**Alice's Console (Receiver - both browsers):**
```
[WS] Received encrypted message
[Signal] Decrypting from device: <bob-device-uuid>
[Signal] From device: Firefox on MacOS
[Signal] Decrypted: "Hello Alice!"
```

### Database Check

```bash
# Check devices table
sqlite3 securemsg.db "SELECT device_name FROM devices WHERE user_id = (SELECT id FROM users WHERE username = 'alice');"

Output:
Chrome on MacOS X
Safari on MacOS X
```

```bash
# Check messages (should see 2 messages for same content)
sqlite3 securemsg.db "SELECT from_device_id, to_device_id, ciphertext FROM messages LIMIT 5;"
```

## Visual Verification Checklist

- [ ] Different browsers show as different devices
- [ ] Device names appear in message timestamps
- [ ] Device badge has green color (📱 badge)
- [ ] Same message appears in all of Alice's browsers
- [ ] Closing one browser doesn't affect others
- [ ] Offline messages delivered when browser reopens
- [ ] Server console shows multiple send operations
- [ ] Each device has different ciphertext (check DevTools Network tab)

## Advanced Test: 3+ Devices

1. Open 4 browser windows:
   - Chrome → Login as alice
   - Firefox → Login as alice
   - Safari → Login as alice
   - Edge → Login as bob

2. From Bob, send one message to Alice

3. Watch **all 3 of Alice's browsers** receive the message simultaneously!

4. Each shows: `📱 Edge on Windows` (Bob's device name)

## Troubleshooting

**Issue**: Device name not showing

**Fix**: Make sure you've updated both server and client:
- Server: `server/main.py` includes `from_device_name` in WebSocket messages
- Client: `client/src/App.jsx` includes `fromDeviceName` in message object
- Client: `client/src/components/ChatWindow.jsx` displays device badge

**Issue**: Only one browser receives message

**Fix**: Check that you used "Login" (not "Register") for additional devices. Each login creates a new device.

**Issue**: Messages not syncing

**Fix**: Check that all browsers have WebSocket connected (green status in DevTools)

## Understanding the Flow

```
Bob sends "Hi" to Alice
         ↓
Bob's client queries: GET /users/{alice_id}/devices
         ↓
Server returns: [device1, device2, device3]
         ↓
Bob's client encrypts 3 times:
  - encrypt("Hi") with device1's keys → ciphertext1
  - encrypt("Hi") with device2's keys → ciphertext2
  - encrypt("Hi") with device3's keys → ciphertext3
         ↓
Bob's client sends 3 WebSocket messages:
  - {to_device: device1, ciphertext: ciphertext1}
  - {to_device: device2, ciphertext: ciphertext2}
  - {to_device: device3, ciphertext: ciphertext3}
         ↓
Server forwards to each device
         ↓
Each of Alice's browsers decrypts with their own keys
         ↓
All show "Hi" with device badge "📱 Bob's Device"
```

## Database Schema Check

```sql
-- See all users
SELECT * FROM users;

-- See all devices (multiple per user)
SELECT u.username, d.device_name, d.id as device_id
FROM users u
JOIN devices d ON u.id = d.user_id
ORDER BY u.username;

-- See messages with device info
SELECT
  (SELECT device_name FROM devices WHERE id = m.from_device_id) as from_device,
  (SELECT device_name FROM devices WHERE id = m.to_device_id) as to_device,
  SUBSTR(m.ciphertext, 1, 40) as ciphertext_preview
FROM messages m
LIMIT 10;
```

Expected output:
```
alice | Chrome on MacOS X | <uuid-1>
alice | Safari on MacOS X | <uuid-2>
bob   | Firefox on MacOS X | <uuid-3>
```

## Success Criteria

✅ **Multi-device support is working if:**

1. Same user can login from multiple browsers simultaneously
2. Each browser is treated as a separate device
3. Messages sent to user appear in ALL their device browsers
4. Device name badge shows which device sent the message
5. Each device has unique encryption keys (different ciphertext)
6. Offline devices receive queued messages when reconnecting

🎉 If all criteria met, your E2EE multi-device messaging is fully functional!

# SMP-reconstruction – Client Re-implementation

## Overview

This is a **Python re-implementation of the SMC (Secure Messaging Component) client-side protocol** based on Phase 3.1 Burp traces and reverse engineering from the Android app.

### Protocol Features

- **ECDH P-192 Key Exchange**: Elliptic Curve Diffie-Hellman for key establishment
- **AES-256-GCM Encryption**: Symmetric encryption for sending messages (AES-256-CBC for polling)
- **HMAC-SHA256 Authentication**: Message integrity and authenticity
- **PBKDF2-HMAC-SHA256 KDF**: Key derivation from shared secret (matching Java implementation)

### Workflow

```
1. authenticate()        → GET session token from server
2. key_exchange()        → ECDH key pair generation & exchange
3. establish_session()   → Derive session key from shared secret
4. send_message()        → Encrypt & send secure messages
5. poll_messages()       → Receive & decrypt messages
```

---

## Project Structure

```
SMP-reconstruction/
├── client_smc.py         # Main ClientSMC class
├── crypto_utils.py       # Cryptographic utilities (ECDH, AES, HMAC, KDF)
├── main.py               # Test script / entry point
├── interactive.py        # Interactive chat mode
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

---

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Setup

```bash
# Clone or navigate to the project directory
cd SMP-reconstruction

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

Edit `main.py` to set your configuration:

```python
USER_ID = "group-1"                     # User/group ID
SERVER_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"    # Server URL (adjust to your server)
```

### Endpoint Structure

The client assumes the following API endpoints:

- `POST /session/create?userId=<id>`     - Authentication
- `POST /session/exchange?userId=<id>`   - ECDH key exchange
- `POST /message/send?userId=<id>`       - Send encrypted message
- `GET /message/poll?userId=<id>&lastId=<id>` - Receive messages

If your server uses different endpoints, modify the URLs in `client_smc.py`.

---

## Usage

### Basic Test

```bash
python main.py
```

This runs the complete flow:
1. Authenticate with server
2. Perform ECDH key exchange
3. Derive session key
4. Send 3 test messages
5. Poll for responses 3 times

### Expected Output

```
======================================================================
  SMC Client Re-implementation - Phase 4 Test
======================================================================

Configuration:
  User ID:     group-1
  Server URL:  https://crypto-assignment.dangduongminhnhat2003.workers.dev

[✓] Client initialized
    State: INIT

======================================================================
  Phase 2: Authenticate
======================================================================

[AUTH] Sending to https://crypto-assignment.dangduongminhnhat2003.workers.dev/session/create?userId=group-1
[AUTH] ✓ Authenticated successfully
       Token: eyJhbGciOiJIUzI...

[SESSION] ✓ Session established - ready for secure messaging

[✓✓✓] FULL FLOW COMPLETED SUCCESSFULLY ✓✓✓
```

### Interactive Chat Mode

For interactive messaging where you can type and send messages in real-time:

```bash
python interactive.py
```

Or with custom configuration:

```bash
python interactive.py group-1 https://crypto-assignment.dangduongminhnhat2003.workers.dev
```

**Features:**
- Real-time message sending
- Automatic background polling for incoming messages (every 3 seconds)
- Command-based interface

**Available Commands:**
- `/help` - Show help message
- `/status` - Display client status and connection info
- `/poll` - Manually poll for new messages
- `/exit` or `/quit` - Exit interactive mode

**Example Session:**

```
======================================================================
  Interactive Secure Chat Mode
======================================================================
[✓] Connected! You can now send secure messages.
[ℹ] Type '/help' for available commands
[ℹ] Type '/exit' to quit

[ℹ] Background message polling started (every 3 seconds)

----------------------------------------------------------------------

You: Hello, this is a test message!
[ℹ] Sending: 'Hello, this is a test message!'
[✓] Message sent successfully (ID: 123)

[📩 Server] Response from server

You: /status
[ℹ] Client Status
[ℹ] State: SESSION_ESTABLISHED
[ℹ] User ID: group-1
...

You: /exit
[ℹ] Exiting interactive mode...
```

### Using with Burp Suite

To intercept traffic with Burp Suite:

**Option 1: System Proxy**
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
python main.py
```

**Option 2: Modify Code**
Edit `client_smc.py` and add proxy configuration:
```python
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080',
}
response = requests.post(..., proxies=proxies, ...)
```

---

## API Documentation

### ClientSMC Class

#### Methods

##### `authenticate()`
Authenticates with the server and obtains a session token.

**Returns:** `bool` - True if successful

```python
client = ClientSMC("group-1", "https://crypto-assignment.dangduongminhnhat2003.workers.dev")
if client.authenticate():
    print("Authentication successful")
```

---

##### `key_exchange()`
Performs ECDH P-192 key exchange with the server.

**Returns:** `bool` - True if successful

```python
if client.key_exchange():
    print("Key exchange successful")
```

---

##### `establish_session()`
Derives session key from ECDH shared secret using PBKDF2-HMAC-SHA256.

**Returns:** `bool` - True if successful

```python
if client.establish_session():
    print("Session established")
```

---

##### `send_message(plaintext)`
Encrypts and sends a message to the server.

**Args:**
- `plaintext` (str): Message to send

**Returns:** `tuple` - (success: bool, message_id: int)

```python
success, msg_id = client.send_message("Hello!")
if success:
    print(f"Message sent with ID: {msg_id}")
```

---

##### `poll_messages()`
Polls the server for new encrypted messages and decrypts them.

**Returns:** `list` - List of decrypted message strings

```python
messages = client.poll_messages()
for msg in messages:
    print(f"Received: {msg}")
```

---

## Cryptographic Details

### ECDH Key Exchange

- **Curve**: SECP192R1 (P-192)
- **Private Key Size**: 24 bytes
- **Public Key Size**: 49 bytes (uncompressed X962 format)
- **Shared Secret Size**: 24 bytes

### Session Key Derivation

The session key is derived using **PBKDF2-HMAC-SHA256** (matching Java CryptoManager implementation):

```
Session Key = PBKDF2-HMAC-SHA256(
    input_key_material = shared_secret (24 bytes),
    salt = 0x00...00 (16 bytes, all zeros),
    iterations = 1000,
    length = 32 bytes
)
```

### Message Encryption

#### Sending Messages (`send_message()`)
- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits (32 bytes)
- **IV/Nonce Size**: 96 bits (12 bytes)
- **Output**: Ciphertext + Authentication Tag (16 bytes)

#### Polling Messages (`poll_messages()`)
- **Algorithm**: AES-256-CBC
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Padding**: PKCS7

### Message Authentication

- **Algorithm**: HMAC-SHA256
- **Key Size**: 256 bits (32 bytes)
- **Output**: 256 bits (32 bytes)

```
MAC Key = PBKDF2-HMAC-SHA256(
    input_key_material = session_key,
    salt = "MAC_SALT",
    iterations = 1,
    length = 32 bytes
)
MAC = HMAC-SHA256(MAC_key, IV || ciphertext)
```

**Note**: For GCM mode (used in `send_message()`), authentication is built-in via the GCM authentication tag, so HMAC is additional.

---

## Troubleshooting

### Connection Refused

```
[✗] Request error: Connection refused
```

**Solution**: Ensure server is running and accessible at the configured URL.

### Authentication Failed

```
[AUTH] ✗ Server rejected: {'success': False, ...}
```

**Solution**: 
- Check `USER_ID` matches server expectations
- Verify server accepts ECDH curve parameters
- Check server logs for errors

### Key Exchange Failed

```
[KX] ✗ Server rejected key exchange
```

**Solution**:
- Ensure authentication succeeded first
- Check token is still valid (may have expired)
- Verify server public key deserialization works

### MAC Verification Failed

```
[POLL] ⚠ MAC verification failed
```

**Solution**:
- Check MAC key derivation uses correct salt/info
- Verify message wasn't corrupted in transit
- Consider disabling MAC check for testing

---

## Testing Checklist

- [ ] Server is running and accessible
- [ ] `USER_ID` matches server expectations
- [ ] `SERVER_URL` is correct
- [ ] Python 3.7+ installed
- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Run `python main.py` and check output
- [ ] All phases complete (AUTHENTICATED → KEY_EXCHANGED → SESSION_ESTABLISHED)
- [ ] Messages sent successfully
- [ ] Messages polled successfully

---

## Mapping to Phase 3.1 (Burp Traces)

| Flow Step | API Endpoint | Burp Capture | ClientSMC Method |
|-----------|--------------|--------------|------------------|
| Auth | POST /session/create?userId=X | 3.1-1 | `authenticate()` |
| Key Exchange | POST /session/exchange?userId=X | 3.1-2 | `key_exchange()` |
| Session Deriv. | (local computation) | N/A | `establish_session()` |
| Send Message | POST /message/send?userId=X | 3.1-3 | `send_message()` |
| Poll Messages | GET /message/poll?userId=X&lastId=X | 3.1-4 | `poll_messages()` |

---

## Notes

- The implementation follows the Java server implementation (CryptoManager) for compatibility
- Key derivation uses **PBKDF2-HMAC-SHA256** (not HKDF) to match Java server
- Message sending uses **AES-256-GCM** for authenticated encryption
- Message polling uses **AES-256-CBC** (as returned by server)
- ECDSA signature generation is implemented with proper curve operations
- Error handling is basic – enhance for production use
- All cryptographic operations use the `cryptography` library which is NIST-approved
- Session key is NOT persisted to disk for security

---

## References

- ECDH: https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman
- AES: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- AES-GCM: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- PBKDF2: https://tools.ietf.org/html/rfc2898
- HMAC: https://tools.ietf.org/html/rfc2104

---

## License

For academic purposes (BTL / Group 3 - HCMUT)

---

**Author**: Group 3 (Khải - 3.2 Re-implementation)  
**Date**: 2025  
**Status**: Phase 4 Complete ✓


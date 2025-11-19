"""
Author: Trịnh Đình Khải - Re-implementation
Client-side SMC (Secure Messaging Component) Protocol Implementation
"""

import requests
import json
import time

from crypto_utils import (
    random_bytes,
    base64_encode,
    base64_decode,
    EllipticCurve,
    ECPoint,
    ecdh_generate_keypair,
    serialize_ecdh_public_key,
    deserialize_ecdh_public_key,
    ecdh_compute_shared_secret,
    ecdsa_sign,
    derive_session_key,
    derive_mac_key,
    aes_256_cbc_encrypt,
    aes_256_cbc_decrypt,
    hmac_sha256,
    hash_sha256,
    verify_ecdsa_signature,
    verify_ecdsa_signature_from_coords,
)

class ClientSMC:
    """
    Client for SMC protocol
    """
    
    # ECDH P-192 Curve Parameters (standard)
    ECDH_CURVE = "P-192"
    
    def __init__(self, user_id, server_url, timeout=10, use_proxy=False, proxy_url="http://127.0.0.1:8080"):
        self.user_id = user_id
        self.server_url = server_url.rstrip('/')
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.proxy_url = proxy_url if use_proxy else None
        # Session state
        self.state = "INIT"
        self.token = None
        
        # ECDH key material
        self.sk_client = None  # Our ECDH private key
        self.pk_client = None  # Our ECDH public key
        self.pk_server = None  # Server's ECDH public key
        
        # Nonces
        self.nonce_client = None
        self.nonce_server = None
        
        # Derived keys
        self.session_key = None
        self.mac_key = None
        
        # Curve (will be set in authenticate())
        self.curve = None
        
        # Long-term signing key (Identity Key)
        self.sk_sign = None  
        self.pk_sign = None 
        
        # Message tracking
        self.last_message_id = 0
    
    def _get_request_kwargs(self):
        """Get kwargs for requests (with optional proxy)"""
        kwargs = {'timeout': self.timeout}
        if self.use_proxy and self.proxy_url:
            kwargs['proxies'] = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            kwargs['verify'] = False  # Disable SSL verification for Burp
        return kwargs

    # ========================================================================
    # PHASE 1: Authentication  
    # ========================================================================
    
    def authenticate(self):
        if self.state != "INIT":
            print(f"[AUTH] Invalid state: {self.state}, expected INIT")
            return False
        
        try:
            # ECDH curve parameters for P-192
            p_hex = "0xfffffffffffffffffffffffffffffffeffffffffffffffff"
            a_hex = "-3"
            b_hex = "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"
            Gx_hex = "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"
            Gy_hex = "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
            order_hex = "0xffffffffffffffffffffffff99def836146bc9b1b4d22831"
            
            curve_params_internal = {
                "p": p_hex, "a": a_hex, "b": b_hex,
                "Gx": Gx_hex, "Gy": Gy_hex, "order": order_hex
            }
            self.curve = EllipticCurve(**curve_params_internal)
            print(f"[AUTH] Created curve with p={self.curve.p.bit_length()} bits")
            
            print("[AUTH] Generating long-term ECDSA signing key...")
            self.sk_sign, self.pk_sign = ecdh_generate_keypair(self.curve)
            
            payload = {
                "algorithm": "ecdh",
                "curveParameters": {
                    "p": str(int(p_hex, 16)),
                    "a": a_hex,
                    "b": str(int(b_hex, 16)),
                    "Gx": str(int(Gx_hex, 16)),
                    "Gy": str(int(Gy_hex, 16)),
                    "order": str(int(order_hex, 16))
                }
            }
            
            endpoint = f"{self.server_url}/session/create?userId={self.user_id}"
            headers = { "Content-Type": "application/json", "x-user-id": self.user_id }
            
            print(f"[AUTH] Sending to {endpoint}")
            # response = requests.post(endpoint, json=payload, headers=headers, timeout=self.timeout)
            response = requests.post(endpoint, json=payload, headers=headers, **self._get_request_kwargs())

            if response.status_code != 200:
                print(f"[AUTH] ✗ Failed: {response.status_code} - {response.text}")
                return False
            
            data = response.json()
            if not data.get("success", False):
                print(f"[AUTH] ✗ Server rejected: {data}")
                return False
            
            self.token = data.get("sessionToken")
            
            # --- FIX: LƯU SERVER PUBLIC KEY TẠI ĐÂY ---
            if "serverPublicKey" in data:
                server_pub_json = data["serverPublicKey"]
                sx = int(server_pub_json["x"])
                sy = int(server_pub_json["y"])
                # Tạo đối tượng ECPoint cho Server Key
                self.pk_server = ECPoint(sx, sy, self.curve)
                print("[AUTH] ✓ Captured Server ECDH Public Key")
            else:
                print("[AUTH] ⚠ Warning: Server did not return ECDH Public Key")
            # -------------------------------------------

            self.state = "AUTHENTICATED"
            print(f"[AUTH] ✓ Authenticated successfully")
            return True
            
        except Exception as e:
            print(f"[AUTH] ✗ Error: {e}")
            return False
    
    # ========================================================================
    # PHASE 2: Key Exchange
    # ========================================================================
    
    def key_exchange(self):
        if self.state != "AUTHENTICATED":
            return False

        try:
            # 1. Generate Ephemeral ECDH Key Pair
            sk_c, pk_c = ecdh_generate_keypair(self.curve)
            self.sk_client = sk_c
            self.pk_client = pk_c
            
            pk_c_bytes = serialize_ecdh_public_key(pk_c, self.curve)
            coord_length = self.curve.get_coord_length()
            x_coord = pk_c_bytes[1:1+coord_length]
            y_coord = pk_c_bytes[1+coord_length:]

            # 2. Message & Hash
            client_public_key = {
                "x": str(int.from_bytes(x_coord, 'big')),
                "y": str(int.from_bytes(y_coord, 'big'))
            }
            message_str = json.dumps(client_public_key, separators=(',', ':'))
            
            message_bytes = message_str.encode('utf-8')
            hash_digest_raw = hash_sha256(message_bytes)
            hash_int = int.from_bytes(hash_digest_raw, 'big')
            hash_int_mod = hash_int % self.curve.order
            order_bytes_len = (self.curve.order.bit_length() + 7) // 8
            hash_for_sign = hash_int_mod.to_bytes(order_bytes_len, 'big')

            # 3. Sign with EPHEMERAL Signing Key
            sk_sign_eph, pk_sign_eph = ecdh_generate_keypair(self.curve)
            r_int, s_int = ecdsa_sign(self.curve, sk_sign_eph, hash_for_sign)
            
            # 4. Payload
            payload = {
                "sessionToken": self.token,
                "clientPublicKey": client_public_key,
                "clientPublicKeySignature": {
                    "r": str(r_int),
                    "s": str(s_int),
                    "messageHash": str(hash_int_mod),
                    "algorithm": "ECDSA-P192",
                },
                "clientSignaturePublicKey": {
                    "x": str(pk_sign_eph.x),
                    "y": str(pk_sign_eph.y),
                },
            }
            
            endpoint = f"{self.server_url}/session/exchange?userId={self.user_id}"
            headers = { "Content-Type": "application/json", "x-user-id": self.user_id }

            print(f"[KX] Sending payload...")
            # response = requests.post(endpoint, json=payload, headers=headers, timeout=self.timeout)
            response = requests.post(endpoint, json=payload, headers=headers, **self._get_request_kwargs())

            if response.status_code != 200:
                print(f"[KX] Failed: {response.status_code} {response.text}")
                return False

            data = response.json()
            if not data.get("success"):
                print(f"[KX] Server rejected: {data}")
                return False

            if data.get("clientSignatureVerified"):
                print("[KX] ✓ Server verified client signature successfully")
            else:
                print("[KX] ✗ Server rejected client signature!")
                return False
            
            # --- FIX START: Update Token ---
            if "sessionToken" in data:
                self.token = data["sessionToken"]
                print(f"[KX] ✓ Session Token updated")
            # --- FIX END ---

            # Handle Server Key (already captured in Auth, assume valid)
            if self.pk_server is None:
                print("[KX] ✗ Error: Missing Server Public Key")
                return False
            
            # Handle Nonce
            if "serverNonce" in data:
                self.nonce_server = base64_decode(data["serverNonce"])
            elif "nonce" in data:
                self.nonce_server = base64_decode(data["nonce"])
            else:
                self.nonce_server = b'\x00' * 16 

            self.nonce_client = random_bytes(16)

            self.state = "KEY_EXCHANGED"
            return True

        except Exception as e:
            print(f"[KX] Exception: {e}")
            return False
    # ========================================================================
    # PHASE 3: Session Establishment
    # ========================================================================
      
    def establish_session(self):
        if self.state != "KEY_EXCHANGED":
            return False
        
        try:
            # 1. Compute ECDH shared secret (Giữ nguyên)
            shared_secret = ecdh_compute_shared_secret(self.curve, self.sk_client, self.pk_server)
            
            # 2. Derive Session Key (FIX: Dùng PBKDF2 giống Java)
            # Trong CryptoManager.java: salt là 16 bytes toàn số 0, iterations=1000
            # Lưu ý: Hàm này cần import kdf_pbkdf2 từ crypto_utils
            from crypto_utils import kdf_pbkdf2
            
            salt = b'\x00' * 16 
            self.session_key = kdf_pbkdf2(shared_secret, salt, iterations=1000, length=32)
            
            # 3. Derive MAC Key 
            # Java không derive MAC key riêng (nó dùng GCM hoặc CBC ghép).
            # Tuy nhiên để code Python chạy được hàm send_message hiện tại (cần mac_key),
            # ta cứ derive tạm một mac_key từ session_key để tránh lỗi code.
            # (Thực tế nếu Server Java dùng CBC thì nó không check HMAC này, hoặc check theo cách khác)
            self.mac_key = kdf_pbkdf2(self.session_key, b"MAC_SALT", iterations=1, length=32)
            
            self.state = "SESSION_ESTABLISHED"
            print(f"[SESSION] ✓ Session established (PBKDF2 Key Derived)")
            return True
        except Exception as e:
            print(f"[SESSION] ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ========================================================================
    # PHASE 4a: Send Secure Message
    # ========================================================================
    
    
    def send_message(self, plaintext):
        if self.state != "SESSION_ESTABLISHED":
            print(f"[SEND] Invalid state: {self.state}")
            return False, None, False
      
        try:
            # 1. Encrypt (AES-GCM)
            from crypto_utils import aes_256_gcm_encrypt, aes_256_gcm_decrypt
            
            iv = random_bytes(12)
            plaintext_bytes = plaintext.encode('utf-8')
            ciphertext_with_tag = aes_256_gcm_encrypt(self.session_key, plaintext_bytes, iv)
            final_encrypted_blob = iv + ciphertext_with_tag
            encrypted_msg_b64 = base64_encode(final_encrypted_blob)
            
            # 2. MAC
            mac = hmac_sha256(self.mac_key, final_encrypted_blob)
            
            # 3. Sign (Logic Java)
            msg_to_sign_str = encrypted_msg_b64
            message_bytes = msg_to_sign_str.encode('utf-8')
            hash_digest_raw = hash_sha256(message_bytes)
            
            hash_int = int.from_bytes(hash_digest_raw, 'big')
            hash_int_mod = hash_int % self.curve.order
            
            order_bytes_len = (self.curve.order.bit_length() + 7) // 8
            hash_for_sign = hash_int_mod.to_bytes(order_bytes_len, 'big')
            
            r, s = ecdsa_sign(self.curve, self.sk_sign, hash_for_sign)
            
            # 4. Payload
            payload = {
                "sessionToken": self.token,
                "iv": base64_encode(iv),
                "encryptedMessage": encrypted_msg_b64,
                "mac": base64_encode(mac),
                "messageSignature": {
                    "r": str(r), "s": str(s),
                    "messageHash": str(hash_int_mod), "algorithm": "ECDSA-P192"
                },
                "clientSignaturePublicKey": {
                    "x": str(self.pk_sign.x), "y": str(self.pk_sign.y)
                }
            }
            
            endpoint = f"{self.server_url}/message/send?userId={self.user_id}"
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "x-user-id": self.user_id
            }
            
            print(f"[SEND] Sending message: '{plaintext}'")
            #response = requests.post(endpoint, json=payload, headers=headers, timeout=self.timeout)
            response = requests.post(endpoint, json=payload, headers=headers, **self._get_request_kwargs())
            
            if response.status_code != 200:
                print(f"[SEND] ✗ Failed: {response.status_code} - {response.text}")
                return False, None, False
            
            data = response.json()
            if not data.get("success", False):
                print(f"[SEND] ✗ Server rejected: {data}")
                return False, None, False
            
            # --- XỬ LÝ PHẢN HỒI TỪ SERVER (THEO ẢNH BẠN GỬI) ---
            decrypted_success = False
            if "encryptedResponse" in data:
                print("[SEND] ✓ Server responded with encrypted data!")
                enc_resp_b64 = data["encryptedResponse"]
                
                # 1. Decode Base64
                enc_resp_blob = base64_decode(enc_resp_b64)
                
                # 2. Tách IV (12 bytes đầu) và Ciphertext (phần còn lại)
                # Logic này khớp với CryptoManager.java hàm decryptGCM
                resp_iv = enc_resp_blob[:12]
                resp_ciphertext = enc_resp_blob[12:]
                
                # 3. Decrypt
                try:
                    resp_plaintext_bytes = aes_256_gcm_decrypt(self.session_key, resp_ciphertext, resp_iv)
                    resp_plaintext = resp_plaintext_bytes.decode('utf-8')
                    print(f"[SEND] 📩 SERVER REPLY: {resp_plaintext}")
                    decrypted_success = True
                except Exception as e:
                    print(f"[SEND] ✗ Failed to decrypt server response: {e}")
            # ---------------------------------------------------
            
            msg_id = data.get("messageId", 0)
            return True, msg_id, decrypted_success
            
        except Exception as e:
            print(f"[SEND] ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False, None, False
  
    # # ========================================================================
    # # PHASE 4b: Poll
    # # ========================================================================
  
    # def poll_messages(self):
    #     if self.state != "SESSION_ESTABLISHED":
    #         return []
        
    #     try:
    #         endpoint = f"{self.server_url}/message/poll?userId={self.user_id}&lastId={self.last_message_id}"
    #         headers = {
    #             "Authorization": f"Bearer {self.token}",
    #             "Content-Type": "application/json",
    #             "x-user-id": self.user_id
    #         }
            
    #         # response = requests.get(endpoint, headers=headers, timeout=self.timeout)
    #         response = requests.get(endpoint, headers=headers, **self._get_request_kwargs())
    #         if response.status_code != 200:
    #             return []
            
    #         messages_encrypted = response.json().get("messages", [])
    #         messages_decrypted = []
            
    #         for msg in messages_encrypted:
    #             try:
    #                 iv = base64_decode(msg.get("iv", ""))
    #                 ciphertext = base64_decode(msg.get("encryptedMessage", ""))
                    
    #                 plaintext = aes_256_cbc_decrypt(self.session_key, ciphertext, iv)
    #                 messages_decrypted.append(plaintext.decode('utf-8'))
    #                 self.last_message_id = msg.get("messageId", 0)
    #             except:
    #                 continue
            
    #         return messages_decrypted
            
    #     except Exception as e:
    #         print(f"[POLL] ✗ Error: {e}")
    #         return []
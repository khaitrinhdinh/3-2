"""
Author: Trịnh Đình Khải - Re-implementation
Cryptographic utilities for SMC (Secure Messaging Component) client
"""
import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def random_bytes(length):
    """Generate cryptographically random bytes"""
    return os.urandom(length)

# ============================================================================
# Custom Elliptic Curve Implementation
# ============================================================================

class ECPoint:
    """Point on elliptic curve"""
    def __init__(self, x, y, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
    
    def __eq__(self, other):
        if other is None:
            return False
        return self.x == other.x and self.y == other.y
    
    def is_infinity(self):
        return self.x is None and self.y is None
    
    @staticmethod
    def infinity():
        return ECPoint(None, None)
    
    def to_bytes(self, coord_length=24):
        """Serialize point to bytes (X962 uncompressed: 0x04 || x || y)"""
        if self.is_infinity():
            raise ValueError("Cannot serialize point at infinity")
        return b'\x04' + self.x.to_bytes(coord_length, 'big') + self.y.to_bytes(coord_length, 'big')
    
    @staticmethod
    def from_bytes(data, curve, coord_length=24):
        """Deserialize point from bytes (X962 format)"""
        if len(data) != 1 + 2 * coord_length:
            raise ValueError(f"Invalid point length: expected {1 + 2 * coord_length}, got {len(data)}")
        if data[0] != 0x04:
            raise ValueError("Only uncompressed points (0x04) are supported")
        x = int.from_bytes(data[1:1+coord_length], 'big')
        y = int.from_bytes(data[1+coord_length:], 'big')
        return ECPoint(x, y, curve)

class EllipticCurve:
    """Custom elliptic curve: y² = x³ + ax + b (mod p)"""
    
    def __init__(self, p, a, b, Gx, Gy, order):
        """
        Args:
            p: Prime modulus (int or hex string)
            a: Curve coefficient a (int or string)
            b: Curve coefficient b (int or hex string)
            Gx, Gy: Generator point coordinates (int or hex string)
            order: Order of generator point (int or hex string)
        """
        self.p = int(p, 16) if isinstance(p, str) else int(p)
        self.a = int(a) if isinstance(a, str) else int(a)
        self.b = int(b, 16) if isinstance(b, str) else int(b)
        self.Gx = int(Gx, 16) if isinstance(Gx, str) else int(Gx)
        self.Gy = int(Gy, 16) if isinstance(Gy, str) else int(Gy)
        self.order = int(order, 16) if isinstance(order, str) else int(order)
        
        self.G = ECPoint(self.Gx, self.Gy, self)
        
        if not self.is_point_on_curve(self.G):
            raise ValueError("Generator point not on curve!")
    
    def mod_inverse(self, a):
        """Compute modular inverse using extended Euclidean algorithm"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % self.p, self.p)
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {self.p}")
        return (x % self.p + self.p) % self.p
    
    def is_point_on_curve(self, point):
        """Verify point (x, y) lies on curve: y² ≡ x³ + ax + b (mod p)"""
        if point.is_infinity():
            return True
        left = (point.y * point.y) % self.p
        right = (point.x * point.x * point.x + self.a * point.x + self.b) % self.p
        return left == right
    
    def point_add(self, P, Q):
        """Point addition: P + Q"""
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P
        if P.x == Q.x:
            if P.y == Q.y:
                return self.point_double(P)
            else:
                return ECPoint.infinity()
        
        dx = (Q.x - P.x) % self.p
        dy = (Q.y - P.y) % self.p
        s = (dy * self.mod_inverse(dx)) % self.p
        
        x3 = (s * s - P.x - Q.x) % self.p
        y3 = (s * (P.x - x3) - P.y) % self.p
        
        return ECPoint(x3, y3, self)
    
    def point_double(self, P):
        """Point doubling: 2P"""
        if P.is_infinity() or P.y == 0:
            return ECPoint.infinity()
        
        s = ((3 * P.x * P.x + self.a) * self.mod_inverse(2 * P.y)) % self.p
        x3 = (s * s - 2 * P.x) % self.p
        y3 = (s * (P.x - x3) - P.y) % self.p
        
        return ECPoint(x3, y3, self)
    
    def scalar_mult(self, k, point):
        """Scalar multiplication: k * point (using double-and-add)"""
        if k == 0 or point.is_infinity():
            return ECPoint.infinity()
        
        if k < 0:
            k = self.order + k
        
        k = k % self.order
        if k == 0:
            return ECPoint.infinity()
        
        result = ECPoint.infinity()
        addend = point
        
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1
        
        return result
    
    def get_coord_length(self):
        """Get coordinate length in bytes (for P-192: 24 bytes)"""
        return (self.p.bit_length() + 7) // 8

def base64_encode(data):
    """Encode bytes to base64 string"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')

def base64_decode(s):
    """Decode base64 string to bytes"""
    if isinstance(s, str):
        s = s.encode('ascii')
    return base64.b64decode(s)

# ============================================================================
# ECDH Key Generation with Custom Curve
# ============================================================================

def ecdh_generate_keypair(curve):
    """
    Generate ECDH key pair using custom curve
    
    Args:
        curve: EllipticCurve object
    
    Returns:
        (private_key_int, public_key_point: ECPoint)
    """
    private_key = secrets.randbelow(curve.order - 1) + 1
    
    public_key = curve.scalar_mult(private_key, curve.G)
    
    if not curve.is_point_on_curve(public_key):
        raise ValueError("Generated public key not on curve!")
    
    return private_key, public_key

def serialize_ecdh_public_key(public_key_point, curve):
    """
    Serialize ECDH public key to bytes (X962 uncompressed format)
    Format: 0x04 || Px || Py
    
    Args:
        public_key_point: ECPoint object
        curve: EllipticCurve object (for coordinate length)
    
    Returns:
        bytes: Serialized public key
    """
    coord_length = curve.get_coord_length()
    return public_key_point.to_bytes(coord_length)

def deserialize_ecdh_public_key(key_bytes, curve):
    """
    Deserialize ECDH public key from bytes (X962 format)
    
    Args:
        key_bytes: Raw public key bytes (X962 format)
        curve: EllipticCurve object
    
    Returns:
        ECPoint: Public key point
    """
    coord_length = curve.get_coord_length()
    point = ECPoint.from_bytes(key_bytes, curve, coord_length)
    
    if not curve.is_point_on_curve(point):
        raise ValueError("Deserialized point not on curve!")
    
    return point

def ecdh_compute_shared_secret(curve, private_key_int, peer_public_key_point):
    """
    Compute ECDH shared secret
    
    Args:
        curve: EllipticCurve object
        private_key_int: Our private key (int)
        peer_public_key_point: Peer's public key (ECPoint)
    
    Returns:
        shared_secret: Raw bytes of shared secret
    """
    shared_point = curve.scalar_mult(private_key_int, peer_public_key_point)
    
    if shared_point.is_infinity():
        raise ValueError("Shared secret is point at infinity!")
    
    coord_length = curve.get_coord_length()
    shared_secret = shared_point.x.to_bytes(coord_length, 'big')
    
    return shared_secret

# ============================================================================
# Key Derivation Function (HKDF-SHA256)
# ============================================================================

def kdf_derive(input_key_material, salt=None, info=b"SMC", length=32):
    """
    Derive key using HKDF-SHA256
    
    Args:
        input_key_material: IKM bytes (e.g., shared secret)
        salt: Optional salt bytes (if None, uses default)
        info: Context/application-specific info string
        length: Output key length in bytes (typically 32 for AES-256)
    
    Returns:
        derived_key: Random bytes of specified length
    """
    if salt is None:
        salt = b""
    
    if isinstance(info, str):
        info = info.encode('utf-8')
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(input_key_material)

# ============================================================================
# AES-256-CBC/GCM Encryption/Decryption
# ============================================================================

def aes_256_cbc_encrypt(key, plaintext, iv):
    """
    Encrypt plaintext using AES-256-CBC
    
    Args:
        key: 32-byte encryption key
        plaintext: Plaintext bytes (will be PKCS7-padded)
        iv: 16-byte initialization vector
    
    Returns:
        ciphertext: Encrypted bytes
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
    
    # Apply PKCS7 padding
    plaintext_padded = pkcs7_pad(plaintext, block_size=16)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    return ciphertext

def aes_256_cbc_decrypt(key, ciphertext, iv):
    """
    Decrypt ciphertext using AES-256-CBC
    
    Args:
        key: 32-byte encryption key
        ciphertext: Encrypted bytes
        iv: 16-byte initialization vector
    
    Returns:
        plaintext: Decrypted bytes (PKCS7-padding removed)
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    plaintext = pkcs7_unpad(plaintext_padded)
    return plaintext

def aes_256_gcm_encrypt(key, plaintext, iv):
    """
    Encrypt using AES-256-GCM
    Args:
        key: 32 bytes key
        plaintext: bytes
        iv: 12 bytes nonce
    Returns:
        ciphertext + tag (bytes)
    """
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, plaintext, None)

def aes_256_gcm_decrypt(key, ciphertext_with_tag, iv):
    """
    Decrypt using AES-256-GCM
    Args:
        key: 32 bytes key
        ciphertext_with_tag: bytes (ciphertext + auth tag)
        iv: 12 bytes nonce
    Returns:
        plaintext bytes
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext_with_tag, None)
    
# ============================================================================
# PKCS7 Padding
# ============================================================================

def pkcs7_pad(data, block_size=16):
    """
    Apply PKCS7 padding to data
    
    Args:
        data: Bytes to pad
        block_size: Block size in bytes (default 16 for AES)
    
    Returns:
        padded_data: Data with PKCS7 padding applied
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data):
    """
    Remove PKCS7 padding from data
    
    Args:
        data: Padded bytes
    
    Returns:
        unpadded_data: Data with PKCS7 padding removed
    """
    padding_length = data[-1]
    if padding_length > 16 or padding_length == 0:
        raise ValueError("Invalid PKCS7 padding")
    
    return data[:-padding_length]

# ============================================================================
# HMAC-SHA256
# ============================================================================

def hmac_sha256(key, data):
    """
    Compute HMAC-SHA256 for message authentication
    
    Args:
        key: HMAC key bytes
        data: Data to authenticate
    
    Returns:
        mac: HMAC-SHA256 bytes (32 bytes)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# ============================================================================
# SHA256 Hashing
# ============================================================================

def hash_sha256(data):
    """
    Compute SHA256 hash
    
    Args:
        data: Data to hash
    
    Returns:
        hash_value: SHA256 hash bytes (32 bytes)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return hashlib.sha256(data).digest()

# ============================================================================
# Helper: Session Key Derivation (Combined KDF)
# ============================================================================

def derive_session_key(shared_secret, nonce_client, nonce_server, user_id, length=32):
    """
    Derive session key from ECDH shared secret and nonces
    
    Args:
        shared_secret: ECDH shared secret bytes (24 bytes for P-192)
        nonce_client: Client nonce bytes (16 bytes)
        nonce_server: Server nonce bytes (16 bytes)
        user_id: User ID string
        length: Output key length (typically 32 for AES-256)
    
    Returns:
        session_key: Derived session key bytes
    """
    if isinstance(user_id, str):
        user_id = user_id.encode('utf-8')
    
    # Combine all inputs
    kdf_input = shared_secret + nonce_client + nonce_server + user_id + b"SMC_SESSION_KEY"
    
    # Use HKDF to derive
    return kdf_derive(kdf_input, salt=None, info=b"SMC_SESSION", length=length)

# ============================================================================
# Helper: MAC Key Derivation
# ============================================================================

def derive_mac_key(session_key, length=32):
    """
    Derive MAC key from session key
    
    Args:
        session_key: Session key bytes
        length: Output key length (typically 32 for HMAC-SHA256)
    
    Returns:
        mac_key: Derived MAC key bytes
    """
    return kdf_derive(session_key, salt=b"MAC_SALT", info=b"SMC_MAC", length=length)

# ============================================================================
# ECDSA Signing and Verification with Custom Curve
# ============================================================================

def mod_inverse_order(a, m):
    """Modular inverse for order (used in ECDSA)"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return (x % m + m) % m

def ecdsa_sign(curve, private_key_int, message_hash_bytes, max_retries=10):
    """
    ECDSA signature generation
    
    Args:
        curve: EllipticCurve object
        private_key_int: Private key (int)
        message_hash_bytes: Message hash (bytes, typically 32 bytes for SHA256)
        max_retries: Maximum number of retries if r or s is 0
    
    Returns:
        (r, s): Signature components (int, int)
    """
    hash_int = int.from_bytes(message_hash_bytes, 'big')
    hash_bits = hash_int.bit_length()
    order_bits = curve.order.bit_length()
    
    if hash_bits > order_bits:
        hash_int = hash_int >> (hash_bits - order_bits)
    
    hash_int = hash_int % curve.order
    if hash_int == 0:
        hash_int = 1
    
    for attempt in range(max_retries):
        k = secrets.randbelow(curve.order - 1) + 1
        
        # Compute R = k * G
        R = curve.scalar_mult(k, curve.G)
        if R.is_infinity():
            continue  # Retry if R is infinity
        
        r = R.x % curve.order
        if r == 0:
            continue  # Retry if r == 0
        
        # Compute s = k⁻¹ * (hash + r * private_key) mod order
        k_inv = mod_inverse_order(k, curve.order)
        s = (k_inv * (hash_int + r * private_key_int)) % curve.order
        if s == 0:
            continue  # Retry if s == 0
        
        return r, s
    
    # If we get here, all retries failed
    raise ValueError(f"Failed to generate valid ECDSA signature after {max_retries} attempts")

def ecdsa_verify(curve, public_key_point, r, s, message_hash_bytes):
    """
    ECDSA signature verification
    
    Args:
        curve: EllipticCurve object
        public_key_point: Public key point (ECPoint)
        r, s: Signature components (int, int)
        message_hash_bytes: Message hash (bytes)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not (1 <= r < curve.order and 1 <= s < curve.order):
        return False
    
    hash_int = int.from_bytes(message_hash_bytes, 'big')
    hash_bits = hash_int.bit_length()
    order_bits = curve.order.bit_length()
    
    if hash_bits > order_bits:
        hash_int = hash_int >> (hash_bits - order_bits)
    
    hash_int = hash_int % curve.order
    if hash_int == 0:
        hash_int = 1
    
    # Compute w = s⁻¹ mod order
    w = mod_inverse_order(s, curve.order)
    
    # Compute u1 = hash * w mod order, u2 = r * w mod order
    u1 = (hash_int * w) % curve.order
    u2 = (r * w) % curve.order
    
    # Compute R = u1 * G + u2 * Q
    u1G = curve.scalar_mult(u1, curve.G)
    u2Q = curve.scalar_mult(u2, public_key_point)
    R = curve.point_add(u1G, u2Q)
    
    if R.is_infinity():
        return False
    
    # Verify r == R.x mod order
    return (R.x % curve.order) == r

def verify_ecdsa_signature(curve, public_key_point, signature_r, signature_s, message_hash_bytes):
    """
    Verify ECDSA signature (wrapper function)
    
    Args:
        curve: EllipticCurve object
        public_key_point: Public key point (ECPoint)
        signature_r: Signature component r (int or bytes)
        signature_s: Signature component s (int or bytes)
        message_hash_bytes: Message hash bytes (32 bytes for SHA256)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Convert r, s to integers if they're bytes
    if isinstance(signature_r, bytes):
        signature_r = int.from_bytes(signature_r, 'big')
    if isinstance(signature_s, bytes):
        signature_s = int.from_bytes(signature_s, 'big')
    
    try:
        return ecdsa_verify(curve, public_key_point, signature_r, signature_s, message_hash_bytes)
    except Exception as e:
        print(f"[VERIFY] Signature verification failed: {e}")
        return False

def verify_ecdsa_signature_from_coords(curve, public_key_x, public_key_y, signature_r, signature_s, message):
    """
    Verify ECDSA signature from public key coordinates (convenience function)
    
    Args:
        curve: EllipticCurve object
        public_key_x: Public key x coordinate (int or bytes)
        public_key_y: Public key y coordinate (int or bytes)
        signature_r: Signature component r (int or bytes)
        signature_s: Signature component s (int or bytes)
        message: Message string or message hash bytes (32 bytes for SHA256)
                 If string, it will be hashed (theo ECDSASignature.verifySignature)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Convert coordinates to int if needed
    if isinstance(public_key_x, bytes):
        public_key_x = int.from_bytes(public_key_x, 'big')
    if isinstance(public_key_y, bytes):
        public_key_y = int.from_bytes(public_key_y, 'big')
    
    # Reconstruct public key point
    public_key_point = ECPoint(public_key_x, public_key_y, curve)
    
    if not curve.is_point_on_curve(public_key_point):
        print("[VERIFY] Public key point not on curve!")
        return False
    
    # If message is string, hash it (theo ECDSASignature.verifySignature line 113)
    if isinstance(message, str):
        message_hash_bytes = hash_sha256(message.encode('utf-8'))
    else:
        message_hash_bytes = message
    
    return verify_ecdsa_signature(curve, public_key_point, signature_r, signature_s, message_hash_bytes)

def kdf_pbkdf2(input_key_material, salt, iterations=1000, length=32):
    """
    Derive key using PBKDF2-HMAC-SHA256 (Matching Java CryptoManager)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(input_key_material)
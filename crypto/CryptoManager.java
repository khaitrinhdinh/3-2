package com.example.securechat;

import android.util.Base64;
import android.util.Log;
import com.example.securechat.crypto.AlgorithmSelector;
import com.example.securechat.crypto.KeyExchange;
import com.example.securechat.crypto.KeyExchangeFactory;
import com.example.securechat.crypto.SignatureBase;
import com.example.securechat.crypto.SignatureFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

/* loaded from: classes4.dex */
public class CryptoManager {
    private static final String TAG = "CryptoManager";
    private SecretKeySpec aesKey;
    private String algorithm;
    private SignatureBase.KeyPair clientSignatureKeys;
    private KeyExchange keyExchange;
    private JSONObject serverSignaturePublicKey;
    private BigInteger sharedSecret;
    private String signatureAlgorithm;
    private SignatureBase signatureManager;
    private String encryptionMode = "GCM";
    private KeyExchangeFactory keyExchangeFactory = new KeyExchangeFactory();
    private SignatureFactory signatureFactory = new SignatureFactory();

    public void initializeForUser(String userId) throws Exception {
        this.algorithm = AlgorithmSelector.getAlgorithmForUser(userId);
        this.keyExchange = this.keyExchangeFactory.create(this.algorithm);
        if (this.signatureFactory.isSupported(this.algorithm)) {
            this.signatureManager = this.signatureFactory.create(this.algorithm);
            this.signatureAlgorithm = this.signatureManager.getAlgorithmName();
            this.clientSignatureKeys = this.signatureManager.generateSignatureKeyPair();
            Log.d(TAG, "Initialized " + AlgorithmSelector.getAlgorithmDisplayName(this.algorithm) + " for user: " + userId + " with " + this.signatureAlgorithm + " signatures");
            return;
        }
        Log.w(TAG, "No signature support available for " + this.algorithm);
    }

    public String getAlgorithmName() {
        return this.algorithm != null ? AlgorithmSelector.getAlgorithmDisplayName(this.algorithm) : "Unknown";
    }

    public String getSignatureAlgorithmName() {
        return this.signatureAlgorithm;
    }

    public JSONObject getClientSignaturePublicKey() {
        if (this.clientSignatureKeys != null) {
            return this.clientSignatureKeys.publicKey;
        }
        return null;
    }

    public void setServerSignaturePublicKey(JSONObject serverSignaturePublicKey) {
        this.serverSignaturePublicKey = serverSignaturePublicKey;
    }

    public boolean verifyServerSignature(String message, SignatureBase.Signature signature) {
        if (this.signatureManager == null || this.serverSignaturePublicKey == null) {
            Log.w(TAG, "Signature manager or server public key not available");
            return false;
        }
        return this.signatureManager.verifySignature(message, signature, this.serverSignaturePublicKey);
    }

    public boolean verifyServerSignature(String message, JSONObject signatureJson, JSONObject publicKey) {
        if (this.signatureManager == null) {
            Log.w(TAG, "Signature manager not available");
            return false;
        }
        try {
            SignatureBase.Signature signature = SignatureBase.Signature.fromJSON(signatureJson, this.signatureAlgorithm);
            return this.signatureManager.verifySignature(message, signature, publicKey);
        } catch (Exception e) {
            Log.e(TAG, "Error verifying signature from JSON", e);
            return false;
        }
    }

    public boolean verifyServerSignature(String message, JSONObject signatureJson) {
        if (this.signatureManager == null || this.serverSignaturePublicKey == null) {
            Log.w(TAG, "Signature manager or server public key not available");
            return false;
        }
        try {
            SignatureBase.Signature signature = SignatureBase.Signature.fromJSON(signatureJson, this.signatureAlgorithm);
            return this.signatureManager.verifySignature(message, signature, this.serverSignaturePublicKey);
        } catch (Exception e) {
            Log.e(TAG, "Error verifying signature from JSON", e);
            return false;
        }
    }

    public boolean verifySignatureWithPublicKey(String message, SignatureBase.Signature signature, JSONObject publicKey) {
        if (this.signatureManager == null) {
            Log.w(TAG, "Signature manager not available");
            return false;
        }
        return this.signatureManager.verifySignature(message, signature, publicKey);
    }

    public boolean isSignatureSupported() {
        return (this.signatureManager == null || this.clientSignatureKeys == null) ? false : true;
    }

    public void generateKeyPair() throws Exception {
        if (this.keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }
        this.keyExchange.generatePrivateKey();
        Log.d(TAG, "Key pair generated using " + this.keyExchange.getAlgorithmName());
    }

    public JSONObject getPublicKeyJson() throws Exception {
        if (this.keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }
        return this.keyExchange.generatePublicKey();
    }

    public void computeSharedSecret(JSONObject serverPublicKey) throws Exception {
        if (this.keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }
        this.keyExchange.computeSharedSecret(serverPublicKey);
        byte[] secretBytes = this.keyExchange.getSharedSecretBytes();
        this.sharedSecret = new BigInteger(1, secretBytes);
        deriveAESKey();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", Byte.valueOf(b)));
        }
        return sb.toString();
    }

    private void deriveAESKey() throws Exception {
        if (this.sharedSecret == null) {
            throw new IllegalStateException("Shared secret not computed yet");
        }
        int secretByteSize = getSecretByteSizeForAlgorithm();
        byte[] secretBytes = bigIntToBytes(this.sharedSecret, secretByteSize);
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0);
        byte[] keyBytes = pbkdf2(secretBytes, salt, 1000, 32);
        this.aesKey = new SecretKeySpec(keyBytes, "AES");
        Log.d(TAG, "✅ AES key derived successfully");
    }

    private int getSecretByteSizeForAlgorithm() {
        if (this.keyExchange == null) {
            return 24;
        }
        String algoName = this.keyExchange.getAlgorithmName();
        Log.d(TAG, "Determining byte size for algorithm: " + algoName);
        int keySize = this.keyExchange.getKeySize();
        return keySize / 8;
    }

    private byte[] pbkdf2(byte[] password, byte[] salt, int iterations, int keyLength) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(password, "HmacSHA256"));
        byte[] result = new byte[keyLength];
        int hLen = mac.getMacLength();
        int blockCount = ((keyLength + hLen) - 1) / hLen;
        for (int i = 1; i <= blockCount; i++) {
            byte[] block = new byte[salt.length + 4];
            System.arraycopy(salt, 0, block, 0, salt.length);
            block[salt.length] = (byte) (i >>> 24);
            block[salt.length + 1] = (byte) (i >>> 16);
            block[salt.length + 2] = (byte) (i >>> 8);
            block[salt.length + 3] = (byte) i;
            byte[] u = mac.doFinal(block);
            byte[] t = (byte[]) u.clone();
            for (int j = 1; j < iterations; j++) {
                u = mac.doFinal(u);
                for (int k = 0; k < u.length; k++) {
                    t[k] = (byte) (t[k] ^ u[k]);
                }
            }
            int j2 = t.length;
            int copyLength = Math.min(j2, keyLength - ((i - 1) * hLen));
            System.arraycopy(t, 0, result, (i - 1) * hLen, copyLength);
        }
        return result;
    }

    private byte[] bigIntToBytes(BigInteger bigInt, int length) {
        String hex = format(bigInt, length * 2);
        return hexToBytes(hex);
    }

    private String format(BigInteger bigInt, int length) {
        String hex = bigInt.toString(16);
        while (hex.length() < length) {
            hex = "0" + hex;
        }
        if (hex.length() > length) {
            return hex.substring(hex.length() - length);
        }
        return hex;
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public void setEncryptionMode(String mode) {
        if ("CBC".equals(mode) || "GCM".equals(mode)) {
            this.encryptionMode = mode;
            Log.d(TAG, "Encryption mode set to: " + mode);
        } else {
            Log.w(TAG, "Invalid encryption mode: " + mode);
        }
    }

    public String getEncryptionMode() {
        return this.encryptionMode;
    }

    public String encryptGCM(String plaintext) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(1, this.aesKey, spec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return Base64.encodeToString(result, 2);
    }

    public String decryptGCM(String encryptedData) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }
        byte[] data = Base64.decode(encryptedData, 2);
        byte[] iv = Arrays.copyOfRange(data, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(2, this.aesKey, spec);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private String encryptCBC(String plaintext) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(1, this.aesKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return Base64.encodeToString(result, 2);
    }

    private String decryptCBC(String encryptedData) throws Exception {
        if (this.aesKey == null) {
            throw new IllegalStateException("AES key not derived");
        }
        byte[] data = Base64.decode(encryptedData, 2);
        byte[] iv = Arrays.copyOfRange(data, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(data, 16, data.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(2, this.aesKey, ivSpec);
        try {
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (BadPaddingException e) {
            throw new RuntimeException("PADDING_ERROR", e);
        } catch (Exception e2) {
            throw new RuntimeException("DECRYPT_ERROR", e2);
        }
    }

    public PaddingOracleResult checkPadding(String encryptedData) {
        try {
            decryptCBC(encryptedData);
            return new PaddingOracleResult(true, null);
        } catch (RuntimeException e) {
            String errorType = e.getMessage().equals("PADDING_ERROR") ? "PADDING_ERROR" : "DECRYPT_ERROR";
            return new PaddingOracleResult(false, errorType);
        } catch (Exception e2) {
            return new PaddingOracleResult(false, "UNKNOWN_ERROR");
        }
    }

    public String encrypt(String plaintext) throws Exception {
        if ("CBC".equals(this.encryptionMode)) {
            Log.w(TAG, "⚠️ Using CBC mode - vulnerable to padding oracle attack!");
            return encryptCBC(plaintext);
        }
        return encryptGCM(plaintext);
    }

    public String decrypt(String encryptedData) throws Exception {
        if ("CBC".equals(this.encryptionMode)) {
            Log.w(TAG, "⚠️ Using CBC mode - vulnerable to padding oracle attack!");
            return decryptCBC(encryptedData);
        }
        return decryptGCM(encryptedData);
    }

    public static class PaddingOracleResult {
        public final String errorType;
        public final boolean isValid;

        public PaddingOracleResult(boolean isValid, String errorType) {
            this.isValid = isValid;
            this.errorType = errorType;
        }
    }

    public boolean isKeyExchangeComplete() {
        return (this.aesKey == null || this.sharedSecret == null) ? false : true;
    }

    public JSONObject getAlgorithmParameters() throws Exception {
        if (this.keyExchange == null) {
            throw new IllegalStateException("KeyExchange not initialized");
        }
        return this.keyExchange.getParameters();
    }

    public void testEncryption() {
        try {
            Log.d(TAG, "=== Testing Encryption ===");
            Log.d(TAG, "Original: Hello, World!");
            String encrypted = encrypt("Hello, World!");
            Log.d(TAG, "Encrypted: " + encrypted);
            String decrypted = decrypt(encrypted);
            Log.d(TAG, "Decrypted: " + decrypted);
            boolean match = "Hello, World!".equals(decrypted);
            Log.d(TAG, "Test result: " + (match ? "PASS" : "FAIL"));
        } catch (Exception e) {
            Log.e(TAG, "Encryption test failed", e);
        }
    }

    public void testSignature() {
        if (this.signatureManager == null) {
            Log.w(TAG, "No signature manager available for testing");
            return;
        }
        try {
            String testMessage = "Hello, " + this.signatureAlgorithm + "!";
            Log.d(TAG, "=== Testing " + this.signatureAlgorithm + " Signature ===");
            Log.d(TAG, "Original: " + testMessage);
            SignatureBase.Signature signature = signMessage(testMessage);
            Log.d(TAG, "Signature created with " + signature.algorithm);
            boolean verified = this.signatureManager.verifySignature(testMessage, signature, this.clientSignatureKeys.publicKey);
            Log.d(TAG, "Signature verification: " + (verified ? "PASS" : "FAIL"));
        } catch (Exception e) {
            Log.e(TAG, this.signatureAlgorithm + " signature test failed", e);
        }
    }

    public SignatureBase.KeyPair generateEphemeralSignatureKeyPair() throws Exception {
        if (this.signatureManager == null) {
            throw new IllegalStateException("Signature manager not initialized");
        }
        SignatureBase.KeyPair ephemeralKeys = this.signatureManager.generateSignatureKeyPair();
        return ephemeralKeys;
    }

    public SignatureWithPublicKey signMessageEphemeral(String message) throws Exception {
        if (this.signatureManager == null) {
            throw new IllegalStateException("Signature manager not initialized");
        }
        SignatureBase.KeyPair ephemeralKeys = generateEphemeralSignatureKeyPair();
        SignatureBase.Signature signature = this.signatureManager.signMessage(message, ephemeralKeys.privateKey);
        Log.d(TAG, "✅ Message signed with EPHEMERAL key");
        return new SignatureWithPublicKey(signature, ephemeralKeys.publicKey);
    }

    public static class SignatureWithPublicKey {
        public final JSONObject publicKey;
        public final SignatureBase.Signature signature;

        public SignatureWithPublicKey(SignatureBase.Signature signature, JSONObject publicKey) {
            this.signature = signature;
            this.publicKey = publicKey;
        }
    }

    public SignatureBase.Signature signMessage(String message) throws Exception {
        if (this.signatureManager == null || this.clientSignatureKeys == null) {
            throw new IllegalStateException("Signature manager not initialized");
        }
        return this.signatureManager.signMessage(message, this.clientSignatureKeys.privateKey);
    }
}
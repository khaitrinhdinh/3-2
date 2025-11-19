package com.example.securechat.crypto;

import android.util.Log;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class ECDHKeyExchange2 extends KeyExchange {
    private static final String TAG = "ECDHKeyExchange";
    private BigInteger privateKey;
    private ECPoint publicKey;
    private BigInteger sharedSecret;
    private static final BigInteger CURVE_P = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    private static final BigInteger CURVE_A = BigInteger.valueOf(-3);
    private static final BigInteger CURVE_B = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    private static final BigInteger CURVE_GX = new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    private static final BigInteger CURVE_GY = new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    private static final BigInteger CURVE_ORDER = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");

    public static class ECPoint {
        public BigInteger x;
        public BigInteger y;

        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public String toString() {
            return "ECPoint{x=" + this.x + ", y=" + this.y + "}";
        }
    }

    public ECDHKeyExchange2() {
        super("ECDH-P256");
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public void generatePrivateKey() {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[32];
        random.nextBytes(privateKeyBytes);
        this.privateKey = new BigInteger(1, privateKeyBytes).mod(CURVE_ORDER.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        ECPoint G = new ECPoint(CURVE_GX, CURVE_GY);
        this.publicKey = scalarMult(G, this.privateKey);
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public JSONObject generatePublicKey() throws Exception {
        if (this.publicKey == null) {
            throw new IllegalStateException("Private key not generated yet");
        }
        JSONObject pubKey = new JSONObject();
        pubKey.put("x", this.publicKey.x.toString());
        pubKey.put("y", this.publicKey.y.toString());
        return pubKey;
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public void computeSharedSecret(JSONObject serverPublicKey) throws Exception {
        BigInteger serverX = new BigInteger(serverPublicKey.getString("x"));
        BigInteger serverY = new BigInteger(serverPublicKey.getString("y"));
        ECPoint serverPoint = new ECPoint(serverX, serverY);
        if (!validatePublicKey(serverPublicKey)) {
            throw new Exception("Invalid server public key");
        }
        ECPoint sharedPoint = scalarMult(serverPoint, this.privateKey);
        if (sharedPoint == null) {
            throw new Exception("Failed to compute shared secret - point at infinity");
        }
        this.sharedSecret = sharedPoint.x;
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public byte[] getSharedSecretBytes() {
        if (this.sharedSecret == null) {
            throw new IllegalStateException("Shared secret not computed yet");
        }
        return toByteArray(this.sharedSecret, 32);
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public boolean validatePublicKey(JSONObject publicKey) {
        try {
            BigInteger x = new BigInteger(publicKey.getString("x"));
            BigInteger y = new BigInteger(publicKey.getString("y"));
            BigInteger left = y.multiply(y).mod(CURVE_P);
            BigInteger right = x.multiply(x).multiply(x).add(CURVE_A.multiply(x)).add(CURVE_B).mod(CURVE_P);
            return left.equals(right);
        } catch (Exception e) {
            Log.e(TAG, "Error validating public key", e);
            return false;
        }
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public int getKeySize() {
        return 256;
    }

    @Override // com.example.securechat.crypto.KeyExchange
    public JSONObject getParameters() throws Exception {
        JSONObject params = new JSONObject();
        params.put("algorithm", this.algorithmName);
        params.put("curve", "P-256");
        params.put("keySize", getKeySize());
        params.put("p", CURVE_P.toString());
        params.put("a", CURVE_A.toString());
        params.put("b", CURVE_B.toString());
        params.put("gx", CURVE_GX.toString());
        params.put("gy", CURVE_GY.toString());
        params.put("order", CURVE_ORDER.toString());
        return params;
    }

    private BigInteger modInverse(BigInteger a, BigInteger m) {
        return a.modInverse(m);
    }

    private ECPoint pointAdd(ECPoint pointP, ECPoint pointQ) {
        if (pointP == null) {
            return pointQ;
        }
        if (pointQ == null) {
            return pointP;
        }
        if (pointP.x.equals(pointQ.x)) {
            if (pointP.y.add(pointQ.y).mod(CURVE_P).equals(BigInteger.ZERO)) {
                return null;
            }
            if (pointP.y.equals(pointQ.y)) {
                return pointDouble(pointP);
            }
        }
        BigInteger deltaY = pointQ.y.subtract(pointP.y);
        BigInteger deltaX = pointQ.x.subtract(pointP.x);
        BigInteger slope = deltaY.multiply(modInverse(deltaX, CURVE_P)).mod(CURVE_P);
        BigInteger resultX = slope.multiply(slope).subtract(pointP.x).subtract(pointQ.x).mod(CURVE_P);
        BigInteger resultY = slope.multiply(pointP.x.subtract(resultX)).subtract(pointP.y).mod(CURVE_P);
        if (resultX.compareTo(BigInteger.ZERO) < 0) {
            resultX = resultX.add(CURVE_P);
        }
        if (resultY.compareTo(BigInteger.ZERO) < 0) {
            resultY = resultY.add(CURVE_P);
        }
        return new ECPoint(resultX, resultY);
    }

    private ECPoint pointDouble(ECPoint point) {
        if (point == null) {
            return null;
        }
        BigInteger numerator = point.x.multiply(point.x).multiply(BigInteger.valueOf(3L)).add(CURVE_A);
        BigInteger denominator = point.y.multiply(BigInteger.valueOf(2L));
        BigInteger slope = numerator.multiply(modInverse(denominator, CURVE_P)).mod(CURVE_P);
        BigInteger resultX = slope.multiply(slope).subtract(point.x.multiply(BigInteger.valueOf(2L))).mod(CURVE_P);
        BigInteger resultY = slope.multiply(point.x.subtract(resultX)).subtract(point.y).mod(CURVE_P);
        if (resultX.compareTo(BigInteger.ZERO) < 0) {
            resultX = resultX.add(CURVE_P);
        }
        if (resultY.compareTo(BigInteger.ZERO) < 0) {
            resultY = resultY.add(CURVE_P);
        }
        return new ECPoint(resultX, resultY);
    }

    private ECPoint scalarMult(ECPoint point, BigInteger scalar) {
        if (point == null || scalar.equals(BigInteger.ZERO)) {
            return null;
        }
        if (scalar.equals(BigInteger.ONE)) {
            return new ECPoint(point.x, point.y);
        }
        ECPoint result = null;
        ECPoint addend = new ECPoint(point.x, point.y);
        for (BigInteger k = scalar; k.compareTo(BigInteger.ZERO) > 0; k = k.shiftRight(1)) {
            if (k.testBit(0)) {
                result = pointAdd(result, addend);
            }
            addend = pointDouble(addend);
        }
        return result;
    }

    private byte[] toByteArray(BigInteger bigInt, int length) {
        byte[] bytes = bigInt.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        if (bytes.length > length && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, length + 1);
        }
        if (bytes.length < length) {
            byte[] padded = new byte[length];
            System.arraycopy(bytes, 0, padded, length - bytes.length, bytes.length);
            return padded;
        }
        return Arrays.copyOfRange(bytes, bytes.length - length, bytes.length);
    }
}
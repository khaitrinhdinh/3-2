package com.example.securechat.crypto;

import android.util.Log;
import com.example.securechat.crypto.SignatureBase;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class ECDSASignature extends SignatureBase {
    private static final String TAG = "ECDSASignature";
    private static final BigInteger CURVE_P = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
    private static final BigInteger CURVE_A = BigInteger.valueOf(-3);
    private static final BigInteger CURVE_B = new BigInteger("2455155546008943817740293915197451784769108058161191238065");
    private static final BigInteger CURVE_GX = new BigInteger("3289624317623424368845348028842487418520868978772050262753");
    private static final BigInteger CURVE_GY = new BigInteger("5673242899673324591834582889556471730778853907191064256384");
    private static final BigInteger CURVE_ORDER = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

    public ECDSASignature() {
        super("ECDSA-P192");
    }

    public static class ECPoint {
        public BigInteger x;
        public BigInteger y;

        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    public static class ECDSASignatureData extends SignatureBase.Signature {
        public String messageHash;
        public String r;
        public String s;

        public ECDSASignatureData(String r, String s, String messageHash) {
            super("ECDSA-P192");
            this.r = r;
            this.s = s;
            this.messageHash = messageHash;
        }

        @Override // com.example.securechat.crypto.SignatureBase.Signature
        public JSONObject toJSON() throws Exception {
            JSONObject json = new JSONObject();
            json.put("r", this.r);
            json.put("s", this.s);
            json.put("messageHash", this.messageHash);
            json.put("algorithm", this.algorithm);
            return json;
        }

        public static ECDSASignatureData fromJSON(JSONObject json) throws Exception {
            return new ECDSASignatureData(json.getString("r"), json.getString("s"), json.getString("messageHash"));
        }
    }

    @Override // com.example.securechat.crypto.SignatureBase
    public SignatureBase.KeyPair generateSignatureKeyPair() throws JSONException {
        SecureRandom random = new SecureRandom();
        byte[] privateKeyBytes = new byte[24];
        random.nextBytes(privateKeyBytes);
        BigInteger privateKey = new BigInteger(1, privateKeyBytes).mod(CURVE_ORDER.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        ECPoint publicKeyPoint = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), privateKey);
        try {
            JSONObject publicKey = new JSONObject();
            publicKey.put("x", publicKeyPoint.x.toString());
            publicKey.put("y", publicKeyPoint.y.toString());
            return new SignatureBase.KeyPair(privateKey.toString(), publicKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate ECDSA signature key pair", e);
        }
    }

    @Override // com.example.securechat.crypto.SignatureBase
    public SignatureBase.Signature signMessage(String message, String privateKeyStr) throws Exception {
        BigInteger k;
        BigInteger messageHash = hashMessage(message);
        BigInteger privateKey = new BigInteger(privateKeyStr);
        SecureRandom random = new SecureRandom();
        do {
            byte[] kBytes = new byte[24];
            random.nextBytes(kBytes);
            k = new BigInteger(1, kBytes).mod(CURVE_ORDER.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        } while (k.equals(BigInteger.ZERO));
        ECPoint kG = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), k);
        BigInteger r = kG.x.mod(CURVE_ORDER);
        if (r.equals(BigInteger.ZERO)) {
            throw new Exception("Invalid ECDSA signature generation (r = 0)");
        }
        BigInteger kInv = k.modInverse(CURVE_ORDER);
        BigInteger s = kInv.multiply(messageHash.add(r.multiply(privateKey))).mod(CURVE_ORDER);
        if (s.equals(BigInteger.ZERO)) {
            throw new Exception("Invalid ECDSA signature generation (s = 0)");
        }
        return new ECDSASignatureData(r.toString(), s.toString(), messageHash.toString());
    }

    @Override // com.example.securechat.crypto.SignatureBase
    public boolean verifySignature(String message, SignatureBase.Signature signature, JSONObject publicKeyJson) {
        boolean z;
        try {
            if (!(signature instanceof ECDSASignatureData)) {
                Log.e(TAG, "Invalid signature type for ECDSA verification");
                return false;
            }
            ECDSASignatureData ecdsaSig = (ECDSASignatureData) signature;
            BigInteger messageHash = hashMessage(message);
            BigInteger r = new BigInteger(ecdsaSig.r);
            BigInteger s = new BigInteger(ecdsaSig.s);
            BigInteger pubX = new BigInteger(publicKeyJson.getString("x"));
            BigInteger pubY = new BigInteger(publicKeyJson.getString("y"));
            ECPoint publicKey = new ECPoint(pubX, pubY);
            if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(CURVE_ORDER) >= 0) {
                return false;
            }
            if (s.compareTo(BigInteger.ZERO) > 0 && s.compareTo(CURVE_ORDER) < 0) {
                BigInteger w = s.modInverse(CURVE_ORDER);
                BigInteger u1 = messageHash.multiply(w).mod(CURVE_ORDER);
                BigInteger u2 = r.multiply(w).mod(CURVE_ORDER);
                z = false;
                try {
                    ECPoint point1 = scalarMult(new ECPoint(CURVE_GX, CURVE_GY), u1);
                    ECPoint point2 = scalarMult(publicKey, u2);
                    ECPoint point = pointAdd(point1, point2);
                    if (point == null) {
                        return false;
                    }
                    BigInteger v = point.x.mod(CURVE_ORDER);
                    return v.equals(r);
                } catch (Exception e) {
                    e = e;
                    Log.e(TAG, "ECDSA signature verification error", e);
                    return z;
                }
            }
            return false;
        } catch (Exception e2) {
            e = e2;
            z = false;
        }
    }

    @Override // com.example.securechat.crypto.SignatureBase
    public boolean validateSignature(SignatureBase.Signature signature) {
        if (!(signature instanceof ECDSASignatureData)) {
            return false;
        }
        ECDSASignatureData ecdsaSig = (ECDSASignatureData) signature;
        return (ecdsaSig.r == null || ecdsaSig.s == null || !this.algorithmName.equals(ecdsaSig.algorithm)) ? false : true;
    }

    public BigInteger hashMessage(String message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        BigInteger hash = new BigInteger(1, hashBytes);
        return hash.mod(CURVE_ORDER);
    }

    @Override // com.example.securechat.crypto.SignatureBase
    public int getSignatureSize() {
        return 384;
    }

    @Override // com.example.securechat.crypto.SignatureBase
    public JSONObject getParameters() throws Exception {
        JSONObject params = new JSONObject();
        params.put("algorithm", this.algorithmName);
        params.put("curve", "P-192");
        params.put("signatureSize", getSignatureSize());
        params.put("hashAlgorithm", "SHA-256");
        params.put("p", CURVE_P.toString());
        params.put("a", CURVE_A.toString());
        params.put("b", CURVE_B.toString());
        params.put("gx", CURVE_GX.toString());
        params.put("gy", CURVE_GY.toString());
        params.put("order", CURVE_ORDER.toString());
        return params;
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
        BigInteger slope = deltaY.multiply(deltaX.modInverse(CURVE_P)).mod(CURVE_P);
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
        BigInteger slope = numerator.multiply(denominator.modInverse(CURVE_P)).mod(CURVE_P);
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
}
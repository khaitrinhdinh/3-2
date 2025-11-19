package com.example.securechat.crypto;

import org.json.JSONObject;

/* loaded from: classes3.dex */
public abstract class SignatureBase {
    protected String algorithmName;

    public abstract KeyPair generateSignatureKeyPair();

    public abstract JSONObject getParameters() throws Exception;

    public abstract int getSignatureSize();

    public abstract Signature signMessage(String str, String str2) throws Exception;

    public abstract boolean verifySignature(String str, Signature signature, JSONObject jSONObject);

    public SignatureBase(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public boolean validateSignature(Signature signature) {
        return true;
    }

    public String getAlgorithmName() {
        return this.algorithmName;
    }

    public static abstract class Signature {
        public String algorithm;

        public abstract JSONObject toJSON() throws Exception;

        public Signature(String algorithm) {
            this.algorithm = algorithm;
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        /* JADX WARN: Removed duplicated region for block: B:11:0x0022  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct code enable 'Show inconsistent code' option in preferences
        */
        public static com.example.securechat.crypto.SignatureBase.Signature fromJSON(org.json.JSONObject r4, java.lang.String r5) throws java.lang.Exception {
            /*
                java.lang.String r0 = "algorithm"
                java.lang.String r0 = r4.getString(r0)
                int r1 = r0.hashCode()
                switch(r1) {
                    case -709629261: goto L18;
                    case -709628420: goto Le;
                    default: goto Ld;
                }
            Ld:
                goto L22
            Le:
                java.lang.String r1 = "ECDSA-P256"
                boolean r1 = r0.equals(r1)
                if (r1 == 0) goto Ld
                r1 = 1
                goto L23
            L18:
                java.lang.String r1 = "ECDSA-P192"
                boolean r1 = r0.equals(r1)
                if (r1 == 0) goto Ld
                r1 = 0
                goto L23
            L22:
                r1 = -1
            L23:
                switch(r1) {
                    case 0: goto L44;
                    case 1: goto L3f;
                    default: goto L26;
                }
            L26:
                java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException
                java.lang.StringBuilder r2 = new java.lang.StringBuilder
                r2.<init>()
                java.lang.String r3 = "Unknown signature algorithm: "
                java.lang.StringBuilder r2 = r2.append(r3)
                java.lang.StringBuilder r2 = r2.append(r0)
                java.lang.String r2 = r2.toString()
                r1.<init>(r2)
                throw r1
            L3f:
                com.example.securechat.crypto.ECDSASignature2$ECDSASignatureData r1 = com.example.securechat.crypto.ECDSASignature2.ECDSASignatureData.fromJSON(r4)
                return r1
            L44:
                com.example.securechat.crypto.ECDSASignature$ECDSASignatureData r1 = com.example.securechat.crypto.ECDSASignature.ECDSASignatureData.fromJSON(r4)
                return r1
            */
            throw new UnsupportedOperationException("Method not decompiled: com.example.securechat.crypto.SignatureBase.Signature.fromJSON(org.json.JSONObject, java.lang.String):com.example.securechat.crypto.SignatureBase$Signature");
        }
    }

    public static class KeyPair {
        public String privateKey;
        public JSONObject publicKey;

        public KeyPair(String privateKey, JSONObject publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }
}
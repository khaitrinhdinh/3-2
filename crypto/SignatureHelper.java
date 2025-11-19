package com.example.securechat.crypto;

/* loaded from: classes3.dex */
public class SignatureHelper {
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0022  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static com.example.securechat.crypto.SignatureBase.Signature createSignatureFromJSON(org.json.JSONObject r4) throws java.lang.Exception {
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
            java.lang.String r3 = "Unsupported signature algorithm: "
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
        throw new UnsupportedOperationException("Method not decompiled: com.example.securechat.crypto.SignatureHelper.createSignatureFromJSON(org.json.JSONObject):com.example.securechat.crypto.SignatureBase$Signature");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static boolean isValidSignatureJSON(org.json.JSONObject r4) throws org.json.JSONException {
        /*
            java.lang.String r0 = "algorithm"
            r1 = 0
            boolean r2 = r4.has(r0)     // Catch: java.lang.Exception -> L4a
            if (r2 != 0) goto La
            return r1
        La:
            java.lang.String r0 = r4.getString(r0)     // Catch: java.lang.Exception -> L4a
            int r2 = r0.hashCode()     // Catch: java.lang.Exception -> L4a
            r3 = 1
            switch(r2) {
                case -709629261: goto L21;
                case -709628420: goto L17;
                default: goto L16;
            }     // Catch: java.lang.Exception -> L4a
        L16:
            goto L2b
        L17:
            java.lang.String r2 = "ECDSA-P256"
            boolean r2 = r0.equals(r2)     // Catch: java.lang.Exception -> L4a
            if (r2 == 0) goto L16
            r2 = r3
            goto L2c
        L21:
            java.lang.String r2 = "ECDSA-P192"
            boolean r2 = r0.equals(r2)     // Catch: java.lang.Exception -> L4a
            if (r2 == 0) goto L16
            r2 = r1
            goto L2c
        L2b:
            r2 = -1
        L2c:
            switch(r2) {
                case 0: goto L30;
                case 1: goto L30;
                default: goto L2f;
            }     // Catch: java.lang.Exception -> L4a
        L2f:
            return r1
        L30:
            java.lang.String r2 = "r"
            boolean r2 = r4.has(r2)     // Catch: java.lang.Exception -> L4a
            if (r2 == 0) goto L49
            java.lang.String r2 = "s"
            boolean r2 = r4.has(r2)     // Catch: java.lang.Exception -> L4a
            if (r2 == 0) goto L49
            java.lang.String r2 = "messageHash"
            boolean r2 = r4.has(r2)     // Catch: java.lang.Exception -> L4a
            if (r2 == 0) goto L49
            r1 = r3
        L49:
            return r1
        L4a:
            r0 = move-exception
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.example.securechat.crypto.SignatureHelper.isValidSignatureJSON(org.json.JSONObject):boolean");
    }
}
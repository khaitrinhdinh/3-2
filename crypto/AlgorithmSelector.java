package com.example.securechat.crypto;

import java.util.HashMap;
import java.util.Map;

/* loaded from: classes3.dex */
public class AlgorithmSelector {
    private static final Map<String, String> USER_ALGORITHM_MAP = new HashMap();

    static {
        USER_ALGORITHM_MAP.put("group-1", "ecdh");
        USER_ALGORITHM_MAP.put("group-2", "ecdh_2");
        USER_ALGORITHM_MAP.put("group-3", "ecdh_3");
    }

    public static String getAlgorithmForUser(String userId) {
        return USER_ALGORITHM_MAP.getOrDefault(userId, "ecdh");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:14:0x002a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static java.lang.String getAlgorithmDisplayName(java.lang.String r2) {
        /*
            java.lang.String r0 = r2.toLowerCase()
            int r1 = r0.hashCode()
            switch(r1) {
                case -1308912427: goto L20;
                case -1308912426: goto L16;
                case 3107234: goto Lc;
                default: goto Lb;
            }
        Lb:
            goto L2a
        Lc:
            java.lang.String r1 = "ecdh"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto Lb
            r0 = 0
            goto L2b
        L16:
            java.lang.String r1 = "ecdh_3"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto Lb
            r0 = 2
            goto L2b
        L20:
            java.lang.String r1 = "ecdh_2"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto Lb
            r0 = 1
            goto L2b
        L2a:
            r0 = -1
        L2b:
            switch(r0) {
                case 0: goto L36;
                case 1: goto L33;
                case 2: goto L33;
                default: goto L2e;
            }
        L2e:
            java.lang.String r0 = r2.toUpperCase()
            return r0
        L33:
            java.lang.String r0 = "ECDH P-256"
            return r0
        L36:
            java.lang.String r0 = "ECDH P-192"
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.example.securechat.crypto.AlgorithmSelector.getAlgorithmDisplayName(java.lang.String):java.lang.String");
    }
}
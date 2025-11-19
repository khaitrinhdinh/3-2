package com.example.securechat.crypto;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/* loaded from: classes3.dex */
public class SignatureFactory {
    private Map<String, Class<? extends SignatureBase>> signatures = new HashMap();

    public SignatureFactory() {
        registerDefaultSignatures();
    }

    private void registerDefaultSignatures() {
        this.signatures.put("ecdh", ECDSASignature.class);
        this.signatures.put("ecdh_2", ECDSASignature2.class);
        this.signatures.put("ecdh_3", ECDSASignature2.class);
    }

    public void register(String keyExchangeAlgorithm, Class<? extends SignatureBase> signatureClass) {
        this.signatures.put(keyExchangeAlgorithm.toLowerCase(), signatureClass);
    }

    public SignatureBase create(String keyExchangeAlgorithm) throws Exception {
        Class<? extends SignatureBase> signatureClass = this.signatures.get(keyExchangeAlgorithm.toLowerCase());
        if (signatureClass == null) {
            throw new IllegalArgumentException("No signature algorithm for key exchange: " + keyExchangeAlgorithm);
        }
        return signatureClass.newInstance();
    }

    public Set<String> getSupportedKeyExchangeAlgorithms() {
        return this.signatures.keySet();
    }

    public boolean isSupported(String keyExchangeAlgorithm) {
        return this.signatures.containsKey(keyExchangeAlgorithm.toLowerCase());
    }

    public String getSignatureAlgorithmName(String keyExchangeAlgorithm) throws Exception {
        if (!isSupported(keyExchangeAlgorithm)) {
            return null;
        }
        SignatureBase instance = create(keyExchangeAlgorithm);
        return instance.getAlgorithmName();
    }
}
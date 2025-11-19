package com.example.securechat.crypto;

import org.json.JSONObject;

/* loaded from: classes3.dex */
public abstract class KeyExchange {
    protected String algorithmName;

    public abstract void computeSharedSecret(JSONObject jSONObject) throws Exception;

    public abstract void generatePrivateKey();

    public abstract JSONObject generatePublicKey() throws Exception;

    public abstract int getKeySize();

    public abstract JSONObject getParameters() throws Exception;

    public abstract byte[] getSharedSecretBytes();

    public KeyExchange(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public boolean validatePublicKey(JSONObject publicKey) {
        return true;
    }

    public String getAlgorithmName() {
        return this.algorithmName;
    }
}
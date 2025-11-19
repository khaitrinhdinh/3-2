package com.example.securechat.crypto;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/* loaded from: classes3.dex */
public class KeyExchangeFactory {
    private Map<String, Class<? extends KeyExchange>> algorithms = new HashMap();

    public KeyExchangeFactory() {
        registerDefaultAlgorithms();
    }

    private void registerDefaultAlgorithms() {
        this.algorithms.put("ecdh", ECDHKeyExchange.class);
        this.algorithms.put("ecdh_2", ECDHKeyExchange2.class);
        this.algorithms.put("ecdh_3", ECDHKeyExchange2.class);
    }

    public void register(String name, Class<? extends KeyExchange> algorithmClass) {
        this.algorithms.put(name.toLowerCase(), algorithmClass);
    }

    public KeyExchange create(String name) throws Exception {
        Class<? extends KeyExchange> algorithmClass = this.algorithms.get(name.toLowerCase());
        if (algorithmClass == null) {
            throw new IllegalArgumentException("Unknown key exchange algorithm: " + name);
        }
        return algorithmClass.newInstance();
    }

    public Set<String> getSupportedAlgorithms() {
        return this.algorithms.keySet();
    }

    public boolean isSupported(String name) {
        return this.algorithms.containsKey(name.toLowerCase());
    }
}
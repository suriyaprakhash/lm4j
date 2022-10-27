package com.suriya.keychain.core.chain;

import java.security.KeyStore;
import java.security.PrivateKey;

public class BuilderStorage extends ExtractorStorage {
    protected PrivateKey privateKey;
    protected KeyStore keyStore;

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}

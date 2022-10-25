package com.suriya.keychain.core.algorithm;

import org.junit.jupiter.api.Test;

import java.security.*;

public class AsymmetricKeyTest {

    @Test
    public void generateAsymmetricKey_Test_RSA() {
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey("DSA", 2048); //DSA RSA
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
    }
}

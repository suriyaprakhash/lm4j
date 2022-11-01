package com.suriya.keychain.core.algorithm.support;

import com.suriya.keychain.core.algorithm.suppport.RSASupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSASupportTest {

    private RSASupport rsaSupport;

//    @BeforeAll
//    public static beforeAll() {
//    }

    @Test
    void generatePublicKeyFromPrivateKeyTest() {
        RSASupport rsaSupport =new RSASupport();
        KeyPair keyPair1 = rsaSupport.generateKeyPair();
        KeyPair keyPair2 = rsaSupport.generateKeyPair();
        Assertions.assertFalse(keyPair1.getPublic().equals(keyPair2.getPublic()));

        PrivateKey pk = keyPair1.getPrivate();
        PublicKey pubKey1 = rsaSupport.generatePublicKeyFromPrivateKey(pk);
        PublicKey pubKey2 = rsaSupport.generatePublicKeyFromPrivateKey(pk);
        Assertions.assertTrue(pubKey1.equals(pubKey2));
    }
}

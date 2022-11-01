package com.suriya.keychain.core.algorithm;

import com.suriya.keychain.core.algorithm.suppport.RSASupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptographyTest {
    @Test
    void encryptTest() {
        KeyPair keyPair1 = AsymmetricKey.generateAsymmetricKey("RSA", 2048); //DSA RSA
        PrivateKey privateKey1 = keyPair1.getPrivate();
        PublicKey publicKey1 = keyPair1.getPublic();

        KeyPair keyPair2 = AsymmetricKey.generateAsymmetricKey("RSA", 2048); //DSA RSA
        PublicKey publicKey2 = keyPair2.getPublic();

//        RSASupport rsaSupport = new RSASupport();
//        KeyPair rsaKeyPair = rsaSupport.generateKeyPair();
//
//        PublicKey publicKey2 = rsaKeyPair.getPublic();

        String actualString = "hello world";
        byte[] encryptedByteArray = Cryptography.encrypt("RSA/ECB/PKCS1Padding", privateKey1, actualString.getBytes(StandardCharsets.UTF_8));
        String decryptedString = new String(Cryptography.decrypt("RSA/ECB/PKCS1Padding", publicKey1, encryptedByteArray));
        Assertions.assertEquals(actualString, decryptedString);
    }
}

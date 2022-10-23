package com.suriya.license.core.algorithm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DigiSignTest {

    @Test
    public void signTest_CorrectCase() {
        String signAlgorithm = "SHA256withDSA";
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey("DSA", 2048); //DSA RSA
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] signature = DigiSign.sign(signAlgorithm, privateKey, "hello world".getBytes());
        Assertions.assertTrue(DigiSign.verify(signAlgorithm, publicKey, signature,"hello world".getBytes()));
    }
    @Test
    public void signTest_InCorrectCase_DiffAlgm() {
        String signAlgorithmDSA = "SHA256withDSA";
        String signAlgorithmRSA = "SHA256withRSA";
        KeyPair keyPairDSA = AsymmetricKey.generateAsymmetricKey("DSA", 2048); //DSA RSA
        KeyPair keyPairRSA = AsymmetricKey.generateAsymmetricKey("RSA", 2048); //DSA RSA
        PrivateKey privateKey = keyPairDSA.getPrivate();
        PublicKey publicKey = keyPairRSA.getPublic();
        byte[] signature = DigiSign.sign(signAlgorithmDSA, privateKey, "hello world".getBytes());
        DigiSign.verify(signAlgorithmRSA, publicKey, signature,"hello world".getBytes());
    }

    @Test
    public void signTest_InCorrectCase_SameAlgm() {
        String signAlgorithm = "SHA256withDSA";
        KeyPair keyPairDSA1 = AsymmetricKey.generateAsymmetricKey("DSA", 2048); //DSA RSA
        KeyPair keyPairDSA2 = AsymmetricKey.generateAsymmetricKey("DSA", 2048); //DSA RSA
        PrivateKey privateKey = keyPairDSA1.getPrivate();
        PublicKey publicKey = keyPairDSA2.getPublic();
        byte[] signature = DigiSign.sign(signAlgorithm, privateKey, "hello world".getBytes());
        Assertions.assertTrue(!DigiSign.verify(signAlgorithm, publicKey, signature,"hello world".getBytes()));
    }

}

package com.suriya.license.core.algorithm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

public class DigiSignTest {

    @Test
    public void signTest_CorrectCase() {
        String signAlgorithm = "SHA256withDSA";
        KeyPair keyPair = AsymmetricKey.generateAsymmetricKey("DSA"); //DSA RSA
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] signature = DigiSign.sign(signAlgorithm, privateKey, "hello world");
        Assertions.assertTrue(DigiSign.verify(signAlgorithm, publicKey, signature,"hello world"));
    }
    @Test
    public void signTest_InCorrectCase_DiffAlgm() {
        String signAlgorithmDSA = "SHA256withDSA";
        String signAlgorithmRSA = "SHA256withRSA";
        KeyPair keyPairDSA = AsymmetricKey.generateAsymmetricKey("DSA"); //DSA RSA
        KeyPair keyPairRSA = AsymmetricKey.generateAsymmetricKey("RSA"); //DSA RSA
        PrivateKey privateKey = keyPairDSA.getPrivate();
        PublicKey publicKey = keyPairRSA.getPublic();
        byte[] signature = DigiSign.sign(signAlgorithmDSA, privateKey, "hello world");
        DigiSign.verify(signAlgorithmRSA, publicKey, signature,"hello world");
    }

    @Test
    public void signTest_InCorrectCase_SameAlgm() {
        String signAlgorithm = "SHA256withDSA";
        KeyPair keyPairDSA1 = AsymmetricKey.generateAsymmetricKey("DSA"); //DSA RSA
        KeyPair keyPairDSA2 = AsymmetricKey.generateAsymmetricKey("DSA"); //DSA RSA
        PrivateKey privateKey = keyPairDSA1.getPrivate();
        PublicKey publicKey = keyPairDSA2.getPublic();
        byte[] signature = DigiSign.sign(signAlgorithm, privateKey, "hello world");
        Assertions.assertTrue(!DigiSign.verify(signAlgorithm, publicKey, signature,"hello world"));
    }
}

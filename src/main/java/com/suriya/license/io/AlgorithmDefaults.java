package com.suriya.license.io;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface AlgorithmDefaults {
    static String keyStoreAlgorithm = "PKCS12";
    static String secureRandomKeyAlgorithm = "HmacSHA1";
    static String passwordKeyAlgorithm = "HmacSHA1";
    static String keyPairAlgorithm = "RSA";
    static String signAlgorithmRSA = "SHA256withRSA";
    static int keyPairKeySize = 2048;

    static String INFO_KEY = "infoKey";
    static String PUBLIC_KEY = "publicKey";
    static String SIGNATURE_KEY = "signatureKey";

}

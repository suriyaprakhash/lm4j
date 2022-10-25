package com.suriya.keychain.core.algorithm;

import java.security.*;

public final class AsymmetricKey {

    public static KeyPair generateAsymmetricKey(String algorithm, int keySize) {
        KeyPair keyPair = null;
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        try {
            //Creating KeyPair generator object
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm); //DSA RSA
            //Initializing the KeyPairGenerator
            keyPairGen.initialize(keySize); //2048

            //Generating the pair of keys
            keyPair = keyPairGen.generateKeyPair();

            //Getting the private key from the key pair
            privateKey = keyPair.getPrivate();

            //Getting the public key from the key pair
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }
}

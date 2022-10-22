package com.suriya.license.core.algorithm;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class SymmetricKey {

    /**
     * Secure Random key - Symmetric key
     *
     * @param algorithm
     * @return
     */
    public static Key generateSecureRandomKey(String algorithm) {
        Key key = null;
        try {
            //Creating a KeyGenerator object
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm); // "DES"

            //Creating a SecureRandom object
            SecureRandom secRandom = new SecureRandom();

            //Initializing the KeyGenerator
            keyGen.init(secRandom);

            //Creating/Generating a key
            key = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }

    public static Key generateKeyFromPassword(String algorithm, String password) {
        //Creating SecretKey object
        SecretKey mySecretKey = new SecretKeySpec(password.getBytes(), algorithm); //DSA
        return mySecretKey;
    }

    public static Key generateKeyFromPasswordBasedEncryption(String algorithm, String password) {
        SecretKey pbeKey = null;
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance(algorithm);
            pbeKey = keyFac.generateSecret(pbeKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return pbeKey;
    }




}

package com.suriya.keychain.core.algorithm.suppport;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class RSASupport implements AlgorithmSupport {

    private String RSA_SUPPORT_ALGORITHM_NAME = "RSA";
    private int DEFAULT_KEY_SITE = 2048;

    @Override
    public PublicKey generatePublicKeyFromPrivateKey(PrivateKey privateKey) {
        PublicKey publicKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_SUPPORT_ALGORITHM_NAME);
            RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(rsaPrivateKeySpec.getModulus(), BigInteger.valueOf(65537));
            publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    @Override
    public KeyPair generateKeyPair() {
        return generateKeyPair(DEFAULT_KEY_SITE);
    }

    @Override
    public KeyPair generateKeyPair(int keySize) {

        KeyPairGenerator keyPairGen = null;
        KeyPair keyPair = null;
        try {
            keyPairGen = KeyPairGenerator.getInstance(RSA_SUPPORT_ALGORITHM_NAME);

            keyPairGen.initialize(keySize);

            keyPair = keyPairGen.generateKeyPair();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return keyPair;
    }

    @Override
    public void savePrivateKeyFile(PrivateKey privateKey, String path, String filename) {
        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(path + "//" + filename + ".key");
            fos.write(pkcs8EncodedKeySpec.getEncoded());
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void savePublicKeyFile(PublicKey publicKey, String path, String filename) {
        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(path + "//" + filename + ".pub");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

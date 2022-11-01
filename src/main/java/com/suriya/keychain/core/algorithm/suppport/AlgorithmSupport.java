package com.suriya.keychain.core.algorithm.suppport;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface AlgorithmSupport {

    public KeyPair generateKeyPair();

    public KeyPair generateKeyPair(int keySize);

    public PublicKey generatePublicKeyFromPrivateKey(PrivateKey privateKey);

    public void savePrivateKeyFile(PrivateKey privateKey,String path, String filename);

    public void savePublicKeyFile(PublicKey publicKey,String path, String filename);

}

package com.suriya.keychain.core.algorithm;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Cryptography {

    public static byte[] encrypt(String cipherAlgorithm, PrivateKey privateKey, byte[] actualData) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm); //
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            cipher.update(actualData);
            encryptedData = cipher.doFinal();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptedData;
    }

    public static  byte[] decrypt(String cipherAlgorithm, PublicKey publicKey, byte[] encryptedData) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm); //
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            cipher.update(encryptedData);
            decryptedData = cipher.doFinal();

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return decryptedData;
    }

}
